#include "bin_io.hpp"

#include <chrono>
#include <cstring>
#include <iostream>
#include <thread>
#include <errno.h>
#include <sys/stat.h>

namespace bin {

static void MkDirP(const std::string& dir) {
    if (dir.empty()) return;
    std::string path;
    for (size_t i = 0; i < dir.size(); ++i) {
        path.push_back(dir[i]);
        if (dir[i] == '/' && path.size() > 1) mkdir(path.c_str(), 0755);
    }
    mkdir(dir.c_str(), 0755);
}

static std::string SegmentPath(const std::string& dir, const std::string& prefix, int seg) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "_%06d.bin", seg);
    return dir + "/" + prefix + buf;
}

// ---- BinRecorder ----

BinRecorder::BinRecorder()
    : max_segment_bytes_(0), fp_(nullptr), current_segment_(0),
      bytes_in_segment_(0), dropped_(0), sync_(nullptr),
      stop_on_io_error_(nullptr), last_io_err_log_ms_(0) {}

BinRecorder::~BinRecorder() { Close(); }

bool BinRecorder::Open(const std::string& dir, const std::string& prefix,
                       uint64_t max_segment_bytes, std::string* err) {
    Close();
    dir_    = dir;
    prefix_ = prefix;
    max_segment_bytes_ = max_segment_bytes ? max_segment_bytes : (uint64_t)256 * 1024 * 1024;
    MkDirP(dir_);
    current_segment_ = sync_ ? sync_->write_segment.load() : 1;
    bytes_in_segment_ = 0;
    dropped_          = 0;
    return OpenSegmentFile(current_segment_, err);
}

void BinRecorder::AttachRotateSync(BinRotateSync* sync) { sync_ = sync; }
void BinRecorder::AttachStopOnIoError(std::atomic<bool>* stop) { stop_on_io_error_ = stop; }

void BinRecorder::LogIoErrorThrottled(const char* context) {
    using namespace std::chrono;
    const uint64_t now = duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
    if (now - last_io_err_log_ms_ < 5000) return;
    last_io_err_log_ms_ = now;
    int e = errno;
    std::cerr << "[BinRecorder] " << context << ": " << std::strerror(e) << std::endl;
}

bool BinRecorder::OpenSegmentFile(int seg, std::string* err) {
    if (fp_) {
        std::fflush(fp_);
        std::fclose(fp_);
        fp_ = nullptr;
    }
    std::string path = SegmentPath(dir_, prefix_, seg);
    fp_ = std::fopen(path.c_str(), "wb");
    if (!fp_) {
        if (err) *err = std::string("fopen wb: ") + path + ": " + std::strerror(errno);
        LogIoErrorThrottled(("fopen wb " + path).c_str());
        if (stop_on_io_error_) stop_on_io_error_->store(true);
        return false;
    }
    current_segment_  = seg;
    bytes_in_segment_ = 0;
    if (sync_) sync_->write_segment.store(seg);
    return true;
}

void BinRecorder::MaybeRotate(size_t next_record_bytes, std::string* err) {
    if (!fp_) return;
    if (bytes_in_segment_ + next_record_bytes <= max_segment_bytes_) return;
    (void)OpenSegmentFile(current_segment_ + 1, err);
}

bool BinRecorder::WriteRecord(uint64_t ts_ns, const uint8_t* packet, size_t len) {
    if (len > 65535) { ++dropped_; return false; }
    const size_t rec = sizeof(BinRecordHeader) + len;
    std::string e;
    MaybeRotate(rec, &e);
    if (!fp_) { ++dropped_; return false; }

    BinRecordHeader h;
    std::memset(&h, 0, sizeof(h));
    h.magic      = kBinMagic;
    h.version    = kBinVersion;
    h.link_type  = 1;
    h.ts_ns      = ts_ns;
    h.packet_len = static_cast<uint32_t>(len);

    if (std::fwrite(&h, 1, sizeof(h), fp_) != sizeof(h)) {
        ++dropped_;
        LogIoErrorThrottled("fwrite header");
        if (stop_on_io_error_) stop_on_io_error_->store(true);
        return false;
    }
    if (len > 0 && std::fwrite(packet, 1, len, fp_) != len) {
        ++dropped_;
        LogIoErrorThrottled("fwrite packet");
        if (stop_on_io_error_) stop_on_io_error_->store(true);
        return false;
    }
    if (std::fflush(fp_) != 0) {
        ++dropped_;
        LogIoErrorThrottled("fflush");
        if (stop_on_io_error_) stop_on_io_error_->store(true);
        return false;
    }
    bytes_in_segment_ += rec;
    return true;
}

void BinRecorder::Close() {
    if (fp_) {
        std::fflush(fp_);
        std::fclose(fp_);
        fp_ = nullptr;
    }
    bytes_in_segment_ = 0;
}

// ---- BinReader ----

BinReader::BinReader()
    : fp_(nullptr), read_segment_(1), sync_(nullptr),
      exhausted_(false), delete_after_read_(false), last_unlink_warn_ms_(0) {}

BinReader::~BinReader() {
    if (fp_) std::fclose(fp_);
}

bool BinReader::Open(const std::string& dir, const std::string& prefix, std::string* err) {
    if (fp_) { std::fclose(fp_); fp_ = nullptr; }
    dir_         = dir;
    prefix_      = prefix;
    read_segment_ = 1;
    exhausted_   = false;
    if (OpenReadSegment(read_segment_, nullptr)) return true;
    if (sync_ && sync_->capture_running.load()) { fp_ = nullptr; return true; }
    if (err) *err = "no segment file and capture not running";
    return false;
}

void BinReader::AttachRotateSync(BinRotateSync* sync) { sync_ = sync; }

void BinReader::SetOnSegmentClosed(std::function<void(int closed_segment)> cb) {
    on_segment_closed_ = std::move(cb);
}

void BinReader::SetDeleteSegmentAfterRead(bool v) { delete_after_read_ = v; }

void BinReader::UnlinkSegmentFile(int seg, const char* ctx) {
    std::string path = SegmentPath(dir_, prefix_, seg);
    if (std::remove(path.c_str()) != 0) {
        const int e = errno;
        using namespace std::chrono;
        const uint64_t now = duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
        if (now - last_unlink_warn_ms_ >= 5000) {
            last_unlink_warn_ms_ = now;
            std::cerr << "[BinReader] " << ctx << " remove " << path << ": " << std::strerror(e) << std::endl;
        }
    }
}

void BinReader::CloseAndDeleteCurrentSegment() {
    if (!delete_after_read_) return;
    const int seg = read_segment_;
    if (fp_) { std::fclose(fp_); fp_ = nullptr; }
    UnlinkSegmentFile(seg, "delete last segment");
}

bool BinReader::OpenReadSegment(int seg, std::string* err) {
    if (fp_) { std::fclose(fp_); fp_ = nullptr; }
    std::string path = SegmentPath(dir_, prefix_, seg);
    fp_ = std::fopen(path.c_str(), "rb");
    if (!fp_) {
        if (err) *err = std::string("fopen rb: ") + path + ": " + std::strerror(errno);
        return false;
    }
    read_segment_ = seg;
    return true;
}

bool BinReader::ReadExact(void* buf, size_t n) {
    char* p = static_cast<char*>(buf);
    size_t got = 0;
    while (got < n) {
        size_t r = std::fread(p + got, 1, n - got, fp_);
        if (r == 0) return false;
        got += r;
    }
    return true;
}

bool BinReader::ReadNext(uint64_t* ts_ns, std::vector<uint8_t>* packet) {
    packet->clear();
    exhausted_ = false;

    for (;;) {
        if (!fp_) {
            if (!OpenReadSegment(read_segment_, nullptr)) {
                if (!sync_ || !sync_->capture_running.load()) {
                    exhausted_ = true;
                    return false;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }
        }

        BinRecordHeader h;
        if (!ReadExact(&h, sizeof(h))) {
            int ws  = sync_ ? sync_->write_segment.load() : read_segment_;
            bool cap = sync_ && sync_->capture_running.load();
            if (read_segment_ < ws) {
                const int closed_seg = read_segment_;
                if (!OpenReadSegment(read_segment_ + 1, nullptr)) {
                    exhausted_ = !cap;
                    return false;
                }
                if (on_segment_closed_) on_segment_closed_(closed_seg);
                if (delete_after_read_) UnlinkSegmentFile(closed_seg, "delete finished segment");
                continue;
            }
            if (cap) {
                std::clearerr(fp_);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                return false;
            }
            exhausted_ = true;
            return false;
        }

        if (h.magic != kBinMagic || h.version != kBinVersion || h.packet_len > 65535) {
            exhausted_ = true;
            return false;
        }

        packet->resize(h.packet_len);
        if (h.packet_len > 0 && !ReadExact(packet->data(), h.packet_len)) {
            exhausted_ = true;
            return false;
        }

        *ts_ns = h.ts_ns;
        return true;
    }
}

}  // namespace bin
