#pragma once

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <string>
#include <vector>

namespace bin {

// 每条记录头，20 字节
struct BinRecordHeader {
    uint32_t magic;       // 0x31425353 "SSB1" LE
    uint16_t version;     // 1
    uint16_t link_type;   // 1 = LINKTYPE_ETHERNET
    uint64_t ts_ns;       // CLOCK_REALTIME 纳秒
    uint32_t packet_len;
} __attribute__((packed));

static const uint32_t kBinMagic   = 0x31425353;
static const uint16_t kBinVersion = 1;

struct BinRotateSync {
    std::atomic<int>  write_segment{1};
    std::atomic<bool> capture_running{true};
};

class BinRecorder {
public:
    BinRecorder();
    ~BinRecorder();

    bool Open(const std::string& dir, const std::string& prefix,
              uint64_t max_segment_bytes, std::string* err);

    void AttachRotateSync(BinRotateSync* sync);
    void AttachStopOnIoError(std::atomic<bool>* stop);

    bool WriteRecord(uint64_t ts_ns, const uint8_t* packet, size_t len);

    void Close();
    uint64_t dropped_records() const { return dropped_; }

private:
    bool OpenSegmentFile(int seg, std::string* err);
    void MaybeRotate(size_t next_record_bytes, std::string* err);
    void LogIoErrorThrottled(const char* context);

    std::string dir_;
    std::string prefix_;
    uint64_t    max_segment_bytes_;
    FILE*       fp_;
    int         current_segment_;
    uint64_t    bytes_in_segment_;
    uint64_t    dropped_;
    BinRotateSync*       sync_;
    std::atomic<bool>*   stop_on_io_error_;
    uint64_t             last_io_err_log_ms_;
};

class BinReader {
public:
    BinReader();
    ~BinReader();

    bool Open(const std::string& dir, const std::string& prefix, std::string* err);
    void AttachRotateSync(BinRotateSync* sync);

    void SetOnSegmentClosed(std::function<void(int closed_segment)> cb);
    void SetDeleteSegmentAfterRead(bool v);
    void CloseAndDeleteCurrentSegment();

    bool ReadNext(uint64_t* ts_ns, std::vector<uint8_t>* packet);

    bool exhausted() const { return exhausted_; }
    int  ReadSegmentNumber() const { return read_segment_; }

private:
    bool OpenReadSegment(int seg, std::string* err);
    bool ReadExact(void* buf, size_t n);
    void UnlinkSegmentFile(int seg, const char* ctx);

    std::string dir_;
    std::string prefix_;
    FILE*       fp_;
    int         read_segment_;
    BinRotateSync* sync_;
    bool        exhausted_;
    std::function<void(int)> on_segment_closed_;
    bool        delete_after_read_;
    uint64_t    last_unlink_warn_ms_;
};

}  // namespace bin
