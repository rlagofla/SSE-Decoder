// decode_6_3113.cpp — 上交所 (6, 3113) 通道专用解码器
//
// 通道特性：
//   - 40B 外层头后面跟 57B 明文 body (无 ZIP 压缩)
//   - Body 采用 FAST stop-bit 变长整数编码, 固定 13 个字段
//   - 每帧承载一条指数 (如 "000001" 上证综指)
// 结构定义见 6_3113_struct.hpp。
//
// 用法:
//   decode_6_3113 <pcap> [filter_port=5261] [max_frames_per_stream=0]
//     max_frames_per_stream = 0 → 每条 TCP 流内不限帧数

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include <Packet.h>
#include <PcapFileDevice.h>
#include <TcpReassembly.h>

#include "6_3113_struct.hpp"

namespace {

constexpr uint32_t kMagic  = 0x0004C453u;
constexpr uint32_t kWantHi = 6;
constexpr uint32_t kWantLo = 3113;

uint32_t readBE32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) <<  8) |  uint32_t(p[3]);
}

// 价格字段 ×10^-5 → "X.XXXXX"
std::string fmtPrice1e5(uint64_t v) {
    std::ostringstream ss;
    ss << (v / 100000) << '.'
       << std::setw(5) << std::setfill('0') << (v % 100000);
    return ss.str();
}

// HHMMSS → "HH:MM:SS"
std::string fmtHHMMSS(uint32_t t) {
    char b[16];
    std::snprintf(b, sizeof(b), "%02u:%02u:%02u",
                  t / 10000, (t / 100) % 100, t % 100);
    return b;
}

void decodeFrame(const uint8_t* body, size_t blen, uint32_t outer_seq,
                 uint32_t frame_idx, const std::string& tag) {
    sse63113::IndexSnapshotView v(body, blen);
    if (!v.valid()) {
        std::cout << "  [IndexSnapshot 解析失败 blen=" << blen << "]\n";
        return;
    }
    std::cout << "\n[IndexSnap] " << tag
              << "  outer_seq=" << outer_seq
              << "  frame#" << frame_idx << "\n"
              << "  SecurityID     = " << v.security_id()          << "\n"
              << "  UpdateTime     = " << fmtHHMMSS(v.update_time())
              << "  (" << v.update_time() << ")\n"
              << "  TemplateId     = " << v.template_id()          << "\n"
              << "  HeaderA        = " << v.header_a()             << "\n"
              << "  LastPx         = " << fmtPrice1e5(v.last_px()) << "\n"
              << "  PxB (前收?)    = " << fmtPrice1e5(v.px_b())    << "\n"
              << "  TotalVolume    = " << v.total_volume()         << "\n"
              << "  PxC            = " << fmtPrice1e5(v.px_c())    << "\n"
              << "  PxD (=PxB)     = " << fmtPrice1e5(v.px_d())    << "\n"
              << "  PxE            = " << fmtPrice1e5(v.px_e())    << "\n"
              << "  FieldF         = " << v.field_f()              << "\n"
              << "  TotalValue?    = " << v.total_value()          << "\n"
              << "  Flag           = " << v.flag()                 << "\n";
}

// -------- 帧切分器 (只关心 (6, 3113)) --------

class Splitter {
public:
    size_t      max_frames = 0;   // 0 = 不限
    std::string stream_tag;

    void feed(const uint8_t* data, size_t len) {
        buf_.insert(buf_.end(), data, data + len);
        drain();
    }

private:
    std::vector<uint8_t> buf_;
    uint32_t             frame_idx_ = 0;
    uint32_t             printed_   = 0;

    void drain() {
        while (buf_.size() >= 40) {
            size_t idx = scanMagic();
            if (idx == std::string::npos) {
                if (buf_.size() > 3) buf_.erase(buf_.begin(), buf_.end() - 3);
                return;
            }
            if (idx > 0) buf_.erase(buf_.begin(), buf_.begin() + idx);
            if (buf_.size() < 40) return;

            uint32_t length = readBE32(&buf_[4]);
            if (length < 40 || length > 16u * 1024u * 1024u) {
                buf_.erase(buf_.begin(), buf_.begin() + 4);
                continue;
            }
            if (buf_.size() < length) return;

            handleFrame(buf_.data(), length);
            buf_.erase(buf_.begin(), buf_.begin() + length);
        }
    }

    size_t scanMagic() const {
        if (buf_.size() < 4) return std::string::npos;
        size_t n = buf_.size() - 3;
        for (size_t i = 0; i < n; ++i) {
            if (buf_[i]     == 0x00 && buf_[i + 1] == 0x04 &&
                buf_[i + 2] == 0xC4 && buf_[i + 3] == 0x53) return i;
        }
        return std::string::npos;
    }

    void handleFrame(const uint8_t* f, uint32_t length) {
        uint32_t hi = readBE32(f + 8);
        uint32_t lo = readBE32(f + 12);
        if (hi != kWantHi || lo != kWantLo) return;

        ++frame_idx_;
        if (max_frames > 0 && printed_ >= max_frames) return;
        ++printed_;

        uint32_t       seq  = readBE32(f + 16);
        const uint8_t* body = f + 40;
        size_t         blen = length - 40;
        decodeFrame(body, blen, seq, frame_idx_, stream_tag);
    }
};

// -------- pcap 回调 --------

struct Context {
    uint16_t filter_port = 5261;
    size_t   max_frames  = 0;
    std::unordered_map<uint32_t, std::unique_ptr<Splitter>> streams;
};

bool portMatch(const pcpp::ConnectionData& c, uint16_t port) {
    return port == 0 || c.srcPort == port || c.dstPort == port;
}

void onConnStart(const pcpp::ConnectionData& c, void* cookie) {
    auto* ctx = static_cast<Context*>(cookie);
    if (!portMatch(c, ctx->filter_port)) return;
    auto sp = std::make_unique<Splitter>();
    sp->max_frames = ctx->max_frames;
    std::ostringstream ss;
    ss << c.srcIP.toString() << ":" << c.srcPort
       << "->" << c.dstIP.toString() << ":" << c.dstPort;
    sp->stream_tag = ss.str();
    std::cout << "[start] " << sp->stream_tag << "\n";
    ctx->streams[c.flowKey] = std::move(sp);
}

void onTcpData(int8_t, const pcpp::TcpStreamData& data, void* cookie) {
    auto* ctx = static_cast<Context*>(cookie);
    auto  it  = ctx->streams.find(data.getConnectionData().flowKey);
    if (it == ctx->streams.end()) return;
    it->second->feed(reinterpret_cast<const uint8_t*>(data.getData()),
                     data.getDataLength());
}

void onConnEnd(const pcpp::ConnectionData& c,
               pcpp::TcpReassembly::ConnectionEndReason, void* cookie) {
    auto* ctx = static_cast<Context*>(cookie);
    ctx->streams.erase(c.flowKey);
}

}  // anonymous namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "用法: " << argv[0]
                  << " <pcap> [filter_port=5261] [max_frames_per_stream=0]\n"
                  << "  max_frames_per_stream = 0 → 每条 TCP 流内不限帧数\n";
        return 1;
    }

    Context ctx;
    ctx.filter_port = (argc >= 3) ? uint16_t(std::stoi(argv[2])) : 5261;
    ctx.max_frames  = (argc >= 4) ? size_t(std::stoul(argv[3])) : 0;

    pcpp::PcapFileReaderDevice reader(argv[1]);
    if (!reader.open()) {
        std::cerr << "打开 pcap 失败: " << argv[1] << "\n";
        return 1;
    }

    pcpp::TcpReassembly reassembly(onTcpData, &ctx, onConnStart, onConnEnd);
    pcpp::RawPacket     raw;
    while (reader.getNextPacket(raw)) reassembly.reassemblePacket(&raw);
    reassembly.closeAllConnections();
    reader.close();
    return 0;
}
