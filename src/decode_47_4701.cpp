// decode_47_4701.cpp — 上交所 (47, 4701) 通道专用解码器
//
// 该通道在本 pcap 里只出现两种 label:
//   - M101: 交易阶段状态通知 (48B 明文)
//   - M201: L2 聚合快照包 (ZIP 压缩, 49B 头 + N 条变长证券)
// 结构定义见 47_4701_struct.hpp。
//
// 流程:
//   1) 读 pcap + TcpReassembly
//   2) 按 0x0004C453 魔数切帧, 拿到 40B 外层头 + body
//   3) 只保留 (type=47, sub=4701) 帧
//   4) compressed==1 时做 ZIP LFH 裸 deflate 解压
//   5) 按 body[4:8] label 分派到 M101 / M201 解码
//   6) 打印可读表格 (Symbol 从 GBK 转到 UTF-8)
//
// 用法:
//   decode_47_4701 <pcap> [filter_port=5261] [max_sec_per_frame=3] [max_m201_frames=0]
//     max_sec_per_frame = 0 表示每帧内不限条数
//     max_m201_frames   = 0 表示不限帧数

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iconv.h>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <zlib.h>

#include <Packet.h>
#include <PcapFileDevice.h>
#include <TcpReassembly.h>

#include "47_4701_struct.hpp"

using sse::readBE16;
using sse::readBE32;
using sse::readBE64;

namespace {

constexpr uint32_t kMagic  = 0x0004C453u;
constexpr uint32_t kWantHi = 47;
constexpr uint32_t kWantLo = 4701;

// -------- ZIP LFH + 裸 deflate 解压 --------

bool rawInflateZipLFH(const uint8_t* body, size_t n, std::vector<uint8_t>& out) {
    if (n < 30 || body[0] != 'P' || body[1] != 'K' ||
        body[2] != 3 || body[3] != 4) return false;
    uint16_t name_len  = uint16_t(body[26]) | (uint16_t(body[27]) << 8);
    uint16_t extra_len = uint16_t(body[28]) | (uint16_t(body[29]) << 8);
    size_t   start     = 30u + name_len + extra_len;
    if (start >= n) return false;

    z_stream zs{};
    if (inflateInit2(&zs, -MAX_WBITS) != Z_OK) return false;
    zs.next_in  = const_cast<Bytef*>(body + start);
    zs.avail_in = uInt(n - start);

    out.clear();
    std::vector<uint8_t> buf(64 * 1024);
    int ret;
    do {
        zs.next_out  = buf.data();
        zs.avail_out = uInt(buf.size());
        ret = inflate(&zs, Z_SYNC_FLUSH);
        if (ret == Z_NEED_DICT || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
            inflateEnd(&zs);
            return false;
        }
        out.insert(out.end(), buf.data(), buf.data() + (buf.size() - zs.avail_out));
    } while (ret != Z_STREAM_END && zs.avail_in > 0);
    inflateEnd(&zs);
    return true;
}

// -------- GBK → UTF-8 (glibc iconv) --------

std::string gbkToUtf8(const uint8_t* src, size_t n) {
    while (n > 0 && src[n - 1] == ' ') --n;   // 去尾部空格
    if (n == 0) return {};

    iconv_t cd = iconv_open("UTF-8", "GBK");
    if (cd == reinterpret_cast<iconv_t>(-1)) return std::string(reinterpret_cast<const char*>(src), n);

    std::string out(n * 4, '\0');
    char*  in_buf   = const_cast<char*>(reinterpret_cast<const char*>(src));
    size_t in_left  = n;
    char*  out_buf  = out.data();
    size_t out_left = out.size();
    size_t r = iconv(cd, &in_buf, &in_left, &out_buf, &out_left);
    iconv_close(cd);
    if (r == size_t(-1)) return std::string(reinterpret_cast<const char*>(src), n);
    out.resize(out.size() - out_left);
    return out;
}

// -------- 格式化 --------

std::string fmtPrice1e5(uint64_t v) {
    std::ostringstream ss;
    ss << (v / 100000) << '.'
       << std::setw(5) << std::setfill('0') << (v % 100000);
    return ss.str();
}

// -------- 解码 M101 --------

void decodeM101(const uint8_t* payload, size_t plen, uint32_t seq,
                uint32_t frame_idx, const std::string& tag) {
    sse::M101View v(payload, plen);
    if (!v.valid()) {
        std::cout << "  [M101 invalid, plen=" << plen << "]\n";
        return;
    }
    auto phase = v.trading_phase();
    std::cout << "\n[M101] " << tag << "  outer_seq=" << seq
              << "  frame#" << frame_idx << "\n"
              << "  SendingTime    = 0x" << std::hex << std::setw(16)
              << std::setfill('0') << v.sending_time()
              << std::dec << std::setfill(' ') << "\n"
              << "  MsgSeqNum      = " << v.msg_seq_num() << "\n"
              << "  TradingPhase   = \"" << phase << "\"  ("
              << sse::tradingPhaseDesc(phase) << ")\n"
              << "  counter1       = " << v.counter1() << "\n"
              << "  counter2       = " << v.counter2() << "\n";
}

// -------- 解码 M201 --------

void decodeM201(const uint8_t* payload, size_t plen, uint32_t seq,
                uint32_t frame_idx, const std::string& tag,
                size_t max_sec_print) {
    sse::M201Header hdr(payload, plen);
    if (!hdr.valid()) {
        std::cout << "  [M201 invalid, plen=" << plen << "]\n";
        return;
    }
    std::cout << "\n[M201] " << tag << "  outer_seq=" << seq
              << "  frame#" << frame_idx << "\n"
              << "  SendingTime    = 0x" << std::hex << std::setw(16)
              << std::setfill('0') << hdr.sending_time()
              << std::dec << std::setfill(' ') << "\n"
              << "  MsgSeqNum      = " << hdr.msg_seq_num() << "\n"
              << "  TradeDate      = " << hdr.trade_date() << "\n"
              << "  NoEntries      = " << hdr.no_entries() << "\n";

    const uint8_t* p   = payload + sse::M201Header::kSize;
    size_t         rem = plen    - sse::M201Header::kSize;
    uint16_t       n   = hdr.no_entries();

    for (uint16_t i = 0; i < n; ++i) {
        if (max_sec_print > 0 && i >= max_sec_print) {
            std::cout << "  ... (" << (n - i) << " 条证券省略)\n";
            break;
        }
        sse::SecurityEntryView se(p, rem);
        if (!se.hasHeader()) {
            std::cout << "  [entry#" << i << " 截断]\n";
            break;
        }

        std::string sym_u8 = gbkToUtf8(se.symbol_gbk(), 8);
        std::cout << "  -- entry#" << i
                  << "  " << std::string(se.md_stream_id())
                  << "  " << std::string(se.security_id())
                  << "  (" << sym_u8 << ")\n"
                  << "      SecType/recTag = 0x"
                  << std::hex << unsigned(se.security_type())
                  << "/0x" << unsigned(se.record_tag())
                  << std::dec << "\n"
                  << "      PreClose       = " << fmtPrice1e5(se.pre_close_px()) << "\n"
                  << "      TotalVolume    = " << se.total_volume_traded() << "\n"
                  << "      NumTrades      = " << se.num_trades() << "\n"
                  << "      TotalValue     = " << se.total_value_traded() << "\n"
                  << "      TradingPhase   = \"" << se.trading_phase_code() << "\"\n"
                  << "      LastUpdateTime = 0x" << std::hex
                  << se.last_update_time() << std::dec << "\n"
                  << "      NoMDEntries    = " << se.no_md_entries() << "\n";

        const uint8_t* me = se.md_entries_begin();
        uint16_t ne = se.no_md_entries();
        // 防御：如果 MDEntries 会越界就截断
        if (sse::SecurityEntryView::kFixedSize + size_t(ne) * sse::MDEntryView::kSize > rem) {
            ne = uint16_t((rem - sse::SecurityEntryView::kFixedSize) / sse::MDEntryView::kSize);
        }
        for (uint16_t j = 0; j < ne; ++j) {
            sse::MDEntryView ent(me + j * sse::MDEntryView::kSize);
            std::cout << "        [" << std::setw(2) << j << "] "
                      << ent.entry_type() << " (" << sse::mdEntryTypeDesc(ent.entry_type()) << ")"
                      << "  px=" << std::setw(12) << fmtPrice1e5(ent.price())
                      << "  qty=" << std::setw(10) << ent.qty()
                      << "  pos=" << unsigned(ent.position_no()) << "\n";
        }

        size_t sz = se.totalSize();
        if (sz > rem) break;
        p   += sz;
        rem -= sz;
    }
}

// -------- 帧切分器 (只关心 (47, 4701)) --------

class Splitter {
public:
    size_t      max_sec_print   = 3;
    size_t      max_m201_frames = 0;    // 0 = 不限
    std::string stream_tag;

    void feed(const uint8_t* data, size_t len) {
        buf_.insert(buf_.end(), data, data + len);
        drain();
    }

private:
    std::vector<uint8_t> buf_;
    uint32_t             frame_idx_     = 0;   // (47,4701) 帧序号, 从 1 开始
    uint32_t             printed_m201_  = 0;

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
            if (buf_[i] == 0x00 && buf_[i+1] == 0x04 &&
                buf_[i+2] == 0xC4 && buf_[i+3] == 0x53) return i;
        }
        return std::string::npos;
    }

    void handleFrame(const uint8_t* f, uint32_t length) {
        uint32_t hi   = readBE32(f + 8);
        uint32_t lo   = readBE32(f + 12);
        if (hi != kWantHi || lo != kWantLo) return;

        uint32_t seq  = readBE32(f + 16);
        uint32_t comp = readBE32(f + 32);
        const uint8_t* body = f + 40;
        size_t         blen = length - 40;
        ++frame_idx_;

        std::vector<uint8_t> inflated;
        const uint8_t* payload = body;
        size_t         plen    = blen;
        if (comp == 1) {
            if (!rawInflateZipLFH(body, blen, inflated)) {
                std::cout << "\n[解压失败] " << stream_tag
                          << "  outer_seq=" << seq
                          << "  frame#" << frame_idx_ << "\n";
                return;
            }
            payload = inflated.data();
            plen    = inflated.size();
        }

        if (plen < 8) return;
        if (std::memcmp(payload + 4, "M101", 4) == 0) {
            decodeM101(payload, plen, seq, frame_idx_, stream_tag);
            return;
        }
        if (std::memcmp(payload + 4, "M201", 4) == 0) {
            if (max_m201_frames > 0 && printed_m201_ >= max_m201_frames) return;
            ++printed_m201_;
            decodeM201(payload, plen, seq, frame_idx_, stream_tag, max_sec_print);
            return;
        }
        std::cout << "\n[意外标签 "
                  << std::string(reinterpret_cast<const char*>(payload + 4), 4)
                  << "] " << stream_tag << "  outer_seq=" << seq << "\n";
    }
};

// -------- pcap 回调 --------

struct Context {
    uint16_t filter_port     = 5261;
    size_t   max_sec_print   = 3;
    size_t   max_m201_frames = 0;
    std::unordered_map<uint32_t, std::unique_ptr<Splitter>> streams;
};

bool portMatch(const pcpp::ConnectionData& c, uint16_t port) {
    return port == 0 || c.srcPort == port || c.dstPort == port;
}

void onConnStart(const pcpp::ConnectionData& c, void* cookie) {
    auto* ctx = static_cast<Context*>(cookie);
    if (!portMatch(c, ctx->filter_port)) return;
    auto sp = std::make_unique<Splitter>();
    sp->max_sec_print    = ctx->max_sec_print;
    sp->max_m201_frames  = ctx->max_m201_frames;
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
                  << " <pcap> [filter_port=5261] [max_sec_per_frame=3] [max_m201_frames=0]\n"
                  << "  max_sec_per_frame = 0 → 每帧内不限条数\n"
                  << "  max_m201_frames   = 0 → 不限 M201 帧数 (M101 始终全打)\n";
        return 1;
    }

    Context ctx;
    ctx.filter_port     = (argc >= 3) ? uint16_t(std::stoi(argv[2])) : 5261;
    ctx.max_sec_print   = (argc >= 4) ? size_t(std::stoul(argv[3])) : 3;
    ctx.max_m201_frames = (argc >= 5) ? size_t(std::stoul(argv[4])) : 0;

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
