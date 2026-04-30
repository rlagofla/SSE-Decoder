#pragma once
// 9_5803_decode_engine.hpp — 解码引擎 (非 main 共享逻辑)
//
// 同时被 decode_9_5803.cpp (file reader) 和 decode_9_5803_live.cpp (live reader) include。
// 每个 TU 各拥有一份匿名 namespace 全局变量, 无链接冲突。
//
// 依赖: zlib, PcapPlusPlus (TcpReassembly), 9_5803_struct.hpp

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <zlib.h>
#include <TcpReassembly.h>

#include "9_5803_struct.hpp"

namespace {

constexpr uint32_t kMagic  = 0x0004C453u;
constexpr uint32_t kWantHi = 9;
constexpr uint32_t kWantLo = 5803;

uint32_t readBE32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) <<  8) |  uint32_t(p[3]);
}

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
            inflateEnd(&zs); return false;
        }
        out.insert(out.end(), buf.data(), buf.data() + (buf.size() - zs.avail_out));
    } while (ret != Z_STREAM_END && zs.avail_in > 0);
    inflateEnd(&zs);
    return true;
}

// ---- 输出格式 ----

enum class OutMode { Human, BizCsv, RawCsv };
OutMode  g_mode = OutMode::Human;

sse95803::BusinessState* g_cur_state = nullptr;
bool                     g_done      = false;

// 跨 TCP 流去重: key = (channel << 32) | uint32_t(biz_index)
std::unordered_set<uint64_t> g_seen_biz;

void printBizCsvHeaderOnce() {
    static bool done = false;
    if (done) return;
    done = true;
    std::cout << "BizIndex,Channel,SecurityID,TickTime,Type,"
                 "BuyOrderNO,SellOrderNO,Price,Qty,TradeMoney,"
                 "TickBSFlag,ExtCode,OuterSeq,FrameIdx,RecLen\n";
}

void printRawCsvHeaderOnce() {
    static bool done = false;
    if (done) return;
    done = true;
    std::cout << "RecIdx,OuterSeq,FrameIdx,PMAP,TID,SecID,SecIDInherited,"
                 "Action,ActionInherited,PrefixInts,MiddleInts,"
                 "BSFlag,ExtCodeHex,ExtCodeAscii,RecLen\n";
}

std::string joinIntsWithWidths(const std::vector<uint64_t>& ints,
                                const std::vector<size_t>& widths) {
    std::ostringstream ss;
    for (size_t i = 0; i < ints.size(); ++i) {
        if (i) ss << '|';
        ss << ints[i] << ':' << widths[i] << 'B';
    }
    return ss.str();
}

void emitRaw(const sse95803::TickRecord& r, uint32_t outer_seq,
             uint32_t frame_idx, size_t rec_idx) {
    printRawCsvHeaderOnce();
    char ext_ch = (r.ext_code >= 32 && r.ext_code < 127)
                      ? char(r.ext_code) : '.';
    std::cout << rec_idx << ','
              << outer_seq << ','
              << frame_idx << ','
              << "0x" << std::hex << std::setw(2) << std::setfill('0')
              << unsigned(r.pmap) << std::dec << std::setfill(' ') << ','
              << r.template_id << ','
              << r.security_id << ','
              << (r.has_security_id ? 1 : 0) << ','
              << (r.action ? r.action : '?') << ','
              << (r.has_action ? 1 : 0) << ','
              << joinIntsWithWidths(r.prefix_ints, r.prefix_widths) << ','
              << joinIntsWithWidths(r.ints, r.widths) << ','
              << (r.bs_flag ? r.bs_flag : '?') << ','
              << "0x" << std::hex << std::setw(2) << std::setfill('0')
              << unsigned(r.ext_code) << std::dec << std::setfill(' ') << ','
              << ext_ch << ','
              << r.raw_len << '\n';
}

void emitBiz(const sse95803::TickRecord& r, uint32_t outer_seq,
             uint32_t frame_idx) {
    printBizCsvHeaderOnce();
    sse95803::TickBusiness b;
    if (!sse95803::decodeBusiness(r, *g_cur_state, b)) {
        std::cout << "?," << g_cur_state->last_channel << ',' << r.security_id
                  << ",?," << (r.action ? r.action : '?')
                  << ",?,?,?,?,?," << (r.bs_flag ? r.bs_flag : '?')
                  << ",0x" << std::hex << std::setw(2) << std::setfill('0')
                  << unsigned(r.ext_code) << std::dec << std::setfill(' ')
                  << ',' << outer_seq << ',' << frame_idx << ',' << r.raw_len
                  << '\n';
        return;
    }

    uint64_t key = (uint64_t(b.channel) << 32) | uint32_t(b.biz_index);
    if (!g_seen_biz.insert(key).second) return;

    char ext_ch = (b.ext_code >= 32 && b.ext_code < 127)
                      ? char(b.ext_code) : '.';
    std::cout << b.biz_index << ','
              << b.channel << ','
              << b.security_id << ','
              << sse95803::fmtTickTime(b.tick_time) << ','
              << b.type << ','
              << b.buy_order_no << ','
              << b.sell_order_no << ','
              << sse95803::fmtDecFixed(b.price_e3, 3) << ','
              << sse95803::fmtDecFixed(b.qty_e3, 3) << ','
              << sse95803::fmtDecFixed(b.money_e5, 5) << ','
              << b.bs_flag << ','
              << ext_ch << ','
              << outer_seq << ',' << frame_idx << ',' << r.raw_len << '\n';
}

void emitHuman(const sse95803::TickRecord& r, uint32_t outer_seq,
               const std::string& stream_tag, uint32_t frame_idx,
               size_t rec_idx) {
    sse95803::TickBusiness b;
    sse95803::decodeBusiness(r, *g_cur_state, b);

    uint64_t key = (uint64_t(b.channel) << 32) | uint32_t(b.biz_index);
    if (!g_seen_biz.insert(key).second) return;

    std::cout << "\n[tick] " << stream_tag
              << "  frame#" << frame_idx << "  rec#" << rec_idx
              << "  outer_seq=" << outer_seq
              << "  len=" << r.raw_len << "\n"
              << "  PMAP=0x" << std::hex << std::setw(2) << std::setfill('0')
              << unsigned(r.pmap) << std::dec << std::setfill(' ')
              << "  TID=" << r.template_id << "\n"
              << "  BizIndex   = " << b.biz_index << "\n"
              << "  Channel    = " << b.channel << "\n"
              << "  SecurityID = " << b.security_id
              << (r.has_security_id ? "" : " (继承)") << "\n"
              << "  TickTime   = " << sse95803::fmtTickTime(b.tick_time)
              << " (" << b.tick_time << ")\n"
              << "  Type       = " << (b.type ? b.type : '?')
              << (r.has_action ? "" : " (继承)") << "\n"
              << "  BuyOrderNO = " << b.buy_order_no << "\n"
              << "  SellOrderNO= " << b.sell_order_no << "\n"
              << "  Price      = " << sse95803::fmtDecFixed(b.price_e3, 3) << "\n"
              << "  Qty        = " << sse95803::fmtDecFixed(b.qty_e3, 3) << "\n"
              << "  TradeMoney = " << sse95803::fmtDecFixed(b.money_e5, 5) << "\n"
              << "  BSFlag     = " << (b.bs_flag ? b.bs_flag : '?') << "\n"
              << "  ExtCode    = 0x" << std::hex << std::setw(2) << std::setfill('0')
              << unsigned(b.ext_code) << std::dec << std::setfill(' ') << " ('"
              << char(b.ext_code >= 32 && b.ext_code < 127 ? b.ext_code : '.')
              << "')\n";
    if (!b.valid) {
        std::cout << "  [WARN] 解码失败: MiddleInts 数量与 Action 模板不符\n"
                  << "    PrefixInts = " << joinIntsWithWidths(r.prefix_ints, r.prefix_widths) << "\n"
                  << "    MiddleInts = " << joinIntsWithWidths(r.ints, r.widths) << "\n";
    }
}

// ---- Type='S' (TradingPhaseCode) 状态记录 emit ----

void emitStatBiz(const sse95803::StatusRecord& s, uint32_t outer_seq,
                 uint32_t frame_idx) {
    printBizCsvHeaderOnce();
    std::string tt = s.has_transact_time
                         ? sse95803::fmtTickTime(s.transact_time)
                         : "";
    // Type='S' 的 FAST 报文中没有 BizIndex/Channel/价量字段, 统一留空
    std::cout << ','                  // BizIndex (FAST 中不存在)
              << ','                  // Channel  (FAST 中不存在)
              << s.security_id << ','
              << tt << ','
              << 'S' << ','
              << ",,,,,"              // BuyNO,SellNO,Price,Qty,Money (不适用)
              << s.trading_phase << ','
              << ','                  // ExtCode  (不适用)
              << outer_seq << ',' << frame_idx << ',' << 0 << '\n';
}

void emitStatHuman(const sse95803::StatusRecord& s, uint32_t outer_seq,
                   const std::string& stream_tag, uint32_t frame_idx) {
    std::cout << "\n[stat] " << stream_tag
              << "  frame#" << frame_idx
              << "  outer_seq=" << outer_seq << "\n"
              << "  SecurityID     = " << s.security_id << "\n"
              << "  TradingPhase   = " << s.trading_phase << "\n";
    if (s.has_transact_time)
        std::cout << "  TransactTime   = " << sse95803::fmtTickTime(s.transact_time)
                  << " (" << s.transact_time << ")\n";
    if (!s.prefix_ints.empty()) {
        std::cout << "  FrameSeq       =";
        for (auto v : s.prefix_ints) std::cout << ' ' << v;
        std::cout << '\n';
    }
}

void emitRecord(const sse95803::TickRecord& r, uint32_t outer_seq,
                const std::string& stream_tag, uint32_t frame_idx,
                size_t rec_idx) {
    // action==0 → 尝试解析为 Type='S' 状态记录
    if (r.action == 0) {
        sse95803::StatusRecord sr;
        if (sse95803::decodeStat(r, sr)) {
            switch (g_mode) {
                case OutMode::BizCsv: emitStatBiz(sr, outer_seq, frame_idx);              break;
                case OutMode::Human:  emitStatHuman(sr, outer_seq, stream_tag, frame_idx); break;
                case OutMode::RawCsv: emitRaw(r, outer_seq, frame_idx, rec_idx);          break;
            }
            return;
        }
    }
    switch (g_mode) {
        case OutMode::BizCsv: emitBiz(r, outer_seq, frame_idx); break;
        case OutMode::RawCsv: emitRaw(r, outer_seq, frame_idx, rec_idx); break;
        case OutMode::Human:  emitHuman(r, outer_seq, stream_tag, frame_idx, rec_idx); break;
    }
}

void decodeFrame(const uint8_t* frame_head, size_t frame_len,
                 const std::string& stream_tag, uint32_t frame_idx) {
    uint32_t outer_seq = readBE32(frame_head + 16);
    uint32_t comp      = readBE32(frame_head + 32);
    const uint8_t* body = frame_head + 40;
    size_t         blen = frame_len - 40;

    std::vector<uint8_t> inflated;
    const uint8_t* payload = body;
    size_t         plen    = blen;

    if (comp == 1) {
        if (!rawInflateZipLFH(body, blen, inflated)) {
            std::cerr << "[warn] frame#" << frame_idx
                      << " inflate failed, skipped (outer_seq=" << outer_seq
                      << ")\n";
            return;
        }
        payload = inflated.data();
        plen    = inflated.size();
    }

    sse95803::TickStreamParser parser(payload, plen);
    sse95803::TickRecord       rec;
    for (size_t i = 0; i < parser.record_count(); ++i) {
        if (!parser.parse(i, rec)) continue;
        if (rec.template_id != kWantLo) continue;
        emitRecord(rec, outer_seq, stream_tag, frame_idx, i);
    }
}

// ---- 帧切分 ----

class Splitter {
public:
    size_t      max_frames = 0;
    std::string stream_tag;
    sse95803::BusinessState biz_state;

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
        if (max_frames > 0 && printed_ >= max_frames) { g_done = true; return; }
        ++printed_;
        g_cur_state = &biz_state;
        decodeFrame(f, length, stream_tag, frame_idx_);
        g_cur_state = nullptr;
    }
};

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
    std::cerr << "[start] " << sp->stream_tag << "\n";
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

// ---- 命令行参数解析 (file 和 live 共用部分) ----

void parseCommonArgs(int argc, char** argv, int start,
                     uint16_t& filter_port, OutMode& mode) {
    filter_port = (argc > start)     ? uint16_t(std::stoi(argv[start])) : 5261;
    for (int i = start + 1; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--csv")     mode = OutMode::BizCsv;
        else if (a == "--raw-csv") mode = OutMode::RawCsv;
    }
}

}  // namespace
