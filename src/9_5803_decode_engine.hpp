#pragma once
// 9_5803_decode_engine.hpp — 解码引擎 (非 main 共享逻辑)
//
// 同时被 decode_9_5803.cpp (file reader) 和 decode_9_5803_live.cpp (live reader) include。
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
#include <spdlog/spdlog.h>

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
    // 验证 LFH 签名
    if (n < 30 || body[0] != 'P' || body[1] != 'K' ||
        body[2] != 3 || body[3] != 4) {
        spdlog::warn("[inflate] ZIP LFH 魔数校验失败: n={} head={:02x} {:02x} {:02x} {:02x}",
                     n,
                     n > 0 ? body[0] : 0, n > 1 ? body[1] : 0,
                     n > 2 ? body[2] : 0, n > 3 ? body[3] : 0);
        return false;
    }

    // 验证压缩方式必须为 deflate(8)
    uint16_t method = uint16_t(body[8]) | (uint16_t(body[9]) << 8);
    if (method != 8) {
        spdlog::warn("[inflate] 压缩方式不是 deflate(8): method={}", method);
        return false;
    }

    uint16_t name_len  = uint16_t(body[26]) | (uint16_t(body[27]) << 8);
    uint16_t extra_len = uint16_t(body[28]) | (uint16_t(body[29]) << 8);
    size_t   start     = 30u + name_len + extra_len;
    if (start >= n) {
        spdlog::warn("[inflate] ZIP LFH 数据区偏移超出 buffer: start={} n={}", start, n);
        return false;
    }

    // 防止 uInt 截断
    size_t compressed_size = n - start;
    if (compressed_size > std::numeric_limits<uInt>::max()) {
        spdlog::warn("[inflate] 压缩数据长度超出 uInt 上限: compressed_size={}", compressed_size);
        return false;
    }

    z_stream zs{};
    if (inflateInit2(&zs, -MAX_WBITS) != Z_OK) {
        spdlog::error("[inflate] inflateInit2 失败");
        return false;
    }
    zs.next_in  = const_cast<Bytef*>(body + start);
    zs.avail_in = uInt(compressed_size);

    out.clear();
    std::vector<uint8_t> buf(64 * 1024);
    int ret;
    do {
        zs.next_out  = buf.data();
        zs.avail_out = uInt(buf.size());

        uInt before_in  = zs.avail_in;
        uInt before_out = zs.avail_out;

        ret = inflate(&zs, Z_NO_FLUSH);

        if (ret != Z_OK && ret != Z_STREAM_END) {
            spdlog::warn("[inflate] inflate 返回错误: ret={} msg={} avail_in={} compressed_size={}",
                        ret, zs.msg ? zs.msg : "(null)", zs.avail_in, compressed_size);
            inflateEnd(&zs);
            return false;
        }

        // 无进展防御：input 和 output 都没变化 → 直接放弃
        if (zs.avail_in == before_in && zs.avail_out == before_out) {
            spdlog::warn("[inflate] inflate 无进展，放弃: avail_in={} avail_out={}",
                        zs.avail_in, zs.avail_out);
            inflateEnd(&zs);
            return false;
        }

        out.insert(out.end(), buf.data(), buf.data() + (buf.size() - zs.avail_out));
    } while (ret != Z_STREAM_END);

    inflateEnd(&zs);
    return ret == Z_STREAM_END;
}

// ---- 输出格式 ----

enum class OutMode { Human, BizCsv, RawCsv };
OutMode g_mode = OutMode::Human;
bool    g_done = false;

// 跨 TCP 流去重: key = (channel << 32) | uint32_t(biz_index)
std::unordered_set<uint64_t> g_seen_biz;

void printBizCsvHeaderOnce() {
    static bool done = false;
    if (done) return;
    done = true;
    std::cout << "BizIndex,Channel,SecurityID,TickTime,Type,"
                 "BuyOrderNO,SellOrderNO,Price,Qty,TradeMoney,"
                 "TickBSFlag,OuterSeq,FrameIdx,RecLen\n";
}

void printRawCsvHeaderOnce() {
    static bool done = false;
    if (done) return;
    done = true;
    std::cout << "RecIdx,OuterSeq,FrameIdx,PMAP,"
                 "BizIndex,Channel,SecID,TickTime,Action,"
                 "BuyOrderNO,SellOrderNO,Price,Qty,TradeMoney,BSFlag\n";
}

void emitRaw(const sse95803::TickRecord& r, uint32_t outer_seq,
             uint32_t frame_idx, size_t rec_idx) {
    printRawCsvHeaderOnce();
    std::cout << rec_idx << ','
              << outer_seq << ','
              << frame_idx << ','
              << "0x" << std::hex << std::setw(4) << std::setfill('0')
              << r.pmap_raw << std::dec << std::setfill(' ') << ','
              << r.biz_index << ','
              << r.channel << ','
              << r.security_id << ','
              << sse95803::fmtTickTime(r.tick_time) << ','
              << (r.action ? r.action : '?') << ','
              << r.buy_order_no << ','
              << r.sell_order_no << ','
              << sse95803::fmtDecFixed(r.price_e3, 3) << ','
              << sse95803::fmtDecFixed(r.qty_e3, 3) << ','
              << sse95803::fmtDecFixed(r.money_e5, 5) << ','
              << (r.bs_flag ? r.bs_flag : '?') << '\n';
}

void emitBiz(const sse95803::TickRecord& r, uint32_t outer_seq,
             uint32_t frame_idx) {
    printBizCsvHeaderOnce();
    if (!r.valid) {
        std::cout << "?," << r.channel << ',' << r.security_id
                  << ",?," << (r.action ? r.action : '?')
                  << ",?,?,?,?,?," << (r.bs_flag ? r.bs_flag : '?')
                  << ',' << outer_seq << ',' << frame_idx << ",0\n";
        return;
    }

    uint64_t key = (uint64_t(r.channel) << 32) | uint32_t(r.biz_index);
    if (!g_seen_biz.insert(key).second) return;

    std::cout << r.biz_index << ','
              << r.channel << ','
              << r.security_id << ','
              << sse95803::fmtTickTime(r.tick_time) << ','
              << r.action << ','
              << r.buy_order_no << ','
              << r.sell_order_no << ','
              << sse95803::fmtDecFixed(r.price_e3, 3) << ','
              << sse95803::fmtDecFixed(r.qty_e3, 3) << ','
              << sse95803::fmtDecFixed(r.money_e5, 5) << ','
              << r.bs_flag << ','
              << outer_seq << ',' << frame_idx << ",0\n";
}

void emitHuman(const sse95803::TickRecord& r, uint32_t outer_seq,
               const std::string& stream_tag, uint32_t frame_idx,
               size_t rec_idx) {
    uint64_t key = (uint64_t(r.channel) << 32) | uint32_t(r.biz_index);
    if (!g_seen_biz.insert(key).second) return;

    std::cout << "\n[tick] " << stream_tag
              << "  frame#" << frame_idx << "  rec#" << rec_idx
              << "  outer_seq=" << outer_seq << "\n"
              << "  PMAP=0x" << std::hex << std::setw(4) << std::setfill('0')
              << r.pmap_raw << std::dec << std::setfill(' ')
              << "  TID=" << r.template_id << "\n"
              << "  BizIndex   = " << r.biz_index << "\n"
              << "  Channel    = " << r.channel << "\n"
              << "  SecurityID = " << r.security_id << "\n"
              << "  TickTime   = " << sse95803::fmtTickTime(r.tick_time)
              << " (" << r.tick_time << ")\n"
              << "  Type       = " << (r.action ? r.action : '?') << "\n"
              << "  BuyOrderNO = " << r.buy_order_no << "\n"
              << "  SellOrderNO= " << r.sell_order_no << "\n"
              << "  Price      = " << sse95803::fmtDecFixed(r.price_e3, 3) << "\n"
              << "  Qty        = " << sse95803::fmtDecFixed(r.qty_e3, 3) << "\n"
              << "  TradeMoney = " << sse95803::fmtDecFixed(r.money_e5, 5) << "\n"
              << "  BSFlag     = " << (r.bs_flag ? r.bs_flag : '?') << "\n";
    if (!r.valid) {
        std::cout << "  [WARN] 解码失败\n";
    }
}

void emitStatBiz(const sse95803::TickRecord& r, uint32_t outer_seq,
                 uint32_t frame_idx) {
    printBizCsvHeaderOnce();
    std::string tt = r.tick_time ? sse95803::fmtTickTime(r.tick_time) : "";
    std::cout << ','                 // BizIndex
              << ','                 // Channel
              << r.security_id << ','
              << tt << ','
              << 'S' << ','
              << ",,,,,"             // BuyNO,SellNO,Price,Qty,Money
              << ','                 // BSFlag（状态记录没有）
              << outer_seq << ',' << frame_idx << ",0\n";
}

void emitStatHuman(const sse95803::TickRecord& r, uint32_t outer_seq,
                   const std::string& stream_tag, uint32_t frame_idx) {
    std::cout << "\n[stat] " << stream_tag
              << "  frame#" << frame_idx
              << "  outer_seq=" << outer_seq << "\n"
              << "  SecurityID = " << r.security_id << "\n";
    if (r.tick_time)
        std::cout << "  TransactTime = " << sse95803::fmtTickTime(r.tick_time)
                  << " (" << r.tick_time << ")\n";
}

void emitRecord(const sse95803::TickRecord& r, uint32_t outer_seq,
                const std::string& stream_tag, uint32_t frame_idx,
                size_t rec_idx) {
    if (r.is_status_record) {
        switch (g_mode) {
            case OutMode::BizCsv: emitStatBiz(r, outer_seq, frame_idx);               break;
            case OutMode::Human:  emitStatHuman(r, outer_seq, stream_tag, frame_idx); break;
            case OutMode::RawCsv: emitRaw(r, outer_seq, frame_idx, rec_idx);          break;
        }
        return;
    }
    switch (g_mode) {
        case OutMode::BizCsv: emitBiz(r, outer_seq, frame_idx);                       break;
        case OutMode::RawCsv: emitRaw(r, outer_seq, frame_idx, rec_idx);              break;
        case OutMode::Human:  emitHuman(r, outer_seq, stream_tag, frame_idx, rec_idx); break;
    }
}

void decodeFrame(const uint8_t* frame_head, size_t frame_len,
                 const std::string& stream_tag, uint32_t frame_idx) {
    uint32_t outer_seq = readBE32(frame_head + 16);
    uint32_t comp      = readBE32(frame_head + 32);
    const uint8_t* body = frame_head + 40;
    size_t         blen = frame_len - 40;

    spdlog::trace("[frame] {} frame#{} outer_seq={} comp={} body_len={}",
                  stream_tag, frame_idx, outer_seq, comp, blen);

    std::vector<uint8_t> inflated;
    const uint8_t* payload = body;
    size_t         plen    = blen;

    if (comp == 1) {
        if (!rawInflateZipLFH(body, blen, inflated)) {
            spdlog::warn("[frame] {} frame#{} inflate 失败，跳过 outer_seq={}",
                         stream_tag, frame_idx, outer_seq);
            return;
        }
        payload = inflated.data();
        plen    = inflated.size();
        spdlog::trace("[frame] {} frame#{} inflate ok: {} -> {} bytes",
                      stream_tag, frame_idx, blen, plen);
    }

    sse95803::TickStreamParser parser(payload, plen);
    sse95803::TickRecord       rec;
    size_t rec_idx = 0;
    while (parser.next(rec)) {
        if (rec.template_id != kWantLo && !rec.is_status_record) {
            spdlog::trace("[frame] {} frame#{} rec#{} TID={} 不是 {}，跳过",
                          stream_tag, frame_idx, rec_idx, rec.template_id, kWantLo);
            continue;
        }
        emitRecord(rec, outer_seq, stream_tag, frame_idx, rec_idx++);
    }
}

// ---- 帧切分 ----

class Splitter {
public:
    size_t      max_frames = 0;
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
                spdlog::trace("[splitter] {} 未找到魔数，保留尾部 3 字节，丢弃 {} 字节",
                              stream_tag, buf_.size() > 3 ? buf_.size() - 3 : 0u);
                if (buf_.size() > 3) buf_.erase(buf_.begin(), buf_.end() - 3);
                return;
            }
            if (idx > 0) {
                spdlog::trace("[splitter] {} 魔数前有 {} 字节无效数据，跳过",
                              stream_tag, idx);
                buf_.erase(buf_.begin(), buf_.begin() + idx);
            }
            if (buf_.size() < 40) {
                spdlog::trace("[splitter] {} 魔数已对齐但 header 不足 40 字节（{}），等待",
                              stream_tag, buf_.size());
                return;
            }

            uint32_t length = readBE32(&buf_[4]);
            if (length < 40 || length > 16u * 1024u * 1024u) {
                spdlog::warn("[splitter] {} 帧长度异常 length={}（期望 40~16M），跳过 4 字节继续扫描",
                             stream_tag, length);
                buf_.erase(buf_.begin(), buf_.begin() + 4);
                continue;
            }
            if (buf_.size() < length) {
                spdlog::trace("[splitter] {} 帧数据不完整: need={} have={}，等待",
                              stream_tag, length, buf_.size());
                return;
            }
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
        if (hi != kWantHi || lo != kWantLo) {
            spdlog::trace("[splitter] {} 帧类型 ({},{}) 不是期望的 ({},{})，跳过 length={}",
                          stream_tag, hi, lo, kWantHi, kWantLo, length);
            return;
        }

        ++frame_idx_;
        if (max_frames > 0 && printed_ >= max_frames) {
            spdlog::info("[splitter] {} 已达到最大帧数限制 max_frames={}，停止",
                         stream_tag, max_frames);
            g_done = true;
            return;
        }
        ++printed_;
        decodeFrame(f, length, stream_tag, frame_idx_);
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
    if (!portMatch(c, ctx->filter_port)) {
        spdlog::trace("[conn] 端口不匹配（filter={}），跳过 {}:{} -> {}:{}",
                      ctx->filter_port,
                      c.srcIP.toString(), c.srcPort,
                      c.dstIP.toString(), c.dstPort);
        return;
    }
    auto sp = std::make_unique<Splitter>();
    sp->max_frames = ctx->max_frames;
    std::ostringstream ss;
    ss << c.srcIP.toString() << ":" << c.srcPort
       << "->" << c.dstIP.toString() << ":" << c.dstPort;
    sp->stream_tag = ss.str();
    spdlog::info("[conn] 新连接: {}", sp->stream_tag);
    ctx->streams[c.flowKey] = std::move(sp);
}

void onTcpData(int8_t, const pcpp::TcpStreamData& data, void* cookie) {
    auto* ctx = static_cast<Context*>(cookie);
    auto  it  = ctx->streams.find(data.getConnectionData().flowKey);
    if (it == ctx->streams.end()) {
        spdlog::trace("[conn] 收到未跟踪连接的数据 flowKey={}",
                      data.getConnectionData().flowKey);
        return;
    }
    it->second->feed(reinterpret_cast<const uint8_t*>(data.getData()),
                     data.getDataLength());
}

void onConnEnd(const pcpp::ConnectionData& c,
               pcpp::TcpReassembly::ConnectionEndReason reason, void* cookie) {
    auto* ctx = static_cast<Context*>(cookie);
    auto  it  = ctx->streams.find(c.flowKey);
    if (it != ctx->streams.end()) {
        spdlog::info("[conn] 连接结束: {} reason={}",
                     it->second->stream_tag, static_cast<int>(reason));
        ctx->streams.erase(it);
    }
}

void parseCommonArgs(int argc, char** argv, int start,
                     uint16_t& filter_port, OutMode& mode) {
    filter_port = (argc > start) ? uint16_t(std::stoi(argv[start])) : 5261;
    for (int i = start + 1; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--csv")     mode = OutMode::BizCsv;
        else if (a == "--raw-csv") mode = OutMode::RawCsv;
    }
}

}  // namespace
