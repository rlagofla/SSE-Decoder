#pragma once
// SsePipeline.hpp — SSE 解析管道（TickStreamParser、Splitter、Context）
//
// PMAP 位布局（readFast 读出的 14-bit 值，TID 在最高位 bit13）:
//   bit13: TID          (1 = 读 2d ab)
//   bit12: BizIndex     (0 = last+1,  1 = 显式 FAST u64)
//   bit11: Channel      (0 = copy,    1 = 显式 FAST u32)
//   bit10: SecurityID   (0 = copy,    1 = 显式 ASCII)
//   bit 9: TickTime     (0 = copy,    1 = 显式 FAST u32 nullable)
//   bit 8: Action       (0 = copy,    1 = 显式 ASCII char; 'A'/'D'/'T'/'C'/'S')
//   bit 7: BuyOrderNO   (0 = 0,       1 = 显式 FAST u64 nullable)
//   bit 6: SellOrderNO  (0 = 0,       1 = 显式 FAST u64 nullable)
//   bit 5: Price        (0 = 0,       1 = 显式 FAST u32 nullable)
//   bit 4: Qty          (0 = 0,       1 = 显式 FAST u64 nullable)
//   bit 3: TradeMoney   (0 = 0,       1 = 显式 FAST u64 nullable)
//   bit 2: BSFlag       (0 = copy,    1 = 显式 ASCII; 'B'/'S'/'N' 或 "SUSP"/"OCALL"/"START")

#include <iomanip>
#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <spdlog/spdlog.h>

#include "SseStructs.hpp"
#include "utils.hpp"

// ---- TickStreamParser ----

namespace sse95803 {

// PMAP 驱动的顺序解析器
class TickStreamParser {
public:
    TickStreamParser(const uint8_t* body, size_t len)
        : body_(body), len_(len) {}

    // 读取下一条记录，返回 false 表示 body 耗尽或解析失败
    bool next(TickRecord& rec) {
        rec = TickRecord{};

        if (cursor_ >= len_) return false;

        uint64_t bits = 0;
        size_t   pm_len = 0;
        if (fast::readFast(body_ + cursor_, len_ - cursor_, bits, pm_len)
                != fast::Status::Ok) {
            spdlog::warn("[9-5803] PMAP 读取失败: cursor={} remaining={}",
                         cursor_, len_ - cursor_);
            return false;
        }
        cursor_ += pm_len;
        rec.pmap_raw = uint16_t(bits);

        // bit13: TID
        if (bits & (1ull << 13)) {
            if (cursor_ + 2 > len_) {
                spdlog::warn("[9-5803] TID: buffer 不足 2 字节: cursor={} len={}",
                             cursor_, len_);
                return false;
            }
            if (body_[cursor_] != 0x2d || body_[cursor_ + 1] != 0xab) {
                spdlog::warn("[9-5803] TID: 期望 2d ab, 实际 {:02x} {:02x}: cursor={}",
                             body_[cursor_], body_[cursor_ + 1], cursor_);
                return false;
            }
            cursor_ += 2;
            rec.template_id = 5803;
        }

        // bit12: BizIndex
        if (bits & (1ull << 12)) {
            uint64_t v; size_t w;
            if (fast::readFast(body_ + cursor_, len_ - cursor_, v, w)
                    != fast::Status::Ok) {
                spdlog::warn("[9-5803] BizIndex: FAST 读取失败: cursor={}", cursor_);
                return false;
            }
            cursor_ += w;
            last_biz_index_ = v;
        } else {
            ++last_biz_index_;
        }
        rec.biz_index = last_biz_index_;

        // bit11: Channel
        if (bits & (1ull << 11)) {
            uint64_t v; size_t w;
            if (fast::readFast(body_ + cursor_, len_ - cursor_, v, w)
                    != fast::Status::Ok) {
                spdlog::warn("[9-5803] Channel: FAST 读取失败: cursor={}", cursor_);
                return false;
            }
            cursor_ += w;
            last_channel_ = uint32_t(v);
        }
        rec.channel = last_channel_;

        // bit10: SecurityID
        if (bits & (1ull << 10)) {
            std::string sid; size_t w;
            if (fast::readAscii(body_ + cursor_, len_ - cursor_, sid, w)
                    != fast::Status::Ok) {
                spdlog::warn("[9-5803] SecurityID: 读取失败: cursor={} remaining={}",
                             cursor_, len_ - cursor_);
                return false;
            }
            cursor_ += w;
            last_sec_id_ = std::move(sid);
        }
        rec.security_id = last_sec_id_;

        // bit9: TickTime (nullable)
        if (bits & (1ull << 9)) {
            uint64_t v; size_t w;
            if (fast::readFast(body_ + cursor_, len_ - cursor_, v, w)
                    != fast::Status::Ok) {
                spdlog::warn("[9-5803] TickTime: FAST 读取失败: cursor={}", cursor_);
                return false;
            }
            cursor_ += w;
            auto [t, is_null] = fast::decNull(v);
            last_tick_time_ = is_null ? last_tick_time_ : uint32_t(t);
        }
        rec.tick_time = last_tick_time_;

        // bit8: Action ('A'/'D'/'T'/'C'/'S')
        if (bits & (1ull << 8)) {
            if (cursor_ >= len_) {
                spdlog::warn("[9-5803] Action: buffer 已耗尽: cursor={}", cursor_);
                return false;
            }
            last_action_ = char(body_[cursor_++] & 0x7F);
        }
        rec.action = last_action_;

        // bit7: BuyOrderNO (nullable)
        if (bits & (1ull << 7)) {
            uint64_t v; size_t w;
            if (fast::readFast(body_ + cursor_, len_ - cursor_, v, w)
                    != fast::Status::Ok) {
                spdlog::warn("[9-5803] BuyOrderNO: FAST 読取失败: cursor={}", cursor_);
                return false;
            }
            cursor_ += w;
            auto [x, is_null] = fast::decNull(v);
            rec.buy_order_no = is_null ? 0 : x;
        }

        // bit6: SellOrderNO (nullable)
        if (bits & (1ull << 6)) {
            uint64_t v; size_t w;
            if (fast::readFast(body_ + cursor_, len_ - cursor_, v, w)
                    != fast::Status::Ok) {
                spdlog::warn("[9-5803] SellOrderNO: FAST 读取失败: cursor={}", cursor_);
                return false;
            }
            cursor_ += w;
            auto [x, is_null] = fast::decNull(v);
            rec.sell_order_no = is_null ? 0 : x;
        }

        // bit5: Price (nullable)
        if (bits & (1ull << 5)) {
            uint64_t v; size_t w;
            if (fast::readFast(body_ + cursor_, len_ - cursor_, v, w)
                    != fast::Status::Ok) {
                spdlog::warn("[9-5803] Price: FAST 读取失败: cursor={}", cursor_);
                return false;
            }
            cursor_ += w;
            auto [x, is_null] = fast::decNull(v);
            rec.price_e3 = is_null ? 0 : int64_t(x);
        }

        // bit4: Qty (nullable)
        if (bits & (1ull << 4)) {
            uint64_t v; size_t w;
            if (fast::readFast(body_ + cursor_, len_ - cursor_, v, w)
                    != fast::Status::Ok) {
                spdlog::warn("[9-5803] Qty: FAST 读取失败: cursor={}", cursor_);
                return false;
            }
            cursor_ += w;
            auto [x, is_null] = fast::decNull(v);
            rec.qty_e3 = is_null ? 0 : int64_t(x);
        }

        // bit3: TradeMoney (nullable)
        if (bits & (1ull << 3)) {
            uint64_t v; size_t w;
            if (fast::readFast(body_ + cursor_, len_ - cursor_, v, w)
                    != fast::Status::Ok) {
                spdlog::warn("[9-5803] TradeMoney: FAST 读取失败: cursor={}", cursor_);
                return false;
            }
            cursor_ += w;
            auto [x, is_null] = fast::decNull(v);
            // 'A'/'D'/'C' 的 money 是 ×10^3，统一转为 ×10^5
            if (rec.action == 'T') {
                rec.money_e5 = is_null ? 0 : int64_t(x);
            } else {
                rec.money_e5 = is_null ? 0 : int64_t(x) * 100;
            }
        }

        // bit2: BSFlag / TradingPhaseCode
        if (bits & (1ull << 2)) {
            std::string s; size_t w;
            if (fast::readAscii(body_ + cursor_, len_ - cursor_, s, w)
                    != fast::Status::Ok) {
                spdlog::warn("[9-5803] BSFlag: 读取失败: cursor={}", cursor_);
                return false;
            }
            cursor_ += w;
            last_bs_flag_ = std::move(s);
        }
        rec.bs_flag = last_bs_flag_;

        rec.valid = true;
        return true;
    }

private:
    const uint8_t* body_;
    size_t         len_;
    size_t         cursor_ = 0;

    uint64_t    last_biz_index_ = 0;
    uint32_t    last_channel_   = 0;
    std::string last_sec_id_;
    uint32_t    last_tick_time_ = 0;
    char        last_action_    = 0;
    std::string last_bs_flag_;
};

}  // namespace sse95803

// ---- 输出 / 解帧 / 切流 ----

namespace {

constexpr uint32_t kMagic = 0x0004C453u;

// 跨 TCP 流去重: key = (channel << 32) | uint32_t(biz_index)
std::unordered_set<uint64_t> g_seen_biz;

void emitRecord(const sse95803::TickRecord& r, uint32_t outer_seq,
                const std::string& /*stream_tag*/, uint32_t frame_idx,
                size_t rec_idx) {
    uint64_t key = (uint64_t(r.channel) << 32) | uint32_t(r.biz_index);
    if (!g_seen_biz.insert(key).second) return;

    static bool header_done = false;
    if (!header_done) {
        header_done = true;
        std::cout << "BizIndex,Channel,SecID,TickTime,Action,"
                     "BuyOrderNO,SellOrderNO,Price,Qty,TradeMoney,BSFlag,PMAP,OuterSeq,FrameIdx,RecIdx\n";
    }

    std::cout << r.biz_index << ','
              << r.channel << ','
              << r.security_id << ','
              << fmtTickTime(r.tick_time) << ','
              << (r.action ? r.action : '?') << ','
              << r.buy_order_no << ','
              << r.sell_order_no << ','
              << fmtDecFixed(r.price_e3, 3) << ','
              << fmtDecFixed(r.qty_e3, 3) << ','
              << fmtDecFixed(r.money_e5, 5) << ','
              << (r.bs_flag.empty() ? "?" : r.bs_flag) << ','
              << "0x" << std::hex << std::setw(4) << std::setfill('0')
              << r.pmap_raw << std::dec << std::setfill(' ') << ','
              << outer_seq << ','
              << frame_idx << ','
              << rec_idx << '\n';
}

void onTick(const uint8_t* frame_head, size_t frame_len,
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
        emitRecord(rec, outer_seq, stream_tag, frame_idx, rec_idx++);
    }
}

// ---- 帧切分 ----

class Splitter {
public:
    std::string stream_tag;
    uint32_t    want_hi = 0;
    uint32_t    want_lo = 0;

    void feed(const uint8_t* data, size_t len) {
        buf_.insert(buf_.end(), data, data + len);
        drain();
    }

private:
    std::vector<uint8_t> buf_;
    uint32_t             frame_idx_ = 0;

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
        if (hi != want_hi || lo != want_lo) {
            spdlog::trace("[splitter] {} 帧类型 ({},{}) 不是期望的 ({},{})，跳过 length={}",
                          stream_tag, hi, lo, want_hi, want_lo, length);
            return;
        }
        ++frame_idx_;
        switch ((uint64_t(hi) << 32) | lo) {
            case (uint64_t(9) << 32) | 5803:
                onTick(f, length, stream_tag, frame_idx_);
                break;
            default:
                spdlog::warn("[splitter] {} 类型 ({},{}) 暂未实现", stream_tag, hi, lo);
                break;
        }
    }
};

struct Context {
    uint16_t filter_port = 5261;
    uint32_t want_hi     = 0;
    uint32_t want_lo     = 0;
    std::unordered_map<uint32_t, std::unique_ptr<Splitter>> streams;
};

}  // namespace
