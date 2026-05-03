#pragma once
// 9_5803_struct.hpp — 上交所 (9, 5803) 通道逐笔行情 PMAP 驱动顺序解码
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
//
// FAST nullable: 编码值 V=0 → NULL(缺省/0), V>0 → 业务值 = V-1
// 注: 所谓 "ExtCode" 根本不存在，它是下一条记录 PMAP 的第一字节。

#include <cstddef>
#include <cstdint>
#include <string>

#include <spdlog/spdlog.h>

#include "fast_utils.hpp"

namespace sse95803 {

// 一条解码后的记录（业务字段直接命名；action='S' 时为状态记录，bs_flag 含交易阶段码）
struct TickRecord {
    uint16_t    pmap_raw     = 0;  // 14-bit PMAP（调试，readFast 原始值截断）
    uint64_t    template_id  = 0;  // 期望 5803

    uint64_t    biz_index    = 0;
    uint32_t    channel      = 0;
    std::string security_id;
    uint32_t    tick_time    = 0;  // HHMMSSXX，已做 nullable -1
    char        action       = 0;  // 'A'/'D'/'T'/'C'/'S'
    uint64_t    buy_order_no  = 0;
    uint64_t    sell_order_no = 0;
    int64_t     price_e3     = 0;  // Price × 1000
    int64_t     qty_e3       = 0;  // Qty × 1000
    int64_t     money_e5     = 0;  // TradeMoney × 10^5
    std::string bs_flag;           // 'B'/'S'/'N' 或状态记录时 "SUSP"/"OCALL"/"START"

    bool valid = false;
};

// PMAP 驱动的顺序解析器
class TickStreamParser {
public:
    TickStreamParser(const uint8_t* body, size_t len)
        : body_(body), len_(len) {}

    // 读取下一条记录，返回 false 表示 body 耗尽或解析失败
    bool next(TickRecord& rec) {
        rec = TickRecord{};

        if (cursor_ >= len_) return false;

        // 读 PMAP（与 readFast 共用 stop-bit 机制；TID 在返回值 bit13）
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
                spdlog::warn("[9-5803] BuyOrderNO: FAST 读取失败: cursor={}", cursor_);
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

        // bit2: BSFlag / TradingPhaseCode (ASCII，单字节或多字节)
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

// ---- 格式化辅助 ----

inline std::string fmtDecFixed(int64_t v, int digits) {
    if (digits <= 0) {
        char b[32];
        std::snprintf(b, sizeof(b), "%lld", (long long)v);
        return b;
    }
    int64_t scale = 1;
    for (int i = 0; i < digits; ++i) scale *= 10;
    int64_t hi = v / scale, lo = v % scale;
    if (lo < 0) lo = -lo;
    char fmt[32], buf[64];
    std::snprintf(fmt, sizeof(fmt), "%%lld.%%0%dlld", digits);
    std::snprintf(buf, sizeof(buf), fmt, (long long)hi, (long long)lo);
    return buf;
}

inline std::string fmtTickTime(uint32_t t) {
    uint32_t xx = t % 100;
    uint32_t ss = (t / 100) % 100;
    uint32_t mm = (t / 10000) % 100;
    uint32_t hh = t / 1000000;
    char b[16];
    std::snprintf(b, sizeof(b), "%02u:%02u:%02u.%02u", hh, mm, ss, xx);
    return b;
}

}  // namespace sse95803
