#pragma once
// 9_5803_struct.hpp — 上交所 (9, 5803) 通道逐笔行情 PMAP 驱动顺序解码
//
// PMAP 位布局（14 bits，高 7 位来自第 1 字节，低 7 位来自 stop-bit 字节）:
//   bit 0 : TID          (1 = 读 2d ab)
//   bit 1 : BizIndex     (0 = last+1,  1 = 显式 FAST u64)
//   bit 2 : Channel      (0 = copy,    1 = 显式 FAST u32)
//   bit 3 : SecurityID   (0 = copy,    1 = 显式 6B ASCII)
//   bit 4 : TickTime     (0 = copy,    1 = 显式 FAST u32 nullable)
//   bit 5 : Action       (0 = copy,    1 = 显式 FAST char)
//   bit 6 : BuyOrderNO   (0 = 0,       1 = 显式 FAST u64 nullable)
//   bit 7 : SellOrderNO  (0 = 0,       1 = 显式 FAST u64 nullable)
//   bit 8 : Price        (0 = 0,       1 = 显式 FAST u32 nullable)
//   bit 9 : Qty          (0 = 0,       1 = 显式 FAST u64 nullable)
//   bit 10: TradeMoney   (0 = 0,       1 = 显式 FAST u64 nullable)
//   bit 11: BSFlag       (0 = copy,    1 = 显式 FAST char)
//
// FAST nullable: 编码值 V=0 → NULL(缺省/0), V>0 → 业务值 = V-1
// 注: 所谓 "ExtCode" 根本不存在，它是下一条记录 PMAP 的第一字节。

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <spdlog/spdlog.h>

#include "fast_utils.hpp"

namespace sse95803 {

// 一条解码后的记录（业务字段直接命名，无需二次转换）
struct TickRecord {
    uint16_t    pmap_raw     = 0;  // 14-bit PMAP payload（调试）
    uint64_t    template_id  = 0;  // 期望 5803

    uint64_t    biz_index    = 0;
    uint32_t    channel      = 0;
    std::string security_id;
    uint32_t    tick_time    = 0;  // HHMMSSXX，已做 nullable -1
    char        action       = 0;  // 'A'/'D'/'T'/'C'
    uint64_t    buy_order_no  = 0;
    uint64_t    sell_order_no = 0;
    int64_t     price_e3     = 0;  // Price × 1000
    int64_t     qty_e3       = 0;  // Qty × 1000
    int64_t     money_e5     = 0;  // TradeMoney × 10^5
    char        bs_flag      = 0;  // 'B'/'S'/'N'

    bool is_status_record = false;
    bool valid            = false;
};

// Type='S' 状态记录
struct StatusRecord {
    bool        valid             = false;
    std::string security_id;
    bool        has_transact_time = false;
    uint32_t    transact_time     = 0;
    std::string trading_phase;           // "SUSP"/"OCALL"/"START"
    std::vector<uint64_t> prefix_ints;   // 7e84 帧首记录的 SeqA/SeqB
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

        // 读 PMAP
        uint16_t bits = 0;
        size_t   pm_len = 0;
        if (fast::readPmap(body_ + cursor_, len_ - cursor_, bits, pm_len)
                != fast::Status::Ok) {
            spdlog::warn("[9-5803] PMAP 读取失败: cursor={} remaining={}",
                         cursor_, len_ - cursor_);
            return false;
        }
        cursor_ += pm_len;
        rec.pmap_raw = bits;

        // bit 0: TID
        if (bits & (1 << 0)) {
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

        // bit 1: BizIndex
        if (bits & (1 << 1)) {
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

        // bit 2: Channel
        if (bits & (1 << 2)) {
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

        // bit 3: SecurityID
        if (bits & (1 << 3)) {
            std::string sid;
            auto st = fast::readAsciiSecID(body_ + cursor_, len_ - cursor_, sid);
            if (st == fast::Status::InsufficientBytes) {
                spdlog::warn("[9-5803] SecurityID: buffer 不足 6 字节: cursor={} remaining={}",
                             cursor_, len_ - cursor_);
                return false;
            }
            if (st == fast::Status::InvalidEncoding) {
                spdlog::warn("[9-5803] SecurityID: 非 ASCII 数字或 stop-bit 缺失: "
                             "cursor={} bytes={:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
                             cursor_,
                             body_[cursor_+0], body_[cursor_+1], body_[cursor_+2],
                             body_[cursor_+3], body_[cursor_+4], body_[cursor_+5]);
                return false;
            }
            cursor_ += 6;
            last_sec_id_ = sid;
        }
        rec.security_id = last_sec_id_;

        // bit 4: TickTime (nullable)
        if (bits & (1 << 4)) {
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

        // bit 5: Action
        if (bits & (1 << 5)) {
            if (cursor_ >= len_) {
                spdlog::warn("[9-5803] Action: buffer 已耗尽: cursor={}", cursor_);
                return false;
            }
            uint8_t b = body_[cursor_++];
            char c = char(b & 0x7F);
            if (c != 'A' && c != 'D' && c != 'T' && c != 'C') {
                // 不是 trade action，退回，改走状态记录路径
                --cursor_;
                return parseStatusRecord(rec, bits);
            }
            last_action_ = c;
        }
        rec.action = last_action_;

        // 检测 Type='S'：bit5=0 且 bits 6-10 都为 0 且 bit11=1
        bool no_middle = !(bits & 0x07C0);  // bits 6-10 全 0
        bool has_bs    =  (bits & (1 << 11));
        if (!rec.action && no_middle && has_bs) {
            return parseStatusRecord(rec, bits);
        }

        // bit 6: BuyOrderNO (nullable)
        if (bits & (1 << 6)) {
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

        // bit 7: SellOrderNO (nullable)
        if (bits & (1 << 7)) {
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

        // bit 8: Price (nullable)
        if (bits & (1 << 8)) {
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

        // bit 9: Qty (nullable)
        if (bits & (1 << 9)) {
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

        // bit 10: TradeMoney (nullable)
        if (bits & (1 << 10)) {
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

        // bit 11: BSFlag
        if (bits & (1 << 11)) {
            if (cursor_ >= len_) {
                spdlog::warn("[9-5803] BSFlag: buffer 已耗尽: cursor={}", cursor_);
                return false;
            }
            uint8_t b = body_[cursor_++];
            last_bs_flag_ = char(b & 0x7F);
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
    char        last_bs_flag_   = 0;

    // Type='S' 状态记录解析（PMAP `48 84` / `4c 84` / `7e 84`）
    bool parseStatusRecord(TickRecord& rec, uint16_t bits) {
        rec.is_status_record = true;
        rec.valid            = true;

        // bit 4: TransactTime（状态记录中有时出现）
        if (bits & (1 << 4)) {
            uint64_t v; size_t w;
            if (fast::readFast(body_ + cursor_, len_ - cursor_, v, w)
                    != fast::Status::Ok) {
                spdlog::warn("[9-5803][stat] TransactTime: FAST 读取失败: cursor={}", cursor_);
                return false;
            }
            cursor_ += w;
            rec.tick_time = uint32_t(v);
        }

        // bit 11: TradingPhaseCode（FAST ASCII 变长整数）
        if (bits & (1 << 11)) {
            uint64_t v; size_t w;
            if (fast::readFast(body_ + cursor_, len_ - cursor_, v, w)
                    != fast::Status::Ok) {
                spdlog::warn("[9-5803][stat] TradingPhaseCode: FAST 读取失败: cursor={}", cursor_);
                return false;
            }
            cursor_ += w;
            (void)fast::fastIntToAscii(v);  // engine 通过 is_status_record 走独立输出路径
            rec.security_id = last_sec_id_;
            rec.action = 'S';
        }

        return true;
    }
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
