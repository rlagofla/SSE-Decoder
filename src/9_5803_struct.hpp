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
#include <utility>
#include <vector>

namespace sse95803 {

// FAST stop-bit 变长无符号整数解码
inline std::pair<uint64_t, size_t> readFast(const uint8_t* p, size_t n) {
    uint64_t v = 0;
    for (size_t i = 0; i < n; ++i) {
        v = (v << 7) | uint64_t(p[i] & 0x7F);
        if (p[i] & 0x80) return {v, i + 1};
    }
    return {v, 0};
}

// 识别 6 字节 ASCII 证券代码
inline bool tryReadAsciiSecID(const uint8_t* p, size_t n, std::string& out) {
    if (n < 6) return false;
    for (size_t i = 0; i < 5; ++i) {
        uint8_t b = p[i];
        if (b < 0x30 || b > 0x39) return false;
    }
    uint8_t last = p[5];
    if (!(last & 0x80)) return false;
    uint8_t lc = last & 0x7F;
    if (lc < 0x30 || lc > 0x39) return false;
    out.assign(reinterpret_cast<const char*>(p), 5);
    out.push_back(char(lc));
    return true;
}

// FAST int → ASCII 字符串（用于 TradingPhaseCode）
inline std::string fastIntToAscii(uint64_t v) {
    if (v == 0) return "";
    std::string s;
    while (v > 0) {
        s += char(v & 0x7F);
        v >>= 7;
    }
    std::reverse(s.begin(), s.end());
    return s;
}

// FAST nullable 解码: V==0 → NULL(返回0), V>0 → V-1
inline std::pair<uint64_t, bool> decNull(uint64_t enc) {
    if (enc == 0) return {0, true};
    return {enc - 1, false};
}

// 读取 stop-bit 终止的 PMAP，最多支持 2 字节（14 bits）
// FAST 规范：payload 内 MSB 优先，即第 1 字节 bit6 → PMAP position 0，bit5 → position 1，…
// 第 2 字节（stop-bit 字节）bit6 → PMAP position 7，…，bit2 → position 11
inline bool readPmap(const uint8_t* p, size_t n, uint16_t& bits, size_t& consumed) {
    bits = 0;
    consumed = 0;
    for (size_t i = 0; i < n && i < 2; ++i) {
        uint8_t b = p[i];
        uint8_t payload = b & 0x7F;
        // 将 7-bit payload 按 MSB-first 映射到 PMAP positions i*7 .. i*7+6
        for (int j = 0; j < 7; ++j) {
            if ((payload >> (6 - j)) & 1)
                bits |= uint16_t(1u << (i * 7 + j));
        }
        consumed = i + 1;
        if (b & 0x80) return true;
    }
    return consumed > 0 && (p[consumed - 1] & 0x80);
}

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
        if (!readPmap(body_ + cursor_, len_ - cursor_, bits, pm_len)) return false;
        cursor_ += pm_len;
        rec.pmap_raw = bits;

        auto consume = [&](size_t n) -> bool {
            if (cursor_ + n > len_) return false;
            cursor_ += n;
            return true;
        };
        auto readFastHere = [&](uint64_t& out) -> bool {
            auto [v, w] = readFast(body_ + cursor_, len_ - cursor_);
            if (w == 0) return false;
            out = v; cursor_ += w;
            return true;
        };

        // bit 0: TID
        if (bits & (1 << 0)) {
            if (cursor_ + 2 > len_) return false;
            if (body_[cursor_] != 0x2d || body_[cursor_ + 1] != 0xab) return false;
            cursor_ += 2;
            rec.template_id = 5803;
        }

        // bit 1: BizIndex
        if (bits & (1 << 1)) {
            uint64_t v = 0;
            if (!readFastHere(v)) return false;
            last_biz_index_ = v;
        } else {
            ++last_biz_index_;
        }
        rec.biz_index = last_biz_index_;

        // bit 2: Channel
        if (bits & (1 << 2)) {
            uint64_t v = 0;
            if (!readFastHere(v)) return false;
            last_channel_ = uint32_t(v);
        }
        rec.channel = last_channel_;

        // bit 3: SecurityID
        if (bits & (1 << 3)) {
            std::string sid;
            if (!tryReadAsciiSecID(body_ + cursor_, len_ - cursor_, sid)) return false;
            cursor_ += 6;
            last_sec_id_ = sid;
        }
        rec.security_id = last_sec_id_;

        // bit 4: TickTime (nullable)
        if (bits & (1 << 4)) {
            uint64_t v = 0;
            if (!readFastHere(v)) return false;
            auto [t, is_null] = decNull(v);
            last_tick_time_ = is_null ? last_tick_time_ : uint32_t(t);
        }
        rec.tick_time = last_tick_time_;

        // bit 5: Action
        if (bits & (1 << 5)) {
            if (cursor_ >= len_) return false;
            uint8_t b = body_[cursor_++];
            char c = char(b & 0x7F);
            if (c != 'A' && c != 'D' && c != 'T' && c != 'C') {
                // 不是 trade action，可能是 Type='S' 记录
                // 退回，改走状态记录路径
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
            uint64_t v = 0;
            if (!readFastHere(v)) return false;
            auto [x, is_null] = decNull(v);
            rec.buy_order_no = is_null ? 0 : x;
        }

        // bit 7: SellOrderNO (nullable)
        if (bits & (1 << 7)) {
            uint64_t v = 0;
            if (!readFastHere(v)) return false;
            auto [x, is_null] = decNull(v);
            rec.sell_order_no = is_null ? 0 : x;
        }

        // bit 8: Price (nullable)
        if (bits & (1 << 8)) {
            uint64_t v = 0;
            if (!readFastHere(v)) return false;
            auto [x, is_null] = decNull(v);
            rec.price_e3 = is_null ? 0 : int64_t(x);
        }

        // bit 9: Qty (nullable)
        if (bits & (1 << 9)) {
            uint64_t v = 0;
            if (!readFastHere(v)) return false;
            auto [x, is_null] = decNull(v);
            rec.qty_e3 = is_null ? 0 : int64_t(x);
        }

        // bit 10: TradeMoney (nullable)
        if (bits & (1 << 10)) {
            uint64_t v = 0;
            if (!readFastHere(v)) return false;
            auto [x, is_null] = decNull(v);
            // 'A'/'D'/'C' 的 money 是 ×10^3，统一转为 ×10^5
            if (rec.action == 'T') {
                rec.money_e5 = is_null ? 0 : int64_t(x);
            } else {
                rec.money_e5 = is_null ? 0 : int64_t(x) * 100;
            }
        }

        // bit 11: BSFlag
        if (bits & (1 << 11)) {
            if (cursor_ >= len_) return false;
            uint8_t b = body_[cursor_++];
            char c = char(b & 0x7F);
            last_bs_flag_ = c;
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
            uint64_t v = 0;
            auto [val, w] = readFast(body_ + cursor_, len_ - cursor_);
            if (w == 0) return false;
            cursor_ += w;
            // 不更新 last_tick_time_，状态记录时间独立
            rec.tick_time = uint32_t(val);
        }

        // bit 11: TradingPhaseCode（FAST ASCII 变长整数）
        if (bits & (1 << 11)) {
            uint64_t v = 0;
            auto [val, w] = readFast(body_ + cursor_, len_ - cursor_);
            if (w == 0) return false;
            cursor_ += w;
            // 把 FAST int 反向提取为 ASCII
            std::string phase = fastIntToAscii(val);
            rec.security_id = last_sec_id_;
            // 把 phase 存在 bs_flag 位置没有合适字段，用 action='S' 标记
            rec.action = 'S';
            // 把 trading phase 编码进 buy_order_no 当临时存储（供 engine 读取）
            // 实际上 engine 会检查 is_status_record 并走单独的输出路径
            (void)phase;
        }

        return true;
    }
};

// ---- Type='S' 状态记录 emit 支持 ----
// 判断一个已解析为 is_status_record 的 TickRecord 并重新解析状态字段
// 注：由于状态记录的字段语义和 trade 不同，engine 需要重新解析对应的 raw bytes。
// 简化做法：engine 直接检查 is_status_record，跳过 trade 输出，走状态输出路径。

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
