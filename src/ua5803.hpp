#pragma once
// ua5803.hpp — MessageType UA5803 逐笔行情（FAST 编码）

#include <cstdint>
#include <iomanip>
#include <ostream>
#include <string>
#include <unordered_set>

#include <spdlog/spdlog.h>

#include "utils.hpp"

namespace ua5803 {

// 一条逐笔记录
struct Msg {
    uint16_t    pmap_raw      = 0;
    uint64_t    template_id   = 0;   // 期望 5803
    uint64_t    biz_index     = 0;
    uint32_t    channel       = 0;
    std::string security_id;
    uint32_t    tick_time     = 0;   // HHMMSSXX，已做 nullable
    char        action        = 0;   // 'A'/'D'/'T'/'C'/'S'
    uint64_t    buy_order_no  = 0;
    uint64_t    sell_order_no = 0;
    int64_t     price_e3      = 0;   // Price × 1000
    int64_t     qty_e3        = 0;   // Qty × 1000
    int64_t     money_e5      = 0;   // TradeMoney × 10^5
    std::string bs_flag;             // 'B'/'S'/'N' 或状态记录时 "SUSP"/"OCALL"/"START"
    bool        valid         = false;
};

// PMAP 位布局（readFast 读出的 14-bit 值）:
//   bit13: TID          (1 = 读 2d ab)
//   bit12: BizIndex     (0 = last+1,  1 = 显式 FAST u64)
//   bit11: Channel      (0 = copy,    1 = 显式 FAST u32)
//   bit10: SecurityID   (0 = copy,    1 = 显式 ASCII)
//   bit 9: TickTime     (0 = copy,    1 = 显式 FAST u32 nullable)
//   bit 8: Action       (0 = copy,    1 = 显式 ASCII char)
//   bit 7: BuyOrderNO   (0 = 0,       1 = 显式 FAST u64 nullable)
//   bit 6: SellOrderNO  (0 = 0,       1 = 显式 FAST u64 nullable)
//   bit 5: Price        (0 = 0,       1 = 显式 FAST u32 nullable)
//   bit 4: Qty          (0 = 0,       1 = 显式 FAST u64 nullable)
//   bit 3: TradeMoney   (0 = 0,       1 = 显式 FAST u64 nullable)
//   bit 2: BSFlag       (0 = copy,    1 = 显式 ASCII)

class Parser {
public:
    Parser(const uint8_t* body, size_t len): body_(body), len_(len) {}

    bool next(Msg& rec) {
        rec = Msg{};

        if (cursor_ >= len_) return false;

        uint64_t bits = 0;
        size_t   pm_len = 0;
        if (utils::readFast(body_ + cursor_, len_ - cursor_, bits, pm_len)
                != utils::Status::Ok) {
            spdlog::warn("[ua5803] PMAP 读取失败: cursor={} remaining={}",
                         cursor_, len_ - cursor_);
            return false;
        }
        cursor_ += pm_len;
        rec.pmap_raw = uint16_t(bits);
        if (pm_len != 2) {
            spdlog::warn("[ua5803] PMAP 长度异常: pm_len={} cursor={}", pm_len, cursor_);
            return false;
        }

        // bit13: TID
        if (bits & (1ull << 13)) {
            if (cursor_ + 2 > len_) {
                spdlog::warn("[ua5803] TID: buffer 不足 2 字节: cursor={} len={}",
                             cursor_, len_);
                return false;
            }
            if (body_[cursor_] != 0x2d || body_[cursor_ + 1] != 0xab) {
                spdlog::warn("[ua5803] TID: 期望 2d ab, 实际 {:02x} {:02x}: cursor={}",
                             body_[cursor_], body_[cursor_ + 1], cursor_);
                return false;
            }
            cursor_ += 2;
            rec.template_id = 5803;
        }

        // bit12: BizIndex
        if (bits & (1ull << 12)) {
            uint64_t v; size_t w;
            if (utils::readFast(body_ + cursor_, len_ - cursor_, v, w) != utils::Status::Ok) {
                spdlog::warn("[ua5803] BizIndex: FAST 读取失败: cursor={}", cursor_);
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
            if (utils::readFast(body_ + cursor_, len_ - cursor_, v, w) != utils::Status::Ok) {
                spdlog::warn("[ua5803] Channel: FAST 读取失败: cursor={}", cursor_);
                return false;
            }
            cursor_ += w;
            last_channel_ = uint32_t(v);
        }
        rec.channel = last_channel_;

        // bit10: SecurityID
        if (bits & (1ull << 10)) {
            std::string sid; size_t w;
            if (utils::readAscii(body_ + cursor_, len_ - cursor_, sid, w) != utils::Status::Ok) {
                spdlog::warn("[ua5803] SecurityID: 读取失败: cursor={} remaining={}",
                             cursor_, len_ - cursor_);
                return false;
            }
            cursor_ += w;
            if (sid.size() != 6) {
                spdlog::warn("[ua5803] SecurityID 长度异常: len={} val={} cursor={}",
                             sid.size(), sid, cursor_);
                return false;
            }
            last_sec_id_ = std::move(sid);
        }
        rec.security_id = last_sec_id_;

        // bit9: TickTime (nullable)
        if (bits & (1ull << 9)) {
            uint64_t v; size_t w;
            if (utils::readFast(body_ + cursor_, len_ - cursor_, v, w) != utils::Status::Ok) {
                spdlog::warn("[ua5803] TickTime: FAST 读取失败: cursor={}", cursor_);
                return false;
            }
            cursor_ += w;
            auto [t, is_null] = utils::decNull(v);
            last_tick_time_ = is_null ? last_tick_time_ : uint32_t(t);
        }
        rec.tick_time = last_tick_time_;

        // bit8: Action ('A'/'D'/'T'/'C'/'S')
        if (bits & (1ull << 8)) {
            std::string a; size_t w;
            if (utils::readAscii(body_ + cursor_, len_ - cursor_, a, w) != utils::Status::Ok) {
                spdlog::warn("[ua5803] Action: 读取失败: cursor={}", cursor_);
                return false;
            }
            cursor_ += w;
            if (a.size() != 1) {
                spdlog::warn("[ua5803] Action 长度不是 1: val={} cursor={}", a, cursor_);
                return false;
            }
            last_action_ = a[0];
        }
        rec.action = last_action_;

        // bit7: BuyOrderNO (nullable)
        if (bits & (1ull << 7)) {
            uint64_t v; size_t w;
            if (utils::readFast(body_ + cursor_, len_ - cursor_, v, w) != utils::Status::Ok) {
                spdlog::warn("[ua5803] BuyOrderNO: FAST 读取失败: cursor={}", cursor_);
                return false;
            }
            cursor_ += w;
            auto [x, is_null] = utils::decNull(v);
            rec.buy_order_no = is_null ? 0 : x;
        }

        // bit6: SellOrderNO (nullable)
        if (bits & (1ull << 6)) {
            uint64_t v; size_t w;
            if (utils::readFast(body_ + cursor_, len_ - cursor_, v, w) != utils::Status::Ok) {
                spdlog::warn("[ua5803] SellOrderNO: FAST 读取失败: cursor={}", cursor_);
                return false;
            }
            cursor_ += w;
            auto [x, is_null] = utils::decNull(v);
            rec.sell_order_no = is_null ? 0 : x;
        }

        // bit5: Price (nullable)
        if (bits & (1ull << 5)) {
            uint64_t v; size_t w;
            if (utils::readFast(body_ + cursor_, len_ - cursor_, v, w) != utils::Status::Ok) {
                spdlog::warn("[ua5803] Price: FAST 读取失败: cursor={}", cursor_);
                return false;
            }
            cursor_ += w;
            auto [x, is_null] = utils::decNull(v);
            rec.price_e3 = is_null ? 0 : int64_t(x);
        }

        // bit4: Qty (nullable)
        if (bits & (1ull << 4)) {
            uint64_t v; size_t w;
            if (utils::readFast(body_ + cursor_, len_ - cursor_, v, w) != utils::Status::Ok) {
                spdlog::warn("[ua5803] Qty: FAST 读取失败: cursor={}", cursor_);
                return false;
            }
            cursor_ += w;
            auto [x, is_null] = utils::decNull(v);
            rec.qty_e3 = is_null ? 0 : int64_t(x);
        }

        // bit3: TradeMoney (nullable)
        // 'T' 的 money 单位已是 ×10^5；'A'/'D'/'C' 是 ×10^3，统一乘 100 转为 ×10^5
        if (bits & (1ull << 3)) {
            uint64_t v; size_t w;
            if (utils::readFast(body_ + cursor_, len_ - cursor_, v, w) != utils::Status::Ok) {
                spdlog::warn("[ua5803] TradeMoney: FAST 读取失败: cursor={}", cursor_);
                return false;
            }
            cursor_ += w;
            auto [x, is_null] = utils::decNull(v);
            rec.money_e5 = is_null ? 0 : (rec.action == 'T' ? int64_t(x) : int64_t(x) * 100);
        }

        // bit2: BSFlag / TradingPhaseCode
        if (bits & (1ull << 2)) {
            std::string s; size_t w;
            if (utils::readAscii(body_ + cursor_, len_ - cursor_, s, w) != utils::Status::Ok) {
                spdlog::warn("[ua5803] BSFlag: 读取失败: cursor={}", cursor_);
                return false;
            }
            cursor_ += w;
            last_bs_flag_ = std::move(s);
        }
        rec.bs_flag = last_bs_flag_;

        // 非状态记录的 BSFlag 只能是 B/S/N
        if (rec.action != 'S') {
            if (rec.bs_flag != "B" && rec.bs_flag != "S" && rec.bs_flag != "N") {
                spdlog::warn("[ua5803] BSFlag 非法: val={} action={} biz={}",
                             rec.bs_flag, rec.action, rec.biz_index);
                return false;
            }
        }

        // 成交记录：price_e3 × qty_e3 应等于 money_e5 × 10
        if (rec.action == 'T' && rec.price_e3 * rec.qty_e3 != rec.money_e5 * 10) {
            spdlog::warn("[ua5803] price×qty≠money: price={} qty={} money={} biz={}",
                         rec.price_e3, rec.qty_e3, rec.money_e5, rec.biz_index);
            return false;
        }

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

// 跨 TCP 流去重: key = (channel << 32) | uint32_t(biz_index)
inline std::unordered_set<uint64_t> g_seen;

inline void emit(const Msg& r, uint32_t outer_seq, uint32_t frame_idx, size_t rec_idx, bool dedup, std::ostream& out) {
    if (dedup) {
        uint64_t key = (uint64_t(r.channel) << 32) | uint32_t(r.biz_index);
        if (!g_seen.insert(key).second) return;
    }

    static bool header_done = false;
    if (!header_done) {
        header_done = true;
        out << "BizIndex,Channel,SecID,TickTime,Action,"
               "BuyOrderNO,SellOrderNO,Price,Qty,TradeMoney,BSFlag,"
               "PMAP,OuterSeq,FrameIdx,RecIdx\n";
    }

    out << r.biz_index << ','
        << r.channel << ','
        << r.security_id << ','
        << utils::fmtTickTime(r.tick_time) << ','
        << (r.action ? r.action : '?') << ','
        << r.buy_order_no << ','
        << r.sell_order_no << ','
        << utils::fmtDecFixed(r.price_e3, 3) << ','
        << utils::fmtDecFixed(r.qty_e3, 3) << ','
        << utils::fmtDecFixed(r.money_e5, 5) << ','
        << (r.bs_flag.empty() ? "?" : r.bs_flag) << ','
        << "0x" << std::hex << std::setw(4) << std::setfill('0')
        << r.pmap_raw << std::dec << std::setfill(' ') << ','
        << outer_seq << ','
        << frame_idx << ','
        << rec_idx << '\n';
}

}  // namespace ua5803
