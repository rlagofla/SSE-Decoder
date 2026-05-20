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
    uint64_t    pmap_raw      = 0;
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
    Parser(const uint8_t* body, size_t len): fr_(body, len) {}

    bool next(Msg& rec) {
        rec = Msg{};
        if (fr_.empty()) return false;

        // pmap
        if (!fr_.readNum<utils::FastOp::None>(rec.pmap_raw)) return false;
        fr_.setPmap(rec.pmap_raw);

        // bit13: TID
        if (!fr_.readNum<utils::FastOp::Copy>(13, last_template_id_, rec.template_id)) return false;
        if (rec.template_id != 5803) {
            spdlog::warn("[ua5803] TID 异常: {}", rec.template_id);
            return false;
        }

        if (!fr_.readNum<utils::FastOp::Inc>(12, last_biz_index_, rec.biz_index)) return false;
        if (!fr_.readNum<utils::FastOp::Copy>(11, last_channel_, rec.channel)) return false;

        if (!fr_.readString<utils::FastOp::Copy>(10, last_sec_id_, rec.security_id)) return false;
        if (rec.security_id.size() != 6) return false;

        if (!fr_.readNum<utils::FastOp::CopyNull>(9, last_tick_time_, rec.tick_time)) return false;

        std::string action_str;
        if (!fr_.readString<utils::FastOp::Copy>(8, last_action_str_, action_str)) return false;
        if (action_str.size() != 1) return false;
        rec.action = action_str[0];

        if (!fr_.readNum<utils::FastOp::DefaultNull>(7, rec.buy_order_no)) return false;
        if (!fr_.readNum<utils::FastOp::DefaultNull>(6, rec.sell_order_no)) return false;
        if (!fr_.readNum<utils::FastOp::DefaultNull>(5, rec.price_e3)) return false;
        if (!fr_.readNum<utils::FastOp::DefaultNull>(4, rec.qty_e3)) return false;
        if (!fr_.readNum<utils::FastOp::DefaultNull>(3, rec.money_e5)) return false;

        // 'T' 的 money 单位已是 ×10^5；'A'/'D'/'C' 是 ×10^3，统一乘 100 转为 ×10^5
        if (rec.action != 'T') rec.money_e5 *= 100;

        if (!fr_.readString<utils::FastOp::Copy>(2, last_bs_flag_, rec.bs_flag)) return false;

        // 该读的都读完了，现在是逻辑判断阶段
        // 非状态记录的 BSFlag 只能是 B/S/N
        if (rec.action != 'S') {
            if (rec.bs_flag != "B" && rec.bs_flag != "S" && rec.bs_flag != "N") {
                spdlog::warn("[ua5803] BSFlag 非法: {}", rec.bs_flag);
                return false;
            }
        }

        // 成交记录：price_e3 × qty_e3 应等于 money_e5 × 10
        if (rec.action == 'T' && rec.price_e3 * rec.qty_e3 != rec.money_e5 * 10) {
            spdlog::warn("[ua5803] price×qty≠money: price={} qty={} money={}", rec.price_e3, rec.qty_e3, rec.money_e5);
            return false;
        }

        rec.valid = true;
        return true;
    }

private:
    utils::FastReader fr_;

    uint64_t    last_template_id_ = 0;
    uint64_t    last_biz_index_ = 0;
    uint32_t    last_channel_   = 0;
    std::string last_sec_id_;
    uint32_t    last_tick_time_ = 0;
    std::string last_action_str_;
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
        out << "BizIndex,Channel,SecurityID,TickTime,Type,BuyOrderNO,SellOrderNO,Price,Qty,TradeMoney,TickBSFlag,OuterSeq,FrameIdx,RecIdx\n";
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
        << outer_seq << ','
        << frame_idx << ','
        << rec_idx << '\n';
}

}  // namespace ua5803
