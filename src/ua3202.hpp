#pragma once
// ua3202.hpp — MessageType UA3202 L2 全量快照（FAST 编码）
//
// PMAP 位布局（readFast 读出的 49-bit 值，bit48 为第一个字段）:
//   bit48: TID                        bit41: LastPx
//   bit47: TickTime                   bit40: ClosePx
//   bit46: DataStatus                 bit39: InstrumentStatus
//   [SecurityID: none，始终存在]      bit38: TradingPhaseCode
//   [ImageStatus: none，始终存在]     bit37: NumTrades
//   bit45: PreClosePx                 bit36: TotalVolumeTrade
//   bit44: OpenPx                     bit35: TotalValueTrade
//   bit43: HighPx                     bit34: TotalBidQty
//   bit42: LowPx                      bit33: WeightedAvgBidPx
//
//   bit32: AltWeightedAvgBidPx        bit19: WarLowerPx
//   bit31: TotalOfferQty              bit18: WarUpperPx
//   bit30: WeightedAvgOfferPx         bit17: WithdrawBuyNumber
//   bit29: AltWeightedAvgOfferPx      bit16: WithdrawBuyAmount
//   bit28: IOPV                       bit15: WithdrawBuyMoney
//   bit27: ETFBuyNumber               bit14: WithdrawSellNumber
//   bit26: ETFBuyAmount               bit13: WithdrawSellAmount
//   bit25: ETFBuyMoney                bit12: WithdrawSellMoney
//   bit24: ETFSellNumber              bit11: TotalBidNumber
//   bit23: ETFSellAmount              bit10: TotalOfferNumber
//   bit22: ETFSellMoney               bit9:  BidTradeMaxDuration
//   bit21: YieldToMaturity            bit8:  OfferTradeMaxDuration
//   bit20: TotalWarrantExecQty        bit7:  NumBidOrders
//                                     bit6:  NumOfferOrders
//   [NoBidLevel: none，始终存在，引发档位循环]
//   [NoOfferLevel: none，始终存在，引发档位循环]
//
// 档位子 PMAP（1 字节，bit6 起）:
//   bit6: PriceLevelOperator（废用，不应出现）
//   bit5: Price    bit4: OrderQty    bit3: NumOrders
//   [Orders: none，始终存在，引发逐笔循环]
//   逐笔子 PMAP（1 字节）:
//     bit6: OrderQueueOperator（废用）
//     bit5: OrderQueueOperatorEntryID（废用）
//     bit4: OrderQty
//
// 注：bit 位置根据 FAST stop-bit 编码规则推算，需对照真实报文验证后修正。

#include <cstdint>
#include <iomanip>
#include <ostream>
#include <string>
#include <unordered_set>
#include <vector>

#include <spdlog/spdlog.h>

#include "utils.hpp"

namespace ua3202 {

struct PriceLevel {
    int64_t              price      = 0;
    int64_t              qty        = 0;
    uint32_t             num_orders = 0;
    std::vector<int64_t> orders;
};

struct Msg {
    uint64_t    pmap_raw              = 0;
    uint64_t    template_id           = 0;
    uint32_t    tick_time             = 0;
    uint32_t    data_status           = 0;
    std::string security_id;
    std::string image_status;
    int64_t     pre_close_px          = 0;
    int64_t     open_px               = 0;
    int64_t     high_px               = 0;
    int64_t     low_px                = 0;
    int64_t     last_px               = 0;
    int64_t     close_px              = 0;
    std::string instrument_status;
    std::string trading_phase_code;
    uint64_t    num_trades            = 0;
    int64_t     total_volume          = 0;
    int64_t     total_value           = 0;
    int64_t     total_bid_qty         = 0;
    int64_t     wavg_bid_px           = 0;
    int64_t     alt_wavg_bid_px       = 0;
    int64_t     total_offer_qty       = 0;
    int64_t     wavg_offer_px         = 0;
    int64_t     alt_wavg_offer_px     = 0;
    int64_t     iopv                  = 0;
    uint64_t    etf_buy_num           = 0;
    int64_t     etf_buy_amount        = 0;
    int64_t     etf_buy_money         = 0;
    uint64_t    etf_sell_num          = 0;
    int64_t     etf_sell_amount       = 0;
    int64_t     etf_sell_money        = 0;
    int64_t     ytm                   = 0;
    int64_t     total_warrant_exec_qty = 0;
    int64_t     war_lower_px          = 0;
    int64_t     war_upper_px          = 0;
    uint64_t    withdraw_buy_num      = 0;
    int64_t     withdraw_buy_amount   = 0;
    int64_t     withdraw_buy_money    = 0;
    uint64_t    withdraw_sell_num     = 0;
    int64_t     withdraw_sell_amount  = 0;
    int64_t     withdraw_sell_money   = 0;
    uint64_t    total_bid_num         = 0;
    uint64_t    total_offer_num       = 0;
    uint32_t    bid_trade_max_dur     = 0;
    uint32_t    offer_trade_max_dur   = 0;
    uint32_t    num_bid_orders        = 0;
    uint32_t    num_offer_orders      = 0;
    std::vector<PriceLevel> bid_levels;
    std::vector<PriceLevel> offer_levels;
    bool valid = false;
};

class Parser {
public:
    Parser(const uint8_t* body, size_t len) : body_(body), len_(len) {}

    bool next(Msg& rec) {
        rec = Msg{};
        if (cursor_ >= len_) return false;

        uint64_t bits = 0;
        size_t   pm_len = 0;
        if (utils::readFast(body_ + cursor_, len_ - cursor_, bits, pm_len) != utils::Status::Ok) {
            spdlog::warn("[ua3202] PMAP 读取失败: cursor={} remaining={}", cursor_, len_ - cursor_);
            return false;
        }
        cursor_ += pm_len;
        rec.pmap_raw = bits;
        if (pm_len != 7) {
            spdlog::warn("[ua3202] PMAP 长度异常: pm_len={} cursor={}", pm_len, cursor_);
            return false;
        }

        // 读 nullable FAST 整数，pmap bit 为 0 则保持 last_val 不变
        auto rfn = [&](int bit, auto& last_val) -> bool {
            if (!(bits & (1ull << bit))) return true;
            uint64_t v; size_t w;
            if (utils::readFast(body_ + cursor_, len_ - cursor_, v, w) != utils::Status::Ok) {
                spdlog::warn("[ua3202] bit{} 读取失败: cursor={}", bit, cursor_);
                return false;
            }
            cursor_ += w;
            auto [x, is_null] = utils::decNull(v);
            if (!is_null) last_val = decltype(last_val)(x);
            return true;
        };
        // 读 ASCII 字符串字段
        auto rfa = [&](int bit, std::string& last_val) -> bool {
            if (!(bits & (1ull << bit))) return true;
            std::string s; size_t w;
            if (utils::readAscii(body_ + cursor_, len_ - cursor_, s, w) != utils::Status::Ok) {
                spdlog::warn("[ua3202] bit{} ASCII 读取失败: cursor={}", bit, cursor_);
                return false;
            }
            cursor_ += w;
            last_val = std::move(s);
            return true;
        };

        // bit48: TID（期望 0x19 0x82 = 3202）
        if (bits & (1ull << 48)) {
            if (cursor_ + 2 > len_) {
                spdlog::warn("[ua3202] TID: buffer 不足: cursor={} len={}", cursor_, len_);
                return false;
            }
            if (body_[cursor_] != 0x19 || body_[cursor_ + 1] != 0x82) {
                spdlog::warn("[ua3202] TID: 期望 19 82, 实际 {:02x} {:02x}: cursor={}", body_[cursor_], body_[cursor_ + 1], cursor_);
                return false;
            }
            cursor_ += 2;
            rec.template_id = 3202;
        }

        if (!rfn(47, last_tick_time_)) return false; rec.tick_time = last_tick_time_;
        if (!rfn(46, last_data_status_)) return false; rec.data_status = last_data_status_;

        // SecurityID: none 类型，始终存在
        { size_t w; if (utils::readAscii(body_ + cursor_, len_ - cursor_, last_sec_id_, w) != utils::Status::Ok) { spdlog::warn("[ua3202] SecurityID 读取失败: cursor={}", cursor_); return false; } cursor_ += w; }
        rec.security_id = last_sec_id_;

        // ImageStatus: none 类型，始终存在
        { size_t w; if (utils::readAscii(body_ + cursor_, len_ - cursor_, last_image_status_, w) != utils::Status::Ok) { spdlog::warn("[ua3202] ImageStatus 读取失败: cursor={}", cursor_); return false; } cursor_ += w; }
        rec.image_status = last_image_status_;

        if (!rfn(45, last_pre_close_px_)) return false; rec.pre_close_px = last_pre_close_px_;
        if (!rfn(44, last_open_px_)) return false; rec.open_px = last_open_px_;
        if (!rfn(43, last_high_px_)) return false; rec.high_px = last_high_px_;
        if (!rfn(42, last_low_px_)) return false; rec.low_px = last_low_px_;
        if (!rfn(41, last_last_px_)) return false; rec.last_px = last_last_px_;
        if (!rfn(40, last_close_px_)) return false; rec.close_px = last_close_px_;
        if (!rfa(39, last_instr_status_)) return false; rec.instrument_status = last_instr_status_;
        if (!rfa(38, last_trading_phase_)) return false; rec.trading_phase_code = last_trading_phase_;
        if (!rfn(37, last_num_trades_)) return false; rec.num_trades = last_num_trades_;
        if (!rfn(36, last_total_volume_)) return false; rec.total_volume = last_total_volume_;
        if (!rfn(35, last_total_value_)) return false; rec.total_value = last_total_value_;
        if (!rfn(34, last_total_bid_qty_)) return false; rec.total_bid_qty = last_total_bid_qty_;
        if (!rfn(33, last_wavg_bid_px_)) return false; rec.wavg_bid_px = last_wavg_bid_px_;
        if (!rfn(32, last_alt_wavg_bid_px_)) return false; rec.alt_wavg_bid_px = last_alt_wavg_bid_px_;
        if (!rfn(31, last_total_offer_qty_)) return false; rec.total_offer_qty = last_total_offer_qty_;
        if (!rfn(30, last_wavg_offer_px_)) return false; rec.wavg_offer_px = last_wavg_offer_px_;
        if (!rfn(29, last_alt_wavg_offer_px_)) return false; rec.alt_wavg_offer_px = last_alt_wavg_offer_px_;
        if (!rfn(28, last_iopv_)) return false; rec.iopv = last_iopv_;
        if (!rfn(27, last_etf_buy_num_)) return false; rec.etf_buy_num = last_etf_buy_num_;
        if (!rfn(26, last_etf_buy_amount_)) return false; rec.etf_buy_amount = last_etf_buy_amount_;
        if (!rfn(25, last_etf_buy_money_)) return false; rec.etf_buy_money = last_etf_buy_money_;
        if (!rfn(24, last_etf_sell_num_)) return false; rec.etf_sell_num = last_etf_sell_num_;
        if (!rfn(23, last_etf_sell_amount_)) return false; rec.etf_sell_amount = last_etf_sell_amount_;
        if (!rfn(22, last_etf_sell_money_)) return false; rec.etf_sell_money = last_etf_sell_money_;
        if (!rfn(21, last_ytm_)) return false; rec.ytm = last_ytm_;
        if (!rfn(20, last_total_warrant_exec_qty_)) return false; rec.total_warrant_exec_qty = last_total_warrant_exec_qty_;
        if (!rfn(19, last_war_lower_px_)) return false; rec.war_lower_px = last_war_lower_px_;
        if (!rfn(18, last_war_upper_px_)) return false; rec.war_upper_px = last_war_upper_px_;
        if (!rfn(17, last_withdraw_buy_num_)) return false; rec.withdraw_buy_num = last_withdraw_buy_num_;
        if (!rfn(16, last_withdraw_buy_amount_)) return false; rec.withdraw_buy_amount = last_withdraw_buy_amount_;
        if (!rfn(15, last_withdraw_buy_money_)) return false; rec.withdraw_buy_money = last_withdraw_buy_money_;
        if (!rfn(14, last_withdraw_sell_num_)) return false; rec.withdraw_sell_num = last_withdraw_sell_num_;
        if (!rfn(13, last_withdraw_sell_amount_)) return false; rec.withdraw_sell_amount = last_withdraw_sell_amount_;
        if (!rfn(12, last_withdraw_sell_money_)) return false; rec.withdraw_sell_money = last_withdraw_sell_money_;
        if (!rfn(11, last_total_bid_num_)) return false; rec.total_bid_num = last_total_bid_num_;
        if (!rfn(10, last_total_offer_num_)) return false; rec.total_offer_num = last_total_offer_num_;
        if (!rfn(9,  last_bid_trade_max_dur_)) return false; rec.bid_trade_max_dur = last_bid_trade_max_dur_;
        if (!rfn(8,  last_offer_trade_max_dur_)) return false; rec.offer_trade_max_dur = last_offer_trade_max_dur_;
        if (!rfn(7,  last_num_bid_orders_)) return false; rec.num_bid_orders = last_num_bid_orders_;
        if (!rfn(6,  last_num_offer_orders_)) return false; rec.num_offer_orders = last_num_offer_orders_;

        // NoBidLevel: none 类型，始终存在
        { uint64_t n; size_t w; if (utils::readFast(body_ + cursor_, len_ - cursor_, n, w) != utils::Status::Ok) { spdlog::warn("[ua3202] NoBidLevel 读取失败: cursor={}", cursor_); return false; } cursor_ += w; if (!readLevels(n, rec.bid_levels, "bid")) return false; }

        // NoOfferLevel: none 类型，始终存在
        { uint64_t n; size_t w; if (utils::readFast(body_ + cursor_, len_ - cursor_, n, w) != utils::Status::Ok) { spdlog::warn("[ua3202] NoOfferLevel 读取失败: cursor={}", cursor_); return false; } cursor_ += w; if (!readLevels(n, rec.offer_levels, "offer")) return false; }

        rec.valid = true;
        return true;
    }

private:
    const uint8_t* body_;
    size_t         len_;
    size_t         cursor_ = 0;

    uint32_t    last_tick_time_              = 0;
    uint32_t    last_data_status_            = 0;
    std::string last_sec_id_;
    std::string last_image_status_;
    int64_t     last_pre_close_px_           = 0;
    int64_t     last_open_px_                = 0;
    int64_t     last_high_px_                = 0;
    int64_t     last_low_px_                 = 0;
    int64_t     last_last_px_                = 0;
    int64_t     last_close_px_               = 0;
    std::string last_instr_status_;
    std::string last_trading_phase_;
    uint64_t    last_num_trades_             = 0;
    int64_t     last_total_volume_           = 0;
    int64_t     last_total_value_            = 0;
    int64_t     last_total_bid_qty_          = 0;
    int64_t     last_wavg_bid_px_            = 0;
    int64_t     last_alt_wavg_bid_px_        = 0;
    int64_t     last_total_offer_qty_        = 0;
    int64_t     last_wavg_offer_px_          = 0;
    int64_t     last_alt_wavg_offer_px_      = 0;
    int64_t     last_iopv_                   = 0;
    uint64_t    last_etf_buy_num_            = 0;
    int64_t     last_etf_buy_amount_         = 0;
    int64_t     last_etf_buy_money_          = 0;
    uint64_t    last_etf_sell_num_           = 0;
    int64_t     last_etf_sell_amount_        = 0;
    int64_t     last_etf_sell_money_         = 0;
    int64_t     last_ytm_                    = 0;
    int64_t     last_total_warrant_exec_qty_ = 0;
    int64_t     last_war_lower_px_           = 0;
    int64_t     last_war_upper_px_           = 0;
    uint64_t    last_withdraw_buy_num_       = 0;
    int64_t     last_withdraw_buy_amount_    = 0;
    int64_t     last_withdraw_buy_money_     = 0;
    uint64_t    last_withdraw_sell_num_      = 0;
    int64_t     last_withdraw_sell_amount_   = 0;
    int64_t     last_withdraw_sell_money_    = 0;
    uint64_t    last_total_bid_num_          = 0;
    uint64_t    last_total_offer_num_        = 0;
    uint32_t    last_bid_trade_max_dur_      = 0;
    uint32_t    last_offer_trade_max_dur_    = 0;
    uint32_t    last_num_bid_orders_         = 0;
    uint32_t    last_num_offer_orders_       = 0;

    bool readLevels(uint64_t n, std::vector<PriceLevel>& levels, const char* side) {
        levels.resize(n);
        int64_t  last_price      = 0;
        int64_t  last_qty        = 0;
        uint64_t last_num_orders = 0;
        for (uint64_t i = 0; i < n; ++i) {
            uint64_t sbits = 0; size_t spm;
            if (utils::readFast(body_ + cursor_, len_ - cursor_, sbits, spm) != utils::Status::Ok) {
                spdlog::warn("[ua3202] {} level[{}] sub-PMAP 读取失败: cursor={}", side, i, cursor_);
                return false;
            }
            cursor_ += spm;
            if (spm != 1) {
                spdlog::warn("[ua3202] {} level[{}] sub-PMAP 长度异常: spm={}", side, i, spm);
                return false;
            }
            if (sbits & (1ull << 6)) { spdlog::warn("[ua3202] {} level[{}] PriceLevelOperator 不应出现", side, i); return false; }

            auto rfns = [&](int bit, auto& lv) -> bool {
                if (!(sbits & (1ull << bit))) return true;
                uint64_t v; size_t w;
                if (utils::readFast(body_ + cursor_, len_ - cursor_, v, w) != utils::Status::Ok) {
                    spdlog::warn("[ua3202] {} level[{}] sub-bit{} 读取失败: cursor={}", side, i, bit, cursor_);
                    return false;
                }
                cursor_ += w;
                auto [x, is_null] = utils::decNull(v);
                if (!is_null) lv = decltype(lv)(x);
                return true;
            };

            if (!rfns(5, last_price)) return false; levels[i].price = last_price;
            if (!rfns(4, last_qty)) return false; levels[i].qty = last_qty;
            if (!rfns(3, last_num_orders)) return false; levels[i].num_orders = uint32_t(last_num_orders);

            // Orders: none 类型，始终存在
            uint64_t n_orders; size_t ow;
            if (utils::readFast(body_ + cursor_, len_ - cursor_, n_orders, ow) != utils::Status::Ok) {
                spdlog::warn("[ua3202] {} level[{}] Orders count 读取失败: cursor={}", side, i, cursor_);
                return false;
            }
            cursor_ += ow;
            levels[i].orders.resize(n_orders);
            int64_t last_oqty = 0;
            for (uint64_t j = 0; j < n_orders; ++j) {
                uint64_t obits = 0; size_t opm;
                if (utils::readFast(body_ + cursor_, len_ - cursor_, obits, opm) != utils::Status::Ok) {
                    spdlog::warn("[ua3202] {} level[{}] order[{}] sub-PMAP 读取失败: cursor={}", side, i, j, cursor_);
                    return false;
                }
                cursor_ += opm;
                if (obits & (1ull << 6)) { spdlog::warn("[ua3202] {} level[{}] order[{}] OrderQueueOperator 不应出现", side, i, j); return false; }
                if (obits & (1ull << 5)) { spdlog::warn("[ua3202] {} level[{}] order[{}] OrderQueueOperatorEntryID 不应出现", side, i, j); return false; }
                if (obits & (1ull << 4)) {
                    uint64_t v; size_t w;
                    if (utils::readFast(body_ + cursor_, len_ - cursor_, v, w) != utils::Status::Ok) {
                        spdlog::warn("[ua3202] {} level[{}] order[{}] OrderQty 读取失败: cursor={}", side, i, j, cursor_);
                        return false;
                    }
                    cursor_ += w;
                    auto [x, is_null] = utils::decNull(v);
                    if (!is_null) last_oqty = int64_t(x);
                }
                levels[i].orders[j] = last_oqty;
            }
        }
        return true;
    }
};

// 跨 TCP 流去重: key = security_id + "|" + tick_time
inline std::unordered_set<std::string> g_seen;

inline void emit(const Msg& r, uint32_t outer_seq, uint32_t frame_idx, size_t rec_idx, bool dedup, std::ostream& out) {
    if (dedup) {
        std::string key = r.security_id + "|" + std::to_string(r.tick_time);
        if (!g_seen.insert(key).second) return;
    }

    static bool header_done = false;
    if (!header_done) {
        header_done = true;
        out << "SecID,TickTime,DataStatus,ImageStatus,InstrStatus,Phase,"
               "PreClose,Open,High,Low,Last,Close,"
               "NumTrades,TotalVol,TotalVal,"
               "TotalBidQty,WAvgBidPx,AltWAvgBidPx,"
               "TotalOfferQty,WAvgOfferPx,AltWAvgOfferPx,"
               "IOPV,ETFBuyNum,ETFBuyAmt,ETFBuyMoney,ETFSellNum,ETFSellAmt,ETFSellMoney,"
               "YTM,WarrantExecQty,WarLow,WarHigh,"
               "WdBuyNum,WdBuyAmt,WdBuyMoney,WdSellNum,WdSellAmt,WdSellMoney,"
               "TotalBidNum,TotalOfferNum,BidMaxDur,OfferMaxDur,NumBidOrd,NumOfferOrd,";
        for (int i = 1; i <= 10; ++i) out << "BidPx" << i << ",BidQty" << i << ",";
        for (int i = 1; i <= 10; ++i) out << "OfferPx" << i << ",OfferQty" << i << ",";
        out << "PMAP,OuterSeq,FrameIdx,RecIdx\n";
    }

    // 价格字段精度待确认（此处以 ×10000 输出，即 4 位小数）
    auto px = [](int64_t v) { return utils::fmtDecFixed(v, 4); };

    out << r.security_id << ','
        << utils::fmtTickTime(r.tick_time) << ','
        << r.data_status << ','
        << (r.image_status.empty() ? "?" : r.image_status) << ','
        << (r.instrument_status.empty() ? "?" : r.instrument_status) << ','
        << (r.trading_phase_code.empty() ? "?" : r.trading_phase_code) << ','
        << px(r.pre_close_px) << ',' << px(r.open_px) << ',' << px(r.high_px) << ','
        << px(r.low_px) << ',' << px(r.last_px) << ',' << px(r.close_px) << ','
        << r.num_trades << ',' << r.total_volume << ',' << r.total_value << ','
        << r.total_bid_qty << ',' << px(r.wavg_bid_px) << ',' << px(r.alt_wavg_bid_px) << ','
        << r.total_offer_qty << ',' << px(r.wavg_offer_px) << ',' << px(r.alt_wavg_offer_px) << ','
        << px(r.iopv) << ','
        << r.etf_buy_num << ',' << r.etf_buy_amount << ',' << r.etf_buy_money << ','
        << r.etf_sell_num << ',' << r.etf_sell_amount << ',' << r.etf_sell_money << ','
        << px(r.ytm) << ',' << r.total_warrant_exec_qty << ',' << px(r.war_lower_px) << ',' << px(r.war_upper_px) << ','
        << r.withdraw_buy_num << ',' << r.withdraw_buy_amount << ',' << r.withdraw_buy_money << ','
        << r.withdraw_sell_num << ',' << r.withdraw_sell_amount << ',' << r.withdraw_sell_money << ','
        << r.total_bid_num << ',' << r.total_offer_num << ','
        << r.bid_trade_max_dur << ',' << r.offer_trade_max_dur << ','
        << r.num_bid_orders << ',' << r.num_offer_orders << ',';

    for (int i = 0; i < 10; ++i) {
        if (i < (int)r.bid_levels.size()) out << px(r.bid_levels[i].price) << ',' << r.bid_levels[i].qty << ',';
        else out << "0,0,";
    }
    for (int i = 0; i < 10; ++i) {
        if (i < (int)r.offer_levels.size()) out << px(r.offer_levels[i].price) << ',' << r.offer_levels[i].qty << ',';
        else out << "0,0,";
    }

    out << "0x" << std::hex << std::setw(16) << std::setfill('0') << r.pmap_raw
        << std::dec << std::setfill(' ') << ','
        << outer_seq << ',' << frame_idx << ',' << rec_idx << '\n';
}

}  // namespace ua3202
