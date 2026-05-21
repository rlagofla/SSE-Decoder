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
    uint32_t    image_status          = 0;
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
};

class Parser {
public:
    Parser(const uint8_t* body, size_t len) : fr_(body, len) {}

    bool next(Msg& rec) {
        rec = Msg{};
        if (fr_.empty()) return false;

        // pmap
        if (!fr_.readNum<utils::FastOp::None>(rec.pmap_raw)) return false;
        fr_.setPmap(rec.pmap_raw);

        // bit48: TID（期望 3202）
        if (!fr_.readNum<utils::FastOp::Copy>(48, last_template_id_, rec.template_id)) return false;
        if (rec.template_id != 3202) {
            spdlog::warn("[ua3202] TID: 期望 3202, 实际 {}", rec.template_id);
            return false;
        }

        if (!fr_.readNum<utils::FastOp::Copy>(47, last_tick_time_, rec.tick_time)) return false;
        if (!fr_.readNum<utils::FastOp::Copy>(46, last_data_status_, rec.data_status)) return false;

        if (!fr_.readString<utils::FastOp::None>(rec.security_id)) return false;
        if (!fr_.readNum<utils::FastOp::None>(rec.image_status)) return false;

        if (!fr_.readNum<utils::FastOp::CopyNull>(45, last_pre_close_px_, rec.pre_close_px)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(44, last_open_px_, rec.open_px)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(43, last_high_px_, rec.high_px)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(42, last_low_px_, rec.low_px)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(41, last_last_px_, rec.last_px)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(40, last_close_px_, rec.close_px)) return false;
        if (!fr_.readString<utils::FastOp::Copy>(39, last_instr_status_, rec.instrument_status)) return false;
        if (!fr_.readString<utils::FastOp::Copy>(38, last_trading_phase_, rec.trading_phase_code)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(37, last_num_trades_, rec.num_trades)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(36, last_total_volume_, rec.total_volume)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(35, last_total_value_, rec.total_value)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(34, last_total_bid_qty_, rec.total_bid_qty)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(33, last_wavg_bid_px_, rec.wavg_bid_px)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(32, last_alt_wavg_bid_px_, rec.alt_wavg_bid_px)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(31, last_total_offer_qty_, rec.total_offer_qty)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(30, last_wavg_offer_px_, rec.wavg_offer_px)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(29, last_alt_wavg_offer_px_, rec.alt_wavg_offer_px)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(28, last_iopv_, rec.iopv)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(27, last_etf_buy_num_, rec.etf_buy_num)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(26, last_etf_buy_amount_, rec.etf_buy_amount)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(25, last_etf_buy_money_, rec.etf_buy_money)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(24, last_etf_sell_num_, rec.etf_sell_num)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(23, last_etf_sell_amount_, rec.etf_sell_amount)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(22, last_etf_sell_money_, rec.etf_sell_money)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(21, last_ytm_, rec.ytm)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(20, last_total_warrant_exec_qty_, rec.total_warrant_exec_qty)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(19, last_war_lower_px_, rec.war_lower_px)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(18, last_war_upper_px_, rec.war_upper_px)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(17, last_withdraw_buy_num_, rec.withdraw_buy_num)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(16, last_withdraw_buy_amount_, rec.withdraw_buy_amount)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(15, last_withdraw_buy_money_, rec.withdraw_buy_money)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(14, last_withdraw_sell_num_, rec.withdraw_sell_num)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(13, last_withdraw_sell_amount_, rec.withdraw_sell_amount)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(12, last_withdraw_sell_money_, rec.withdraw_sell_money)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(11, last_total_bid_num_, rec.total_bid_num)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(10, last_total_offer_num_, rec.total_offer_num)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(9,  last_bid_trade_max_dur_, rec.bid_trade_max_dur)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(8,  last_offer_trade_max_dur_, rec.offer_trade_max_dur)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(7,  last_num_bid_orders_, rec.num_bid_orders)) return false;
        if (!fr_.readNum<utils::FastOp::CopyNull>(6,  last_num_offer_orders_, rec.num_offer_orders)) return false;

        // NoBidLevel: none 类型，始终存在
        uint64_t no_bid;
        if (!fr_.readNum<utils::FastOp::NoneNull>(no_bid)) return false;
        if (!readLevels(no_bid, rec.bid_levels, "bid")) return false;

        // NoOfferLevel: none 类型，始终存在
        uint64_t no_offer;
        if (!fr_.readNum<utils::FastOp::NoneNull>(no_offer)) return false;
        if (!readLevels(no_offer, rec.offer_levels, "offer")) return false;

        return true;
    }

private:
    utils::FastReader fr_;

    uint64_t    last_template_id_            = 0;
    uint32_t    last_tick_time_              = 0;
    uint32_t    last_data_status_            = 0;
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
        uint32_t last_num_orders = 0;
        for (uint64_t i = 0; i < n; ++i) {
            uint64_t sbits = 0;
            if (!fr_.readNum<utils::FastOp::None>(sbits)) return false;
            fr_.setPmap(sbits);

            if (fr_.hasBit(6)) { spdlog::warn("[ua3202] {} level[{}] PriceLevelOperator 不应出现", side, i); return false; }

            if (!fr_.readNum<utils::FastOp::CopyNull>(5, last_price, levels[i].price)) return false;
            if (!fr_.readNum<utils::FastOp::CopyNull>(4, last_qty, levels[i].qty)) return false;
            if (!fr_.readNum<utils::FastOp::CopyNull>(3, last_num_orders, levels[i].num_orders)) return false;

            uint64_t n_orders;
            if (!fr_.readNum<utils::FastOp::NoneNull>(n_orders)) return false;
            levels[i].orders.resize(n_orders);
            
            int64_t last_oqty = 0;
            for (uint64_t j = 0; j < n_orders; ++j) {
                uint64_t obits = 0;
                if (!fr_.readNum<utils::FastOp::None>(obits)) return false;
                fr_.setPmap(obits);

                if (fr_.hasBit(6)) { spdlog::warn("[ua3202] {} level[{}] order[{}] OrderQueueOperator 不应出现", side, i, j); return false; }
                if (fr_.hasBit(5)) { spdlog::warn("[ua3202] {} level[{}] order[{}] OrderQueueOperatorEntryID 不应出现", side, i, j); return false; }

                if (!fr_.readNum<utils::FastOp::CopyNull>(4, last_oqty, levels[i].orders[j])) return false;
            }
        }
        return true;
    }
};

// 跨 TCP 流去重: key = security_id + "|" + tick_time
inline std::unordered_set<std::string> g_seen;

inline void emit(const Msg& r, uint32_t outer_seq, const std::string& local_time, uint64_t rec_idx, bool dedup, std::ostream& out) {
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
        out << "LocalTime,RecIdx,OuterSeq\n";
    }

    // 价格字段精度待确认（此处以 ×10000 输出，即 4 位小数）
    auto px = [](int64_t v) { return utils::fmtDecFixed(v, 4); };

    out << r.security_id << ','
        << utils::fmtTickTime(r.tick_time) << ','
        << r.data_status << ','
        << r.image_status << ','
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

    out << local_time << ',' << rec_idx << ',' << outer_seq << '\n';
}

}  // namespace ua3202
