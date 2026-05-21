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
        if (!fr_.readNum<utils::FastOp::None>(rec.pmap_raw)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        fr_.setPmap(rec.pmap_raw);

        // bit48: TID（期望 3202）
        if (!fr_.readNum<utils::FastOp::Copy>(48, last_template_id_, rec.template_id)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (rec.template_id != 3202) {
            spdlog::warn("[ua3202] TID: 期望 3202, 实际 {}", rec.template_id);
            return false;
        }

        if (!fr_.readNum<utils::FastOp::Copy>(47, last_tick_time_, rec.tick_time)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::Default>(46, rec.data_status)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };

        if (!fr_.readString<utils::FastOp::None>(rec.security_id)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::None>(rec.image_status)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };

        if (!fr_.readNum<utils::FastOp::DefaultNull>(45, rec.pre_close_px)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(44, rec.open_px)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(43, rec.high_px)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(42, rec.low_px)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(41, rec.last_px)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(40, rec.close_px)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readString<utils::FastOp::Default>(39, rec.instrument_status)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readString<utils::FastOp::Default>(38, rec.trading_phase_code)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(37, rec.num_trades)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(36, rec.total_volume)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(35, rec.total_value)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(34, rec.total_bid_qty)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(33, rec.wavg_bid_px)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(32, rec.alt_wavg_bid_px)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(31, rec.total_offer_qty)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(30, rec.wavg_offer_px)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(29, rec.alt_wavg_offer_px)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(28, rec.iopv)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(27, rec.etf_buy_num)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(26, rec.etf_buy_amount)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(25, rec.etf_buy_money)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(24, rec.etf_sell_num)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(23, rec.etf_sell_amount)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(22, rec.etf_sell_money)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(21, rec.ytm)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(20, rec.total_warrant_exec_qty)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(19, rec.war_lower_px)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(18, rec.war_upper_px)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(17, rec.withdraw_buy_num)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(16, rec.withdraw_buy_amount)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(15, rec.withdraw_buy_money)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(14, rec.withdraw_sell_num)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(13, rec.withdraw_sell_amount)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(12, rec.withdraw_sell_money)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(11, rec.total_bid_num)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(10, rec.total_offer_num)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(9, rec.bid_trade_max_dur)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(8, rec.offer_trade_max_dur)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(7, rec.num_bid_orders)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!fr_.readNum<utils::FastOp::DefaultNull>(6, rec.num_offer_orders)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };

        // NoBidLevel: none 类型，始终存在
        uint64_t no_bid;
        if (!fr_.readNum<utils::FastOp::NoneNull>(no_bid)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!readLevels(no_bid, rec.bid_levels, "bid")) { spdlog::warn("[ua3202] BidLevel 读取失败"); return false; };

        // NoOfferLevel: none 类型，始终存在
        uint64_t no_offer;
        if (!fr_.readNum<utils::FastOp::NoneNull>(no_offer)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
        if (!readLevels(no_offer, rec.offer_levels, "offer")) { spdlog::warn("[ua3202] OfferLevel 读取失败"); return false; };

        return true;
    }

private:
    utils::FastReader fr_;

    uint64_t    last_template_id_            = 0;
    uint32_t    last_tick_time_              = 0;

    bool readLevels(uint64_t n, std::vector<PriceLevel>& levels, const char* side) {
        levels.resize(n);
        for (uint64_t i = 0; i < n; ++i) {
            uint64_t sbits = 0;
            if (!fr_.readNum<utils::FastOp::None>(sbits)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
            fr_.setPmap(sbits);

            if (fr_.hasBit(6)) { spdlog::warn("[ua3202] {} level[{}] PriceLevelOperator 不应出现", side, i); return false; }

            if (!fr_.readNum<utils::FastOp::DefaultNull>(5, levels[i].price)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
            if (!fr_.readNum<utils::FastOp::DefaultNull>(4, levels[i].qty)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
            if (!fr_.readNum<utils::FastOp::DefaultNull>(3, levels[i].num_orders)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };

            uint64_t n_orders;
            if (!fr_.readNum<utils::FastOp::NoneNull>(n_orders)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
            levels[i].orders.resize(n_orders);
            for (uint64_t j = 0; j < n_orders; ++j) {
                uint64_t obits = 0;
                if (!fr_.readNum<utils::FastOp::None>(obits)) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
                fr_.setPmap(obits);

                if (fr_.hasBit(6)) { spdlog::warn("[ua3202] {} level[{}] order[{}] OrderQueueOperator 不应出现", side, i, j); return false; }
                if (fr_.hasBit(5)) { spdlog::warn("[ua3202] {} level[{}] order[{}] OrderQueueOperatorEntryID 不应出现", side, i, j); return false; }

                if (!fr_.readNum<utils::FastOp::DefaultNull>(4, levels[i].orders[j])) { spdlog::warn("[ua3202] FAST 字段读取失败"); return false; };
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

    out << r.security_id << ','
        << utils::fmtSnapTime(r.tick_time) << ','
        << r.data_status << ','
        << r.image_status << ','
        << (r.instrument_status.empty() ? "?" : r.instrument_status) << ','
        << (r.trading_phase_code.empty() ? "?" : r.trading_phase_code) << ','
        << utils::fmtDecFixed(r.pre_close_px, 3) << ',' 
        << utils::fmtDecFixed(r.open_px, 3) << ',' 
        << utils::fmtDecFixed(r.high_px, 3) << ','
        << utils::fmtDecFixed(r.low_px, 3) << ',' 
        << utils::fmtDecFixed(r.last_px, 3) << ',' 
        << utils::fmtDecFixed(r.close_px, 3) << ','
        << r.num_trades << ',' 
        << utils::fmtDecFixed(r.total_volume, 3) << ',' 
        << utils::fmtDecFixed(r.total_value, 5) << ','
        << utils::fmtDecFixed(r.total_bid_qty, 3) << ',' 
        << utils::fmtDecFixed(r.wavg_bid_px, 3) << ',' 
        << utils::fmtDecFixed(r.alt_wavg_bid_px, 3) << ','
        << utils::fmtDecFixed(r.total_offer_qty, 3) << ',' 
        << utils::fmtDecFixed(r.wavg_offer_px, 3) << ',' 
        << utils::fmtDecFixed(r.alt_wavg_offer_px, 3) << ','
        << utils::fmtDecFixed(r.iopv, 3) << ','
        << r.etf_buy_num << ',' << r.etf_buy_amount << ',' << r.etf_buy_money << ','
        << r.etf_sell_num << ',' << r.etf_sell_amount << ',' << r.etf_sell_money << ','
        << utils::fmtDecFixed(r.ytm, 3) << ',' 
        << r.total_warrant_exec_qty << ',' 
        << utils::fmtDecFixed(r.war_lower_px, 3) << ',' 
        << utils::fmtDecFixed(r.war_upper_px, 3) << ','
        << r.withdraw_buy_num << ',' 
        << utils::fmtDecFixed(r.withdraw_buy_amount, 3) << ',' 
        << utils::fmtDecFixed(r.withdraw_buy_money, 5) << ','
        << r.withdraw_sell_num << ',' 
        << utils::fmtDecFixed(r.withdraw_sell_amount, 3) << ',' 
        << utils::fmtDecFixed(r.withdraw_sell_money, 5) << ','
        << r.total_bid_num << ',' << r.total_offer_num << ','
        << r.bid_trade_max_dur << ',' << r.offer_trade_max_dur << ','
        << r.num_bid_orders << ',' << r.num_offer_orders << ',';

    for (int i = 0; i < 10; ++i) {
        if (i < (int)r.bid_levels.size()) 
            out << utils::fmtDecFixed(r.bid_levels[i].price, 3) << ',' 
                << utils::fmtDecFixed(r.bid_levels[i].qty, 3) << ',';
        else out << "0,0,";
    }
    for (int i = 0; i < 10; ++i) {
        if (i < (int)r.offer_levels.size()) 
            out << utils::fmtDecFixed(r.offer_levels[i].price, 3) << ',' 
                << utils::fmtDecFixed(r.offer_levels[i].qty, 3) << ',';
        else out << "0,0,";
    }

    out << local_time << ',' << rec_idx << ',' << outer_seq << '\n';
}

}  // namespace ua3202
