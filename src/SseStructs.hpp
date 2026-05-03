#pragma once
// SseStructs.hpp — 上交所 SSE 行情数据结构

#include <cstdint>
#include <string>

#include "utils.hpp"

// ---- 帧头（固定 40 字节，大端） ----

struct FrameHeader {
    uint32_t magic;
    uint32_t length;
    uint32_t type_hi;
    uint32_t type_lo;
    uint32_t outer_seq;
    uint32_t comp;

    static FrameHeader from(const uint8_t* p) {
        FrameHeader h;
        h.magic     = readBE32(p);
        h.length    = readBE32(p +  4);
        h.type_hi   = readBE32(p +  8);
        h.type_lo   = readBE32(p + 12);
        h.outer_seq = readBE32(p + 16);
        h.comp      = readBE32(p + 32);
        return h;
    }
};

namespace sse95803 {

// 一条解码后的记录（action='S' 时为状态记录，bs_flag 含交易阶段码）
struct TickRecord {
    uint16_t    pmap_raw     = 0;   // 14-bit PMAP（调试用，readFast 原始值截断）
    uint64_t    template_id  = 0;   // 期望 5803

    uint64_t    biz_index    = 0;
    uint32_t    channel      = 0;
    std::string security_id;
    uint32_t    tick_time    = 0;   // HHMMSSXX，已做 nullable -1
    char        action       = 0;   // 'A'/'D'/'T'/'C'/'S'
    uint64_t    buy_order_no  = 0;
    uint64_t    sell_order_no = 0;
    int64_t     price_e3     = 0;   // Price × 1000
    int64_t     qty_e3       = 0;   // Qty × 1000
    int64_t     money_e5     = 0;   // TradeMoney × 10^5
    std::string bs_flag;            // 'B'/'S'/'N' 或状态记录时 "SUSP"/"OCALL"/"START"

    bool valid = false;
};

}  // namespace sse95803
