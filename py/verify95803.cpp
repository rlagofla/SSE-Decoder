// error 第一行是 decode 的，第二行是 ref
// miss cnt 是 decode 的在 ref 中找不到
// error cnt 是 decode 的在 ref 中找到了，但是后面对不上
// match cnt 是 decode 找到了也对上了
// ref remain 是 ref 中 没有被匹配到的，包括 error

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

#include "csv.hpp"

struct TickRecord {
    uint64_t    biz_index  = 0;     // 业务序号 (与 CSV BizIndex 对齐)
    uint32_t    channel    = 0;     // 通道号
    std::string security_id;        // "601106" etc
    std::string tick_time;          // HHMMSSXX, 9535063 = 09:53:50.63
    char        type       = 0;     // 'A'/'D'/'T'/'C'
    uint64_t    buy_order_no  = 0;  // 'A'/'D'+BS='B' 填此, 'T' 填 BidApplSeq
    uint64_t    sell_order_no = 0;  // 'A'/'D'+BS='S' 填此, 'T' 填 OfferApplSeq
    double      price      = 0;     // Price × 1000 (STEP 三位小数的整数表达)
    double      qty        = 0;     // Qty   × 1000
    double      money      = 0;     // TradeMoney × 10^5
    std::string bs_flag    = "";     // 'B'/'S'/'N'

    static TickRecord from_row(const std::vector<std::string>& fields) {
        TickRecord ans{};
        ans.biz_index     = from_string<uint64_t>(fields[0]);
        ans.channel       = from_string<uint32_t>(fields[1]);
        ans.security_id   = fields[2];
        ans.tick_time     = fields[3];
        ans.type          = fields[4][0];
        ans.buy_order_no  = from_string<uint64_t>(fields[5]);
        ans.sell_order_no = from_string<uint64_t>(fields[6]);
        ans.price         = from_string<double>(fields[7]);
        ans.qty           = from_string<double>(fields[8]);
        ans.money         = from_string<double>(fields[9]);
        ans.bs_flag       = fields[10];
        return ans;
    }

    inline uint64_t get_key() const {
        return (uint64_t(this->channel) << 32) | uint32_t(this->biz_index);
    }

    inline void print() const {
        std::cout << this->biz_index    << "\t"
                  << this->channel      << "\t"
                  << this->security_id  << "\t"
                  << this->type         << "\t"
                  << this->buy_order_no << "\t"
                  << this->sell_order_no << "\t"
                  << this->price        << "\t"
                  << this->qty          << "\t"
                  << this->money        << "\n";
    }

    inline static bool isSame(const TickRecord& a, const TickRecord& b) {
        return a.security_id   == b.security_id  &&
               a.type          == b.type         &&
               a.price         == b.price        &&
               a.qty           == b.qty          &&
               a.money         == b.money        &&
               a.bs_flag       == b.bs_flag      &&
               a.buy_order_no  == b.buy_order_no &&
               a.sell_order_no == b.sell_order_no;
    }
};

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "用法: " << argv[0] << " <decoded_csv> <reference_csv>\n";
        return 1;
    }

    std::unordered_map<uint64_t, TickRecord> ref_set;
    size_t ref_n = foreach_csv<TickRecord>(argv[2], [&](const TickRecord& record) {
        ref_set[record.get_key()] = record;
    });

    size_t miss_cnt = 0;
    size_t error_cnt = 0;
    size_t match_cnt = 0;

    size_t dec_n = foreach_csv<TickRecord>(argv[1], [&](const TickRecord& record) {
        auto it = ref_set.find(record.get_key());
        if (it == ref_set.end()) {
            std::cout << " miss: ";
            record.print();
            ++miss_cnt;
            return;
        }
        if (TickRecord::isSame(record, it->second)) {
            ++match_cnt;
            ref_set.erase(it);
            return;
        }
        std::cout << "error: ";
        record.print();
        std::cout << "       ";
        it->second.print();
        ++error_cnt;
    });

    printf(" dec size: %ld\n ref size: %ld\n miss_cnt: %ld\nerror_cnt: %ld\nmatch_cnt: %ld\nref remain %ld",
           dec_n, ref_n, miss_cnt, error_cnt, match_cnt, ref_set.size());

    return 0;
}
