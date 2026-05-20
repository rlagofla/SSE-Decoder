#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include <deque>
#include <algorithm>

#include "csv.hpp"

static const std::string OUT_MISS       = "out/miss.csv";
static const std::string OUT_ERROR      = "out/error.csv";
static const std::string OUT_REF_REMAIN = "out/ref_remain.csv";

struct TickRecord {
    uint64_t    biz_index  = 0;
    uint32_t    channel    = 0;
    std::string security_id;
    std::string tick_time;
    char        type       = 0;
    uint64_t    buy_order_no  = 0;
    uint64_t    sell_order_no = 0;
    double      price      = 0;
    double      qty        = 0;
    double      money      = 0;
    std::string bs_flag    = "";

    static TickRecord from_row(const std::vector<std::string>& fields) {
        if (fields.size() < 11) return {};
        TickRecord ans{};
        try {
            ans.biz_index     = std::stoull(fields[0]);
            ans.channel       = (uint32_t)std::stoul(fields[1]);
            ans.security_id   = fields[2];
            ans.tick_time     = fields[3];
            ans.type          = fields[4].empty() ? 0 : fields[4][0];
            ans.buy_order_no  = std::stoull(fields[5]);
            ans.sell_order_no = std::stoull(fields[6]);
            ans.price         = std::stod(fields[7]);
            ans.qty           = std::stod(fields[8]);
            ans.money         = std::stod(fields[9]);
            ans.bs_flag       = fields[10];
        } catch (...) {}
        return ans;
    }

    void write_csv(std::ofstream& f) const {
        f << this->biz_index     << ","
          << this->channel       << ","
          << this->security_id   << ","
          << this->tick_time     << ","
          << this->type          << ","
          << this->buy_order_no  << ","
          << this->sell_order_no << ","
          << this->price         << ","
          << this->qty           << ","
          << this->money         << ","
          << this->bs_flag       << "\n";
    }

    static void write_csv_header(std::ofstream& f) {
        f << "biz_index,channel,security_id,tick_time,type,"
             "buy_order_no,sell_order_no,price,qty,money,bs_flag\n";
    }

    inline static bool isSame(const TickRecord& a, const TickRecord& b) {
        return a.security_id   == b.security_id  &&
               a.tick_time.substr(0, std::min((size_t)8, a.tick_time.size())) == 
               b.tick_time.substr(0, std::min((size_t)8, b.tick_time.size())) &&
               a.type          == b.type         &&
               a.price         == b.price        &&
               a.qty           == b.qty          &&
               a.money         == b.money        &&
               a.bs_flag       == b.bs_flag      &&
               a.buy_order_no  == b.buy_order_no &&
               a.sell_order_no == b.sell_order_no;
    }
};

void write_with_source(std::ofstream& f, const std::string& src, const TickRecord& r) {
    f << src << ","
      << r.biz_index     << ","
      << r.channel       << ","
      << r.security_id   << ","
      << r.tick_time     << ","
      << r.type          << ","
      << r.buy_order_no  << ","
      << r.sell_order_no << ","
      << r.price         << ","
      << r.qty           << ","
      << r.money         << ","
      << r.bs_flag       << "\n";
}

std::vector<std::string> split_csv_line_fast(const std::string& line) {
    std::vector<std::string> fields;
    fields.reserve(12);
    size_t start = 0;
    size_t end = line.find(',');
    while (end != std::string::npos) {
        fields.push_back(line.substr(start, end - start));
        start = end + 1;
        end = line.find(',', start);
    }
    fields.push_back(line.substr(start));
    return fields;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "用法: " << argv[0] << " <decoded_csv> <reference_csv>\n";
        return 1;
    }

    std::ifstream f_dec_in(argv[1]);
    std::ifstream f_ref_in(argv[2]);
    if (!f_dec_in || !f_ref_in) {
        std::cerr << "打开输入文件失败\n";
        return 1;
    }

    std::ofstream f_miss(OUT_MISS);
    std::ofstream f_error(OUT_ERROR);
    std::ofstream f_remain(OUT_REF_REMAIN);
    if (!f_miss || !f_error || !f_remain) {
        std::cerr << "打开输出文件失败，请确认 out/ 目录存在\n";
        return 1;
    }

    TickRecord::write_csv_header(f_miss);
    f_error << "source,biz_index,channel,security_id,tick_time,type,buy_order_no,sell_order_no,price,qty,money,bs_flag\n";
    TickRecord::write_csv_header(f_remain);

    std::unordered_map<uint32_t, std::deque<TickRecord>> pending_dec;
    std::unordered_map<uint32_t, std::deque<TickRecord>> pending_ref;

    size_t dec_n = 0, ref_n = 0;
    size_t miss_cnt = 0, error_cnt = 0, match_cnt = 0, ref_remain_cnt = 0;

    std::string line_dec, line_ref;
    std::getline(f_dec_in, line_dec); 
    std::getline(f_ref_in, line_ref); 

    auto process_dec = [&](const TickRecord& r) {
        auto& q_ref = pending_ref[r.channel];
        while (!q_ref.empty() && q_ref.front().biz_index < r.biz_index) {
            q_ref.front().write_csv(f_remain);
            ref_remain_cnt++;
            q_ref.pop_front();
        }
        if (!q_ref.empty() && q_ref.front().biz_index == r.biz_index) {
            if (TickRecord::isSame(r, q_ref.front())) {
                match_cnt++;
            } else {
                error_cnt++;
                write_with_source(f_error, "decode", r);
                write_with_source(f_error, "ref", q_ref.front());
                q_ref.front().write_csv(f_remain);
                ref_remain_cnt++;
            }
            q_ref.pop_front();
        } else {
            pending_dec[r.channel].push_back(r);
        }
    };

    auto process_ref = [&](const TickRecord& r) {
        auto& q_dec = pending_dec[r.channel];
        while (!q_dec.empty() && q_dec.front().biz_index < r.biz_index) {
            q_dec.front().write_csv(f_miss);
            miss_cnt++;
            q_dec.pop_front();
        }
        if (!q_dec.empty() && q_dec.front().biz_index == r.biz_index) {
            if (TickRecord::isSame(q_dec.front(), r)) {
                match_cnt++;
            } else {
                error_cnt++;
                write_with_source(f_error, "decode", q_dec.front());
                write_with_source(f_error, "ref", r);
                r.write_csv(f_remain);
                ref_remain_cnt++;
            }
            q_dec.pop_front();
        } else {
            pending_ref[r.channel].push_back(r);
        }
    };

    printf("Comparing files...\n");
    bool active_dec = true, active_ref = true;
    while (active_dec || active_ref) {
        if (active_dec) {
            if (std::getline(f_dec_in, line_dec)) {
                if (!line_dec.empty()) {
                    process_dec(TickRecord::from_row(split_csv_line_fast(line_dec)));
                    dec_n++;
                }
            } else active_dec = false;
        }
        if (active_ref) {
            if (std::getline(f_ref_in, line_ref)) {
                if (!line_ref.empty()) {
                    process_ref(TickRecord::from_row(split_csv_line_fast(line_ref)));
                    ref_n++;
                }
            } else active_ref = false;
        }
        if ((dec_n + ref_n) % 1000000 == 0) {
            printf("\rProcessed %zu lines...", dec_n + ref_n);
            fflush(stdout);
        }
    }

    for (auto& pair : pending_dec) {
        for (const auto& r : pair.second) {
            r.write_csv(f_miss);
            miss_cnt++;
        }
    }
    for (auto& pair : pending_ref) {
        for (const auto& r : pair.second) {
            r.write_csv(f_remain);
            ref_remain_cnt++;
        }
    }

    printf("\nFinished.\n");
    printf("Decoded lines: %zu, Reference lines: %zu\n", dec_n, ref_n);
    printf("Matches: %zu, Errors: %zu, Missed in Ref (Decode has extra): %zu, Ref Remain (Ref has extra/mismatch): %zu\n",
           match_cnt, error_cnt, miss_cnt, ref_remain_cnt);

    return 0;
}

