// verify_9_5803.cpp — 9/5803 解码结果与通联参考 CSV 的字段级对比验证工具
//
// 用法:
//   ./verify_9_5803 <decoded_csv> <reference_csv>
//
// decoded_csv  : decode_9_5803 --csv 的输出
//   列头: BizIndex,Channel,SecurityID,TickTime,Type,BuyOrderNO,SellOrderNO,
//          Price,Qty,TradeMoney,TickBSFlag,ExtCode,OuterSeq,FrameIdx,RecLen
//
// reference_csv: 通联参考文件 (mdl_4_24_0.csv 格式)
//   列头: BizIndex,Channel,SecurityID,TickTime,Type,BuyOrderNO,SellOrderNO,
//          Price,Qty,TradeMoney,TickBSFlag,LocalTime,SeqNo
//
// 两个文件均按 TickTime 升序。算法: 时间窗口流式 merge-join，内存 O(窗口大小)。
//
// 匹配键:   (Channel, BizIndex)
// 比对字段: SecurityID, TickTime, Type, BuyOrderNO, SellOrderNO,
//           Price, Qty, TradeMoney, TickBSFlag

#include <cstdio>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

// ---- CSV 工具 ----

static std::vector<std::string> splitCsv(const std::string& line) {
    std::vector<std::string> out;
    std::string tok;
    for (char c : line) {
        if (c == ',') { out.push_back(tok); tok.clear(); }
        else          { tok.push_back(c); }
    }
    out.push_back(tok);
    return out;
}

static std::unordered_map<std::string, int> parseHeader(const std::string& line) {
    std::unordered_map<std::string, int> m;
    auto cols = splitCsv(line);
    for (int i = 0; i < (int)cols.size(); ++i) m[cols[i]] = i;
    return m;
}

// ---- 格式归一化 ----

// TickTime → 整数 HHMMSSXX
// 支持 "HH:MM:SS.XX", "HH:MM:SS.XXX" (通联末尾补0), "HHMMSSXX"
static uint32_t parseTickTime(const std::string& s) {
    if (s.size() >= 11 && s[2] == ':' && s[5] == ':' && s[8] == '.') {
        auto num = [&](int pos, int len) {
            uint32_t v = 0;
            for (int i = 0; i < len && pos+i < (int)s.size(); ++i)
                v = v*10 + (s[pos+i]-'0');
            return v;
        };
        return num(0,2)*1000000 + num(3,2)*10000 + num(6,2)*100 + num(9,2);
    }
    try { return uint32_t(std::stoul(s)); } catch (...) { return 0; }
}

// TickTime 归一化为 "HH:MM:SS.XX"，消除 ".63" vs ".630" 的差异
static std::string normalizeTickTime(const std::string& s) {
    uint32_t t = parseTickTime(s);
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%02u:%02u:%02u.%02u",
                  t/1000000, (t/10000)%100, (t/100)%100, t%100);
    return buf;
}

// 数字归一化: 去掉小数末尾的零和多余的小数点，使 "1100.000" == "1100"，"6.330" == "6.33"
static std::string normalizeNum(const std::string& s) {
    if (s.find('.') == std::string::npos) return s;
    size_t end = s.size();
    while (end > 0 && s[end-1] == '0') --end;
    if (end > 0 && s[end-1] == '.') --end;
    return end == 0 ? "0" : s.substr(0, end);
}

// ---- 行结构 ----

struct Row {
    std::string biz_index, channel, tick_time;
    std::string security_id, type;
    std::string buy_order_no, sell_order_no;
    std::string price, qty, trade_money, bs_flag;
};

static std::string makeKey(const std::string& ch, const std::string& bi) {
    return ch + ":" + bi;
}

static Row extractRow(const std::vector<std::string>& cols,
                      const std::unordered_map<std::string, int>& hdr) {
    auto get = [&](const char* name) -> const std::string& {
        static const std::string empty;
        auto it = hdr.find(name);
        if (it == hdr.end() || it->second >= (int)cols.size()) return empty;
        return cols[it->second];
    };
    return { get("BizIndex"), get("Channel"), get("TickTime"),
             get("SecurityID"), get("Type"),
             get("BuyOrderNO"), get("SellOrderNO"),
             get("Price"), get("Qty"), get("TradeMoney"), get("TickBSFlag") };
}

// ---- 字段比对统计 ----

static constexpr int kNumFields = 9;
static const char* kFieldNames[kNumFields] = {
    "SecurityID", "TickTime", "Type",
    "BuyOrderNO", "SellOrderNO",
    "Price", "Qty", "TradeMoney", "TickBSFlag"
};

struct FieldStats {
    int64_t mismatch = 0;
    struct Ex { std::string decoded, ref, biz_index, channel; };
    std::vector<Ex> examples;
};

static void recordMismatch(FieldStats& fs, const std::string& d, const std::string& r,
                            const std::string& bi, const std::string& ch) {
    ++fs.mismatch;
    if (fs.examples.size() < 5) fs.examples.push_back({d, r, bi, ch});
}

// decoded 和 ref 的同一条记录比对九个字段
static bool compareRows(const Row& dec, const Row& ref, FieldStats stats[kNumFields]) {
    bool all_ok = true;
    auto cmp = [&](int idx, const std::string& d, const std::string& r) {
        if (d != r) { recordMismatch(stats[idx], d, r, ref.biz_index, ref.channel); all_ok = false; }
    };
    cmp(0, dec.security_id,                         ref.security_id);
    cmp(1, normalizeTickTime(dec.tick_time),         normalizeTickTime(ref.tick_time));
    cmp(2, dec.type,                                 ref.type);
    cmp(3, dec.buy_order_no,                         ref.buy_order_no);
    cmp(4, dec.sell_order_no,                        ref.sell_order_no);
    cmp(5, normalizeNum(dec.price),                  normalizeNum(ref.price));
    cmp(6, normalizeNum(dec.qty),                    normalizeNum(ref.qty));
    cmp(7, normalizeNum(dec.trade_money),            normalizeNum(ref.trade_money));
    cmp(8, dec.bs_flag,                              ref.bs_flag);
    return all_ok;
}

// ---- 主程序 ----

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "用法: " << argv[0] << " <decoded_csv> <reference_csv>\n";
        return 1;
    }

    std::ifstream dec_file(argv[1]);
    std::ifstream ref_file(argv[2]);
    if (!dec_file) { std::cerr << "无法打开: " << argv[1] << "\n"; return 1; }
    if (!ref_file) { std::cerr << "无法打开: " << argv[2] << "\n"; return 1; }

    std::string dec_hdr_line, ref_hdr_line;
    if (!std::getline(dec_file, dec_hdr_line)) { std::cerr << "decoded CSV 为空\n"; return 1; }
    if (!std::getline(ref_file, ref_hdr_line)) { std::cerr << "reference CSV 为空\n"; return 1; }
    auto dec_hdr = parseHeader(dec_hdr_line);
    auto ref_hdr = parseHeader(ref_hdr_line);

    for (const char* f : {"BizIndex","Channel","TickTime"}) {
        if (!dec_hdr.count(f)) { std::cerr << "decoded CSV 缺少列: " << f << "\n"; return 1; }
        if (!ref_hdr.count(f)) { std::cerr << "reference CSV 缺少列: " << f << "\n"; return 1; }
    }

    // 滑动窗口: key → decoded Row (有界缓冲，ε=1 tick 容差)
    constexpr uint32_t kTickEps = 1;
    std::unordered_map<std::string, Row> pending;
    pending.reserve(8192);

    FieldStats stats[kNumFields];
    int64_t ref_total = 0, dec_total = 0;
    int64_t matched = 0, all_correct = 0, missing = 0, extra = 0;

    constexpr int kMaxSample = 10;
    std::vector<Row> missing_samples, extra_samples;

    // 把 extra 样例统一用一个 lambda 处理，顺便累加计数
    auto countExtra = [&](Row r) {
        ++extra;
        if ((int)extra_samples.size() < kMaxSample)
            extra_samples.push_back(std::move(r));
    };

    // decoded 逐行预读游标
    std::string dec_line;
    bool dec_has_next = (bool)std::getline(dec_file, dec_line);
    auto readDecRow = [&]() {
        return extractRow(splitCsv(dec_line), dec_hdr);
    };

    // 流式扫参考文件
    std::string ref_line;
    while (std::getline(ref_file, ref_line)) {
        if (ref_line.empty()) continue;
        Row ref_row = extractRow(splitCsv(ref_line), ref_hdr);
        if (ref_row.biz_index.empty()) continue;
        ++ref_total;

        uint32_t ref_tt = parseTickTime(ref_row.tick_time);

        // 把 decoded 里 TickTime ≤ ref_tt + ε 的行推入 pending
        while (dec_has_next) {
            Row dr = readDecRow();
            if (parseTickTime(dr.tick_time) > ref_tt + kTickEps) break;
            ++dec_total;
            pending[makeKey(dr.channel, dr.biz_index)] = std::move(dr);
            dec_has_next = (bool)std::getline(dec_file, dec_line);
        }

        // 在 pending 里查匹配
        auto it = pending.find(makeKey(ref_row.channel, ref_row.biz_index));
        if (it == pending.end()) {
            ++missing;
            if ((int)missing_samples.size() < kMaxSample)
                missing_samples.push_back(ref_row);
        } else {
            ++matched;
            if (compareRows(it->second, ref_row, stats)) ++all_correct;
            pending.erase(it);
        }

        // 每 100k 行清理 pending 里时间已远落后的行 (unmatched extra)
        if (ref_total % 100000 == 0) {
            uint32_t cutoff = ref_tt > 200 ? ref_tt - 200 : 0;
            for (auto it2 = pending.begin(); it2 != pending.end(); ) {
                if (parseTickTime(it2->second.tick_time) < cutoff) {
                    countExtra(std::move(it2->second));
                    it2 = pending.erase(it2);
                } else {
                    ++it2;
                }
            }
        }
    }

    // decoded 里 ref 结束后还有的行也算入 dec_total 和 extra
    while (dec_has_next) {
        Row dr = readDecRow();
        ++dec_total;
        pending[makeKey(dr.channel, dr.biz_index)] = std::move(dr);
        dec_has_next = (bool)std::getline(dec_file, dec_line);
    }
    for (auto& [k, r] : pending) countExtra(std::move(r));

    // ---- 输出报告 ----

    double hit_pct = ref_total > 0 ? 100.0 * matched / ref_total : 0.0;
    // 正确率基于命中行（更有意义：衡量"找到的那些解析对不对"）
    double correct_of_matched = matched > 0 ? 100.0 * all_correct / matched : 0.0;
    double correct_of_ref     = ref_total > 0 ? 100.0 * all_correct / ref_total : 0.0;

    std::cout << "\n=== 9/5803 验证结果 ===\n"
              << "参考总行数:              " << ref_total << "\n"
              << "解码总行数:              " << dec_total << "\n\n"
              << "命中 (key 匹配):         " << matched
              << "  命中率: " << std::fixed << std::setprecision(4) << hit_pct << "%\n"
              << "完全正确 / 命中:         " << all_correct << " / " << matched
              << "  命中中正确率: " << correct_of_matched << "%\n"
              << "完全正确 / 参考总:       " << all_correct << " / " << ref_total
              << "  总正确率: " << correct_of_ref << "%\n"
              << "缺失 (ref有dec无):       " << missing << "\n"
              << "多余 (dec有ref无):       " << extra   << "\n";

    std::cout << "\n--- 字段级错误 (命中行中) ---\n";
    bool any = false;
    for (int i = 0; i < kNumFields; ++i) {
        if (stats[i].mismatch > 0) {
            std::cout << "  " << kFieldNames[i] << ": " << stats[i].mismatch << " 处不一致\n";
            any = true;
        }
    }
    if (!any) std::cout << "  (无字段不一致)\n";

    bool any_ex = false;
    for (int i = 0; i < kNumFields; ++i) any_ex |= !stats[i].examples.empty();
    if (any_ex) {
        std::cout << "\n--- 每字段前5条不一致样例 (decoded vs ref，匹配键=Channel:BizIndex) ---\n";
        for (int i = 0; i < kNumFields; ++i) {
            if (stats[i].examples.empty()) continue;
            std::cout << "[" << kFieldNames[i] << "]\n";
            for (auto& ex : stats[i].examples)
                std::cout << "  decoded=" << ex.decoded << "  ref=" << ex.ref
                          << "  (Channel=" << ex.channel << " BizIndex=" << ex.biz_index << ")\n";
        }
    }

    if (!missing_samples.empty()) {
        std::cout << "\n--- 缺失行样例 (在 ref 中存在但 decoded 中找不到，前" << kMaxSample << "条) ---\n";
        for (auto& r : missing_samples)
            std::cout << "  Ch=" << r.channel << " Bi=" << r.biz_index
                      << " T=" << r.tick_time << " Type=" << r.type << "\n";
    }

    if (!extra_samples.empty()) {
        std::cout << "\n--- 多余行样例 (decoded 有但 ref 中找不到，前" << kMaxSample << "条) ---\n";
        for (auto& r : extra_samples)
            std::cout << "  Ch=" << r.channel << " Bi=" << r.biz_index
                      << " T=" << r.tick_time << " Type=" << r.type << "\n";
    }

    std::cout << "\n";
    return 0;
}
