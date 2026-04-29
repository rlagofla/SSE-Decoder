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
// 两个文件均按 TickTime 升序。验证算法: 时间窗口流式 merge-join，
// 内存占用 O(窗口内记录数) 而非 O(文件大小)。
//
// 比对字段 (列名匹配): SecurityID, TickTime, Type, BuyOrderNO, SellOrderNO,
//                      Price, Qty, TradeMoney, TickBSFlag
// 匹配键: (Channel, BizIndex)

#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

// ---- CSV 解析工具 ----

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

// 解析表头，返回列名→下标的映射
static std::unordered_map<std::string, int>
parseHeader(const std::string& line) {
    std::unordered_map<std::string, int> m;
    auto cols = splitCsv(line);
    for (int i = 0; i < (int)cols.size(); ++i)
        m[cols[i]] = i;
    return m;
}

// ---- 一条业务行 ----

struct Row {
    std::string biz_index;
    std::string channel;
    std::string tick_time;    // 用于窗口推进
    // 待比对字段
    std::string security_id;
    std::string type;
    std::string buy_order_no;
    std::string sell_order_no;
    std::string price;
    std::string qty;
    std::string trade_money;
    std::string bs_flag;
};

static std::string makeKey(const std::string& channel,
                            const std::string& biz_index) {
    return channel + ":" + biz_index;
}

// TickTime 字符串 → 整数 HHMMSSXX，方便比较大小和格式归一化。
// 支持:
//   "HH:MM:SS.XX"    (本项目输出, 2 位小数)
//   "HH:MM:SS.XXX"   (通联参考, 3 位小数, 实为 2 位百分秒末尾补 0)
//   "HHMMSSXX"       (原始整数)
static uint32_t parseTickTime(const std::string& s) {
    if (s.size() >= 11 && s[2] == ':' && s[5] == ':' && s[8] == '.') {
        auto num = [&](int pos, int len) -> uint32_t {
            uint32_t v = 0;
            for (int i = 0; i < len && pos + i < (int)s.size(); ++i)
                v = v * 10 + (s[pos + i] - '0');
            return v;
        };
        uint32_t hh = num(0,2), mm = num(3,2), ss = num(6,2), xx = num(9,2);
        return hh*1000000 + mm*10000 + ss*100 + xx;
    }
    try { return uint32_t(std::stoul(s)); } catch (...) { return 0; }
}

// 把 TickTime 字符串归一化为 "HH:MM:SS.XX" (2 位小数)，
// 用于字段比对，消除 ".63" vs ".630" 的格式差异。
static std::string normalizeTickTime(const std::string& s) {
    uint32_t t = parseTickTime(s);
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%02u:%02u:%02u.%02u",
                  t/1000000, (t/10000)%100, (t/100)%100, t%100);
    return buf;
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
    struct Example { std::string decoded, ref, biz_index, channel; };
    std::vector<Example> examples;  // 最多保存 5 条
};

static void recordMismatch(FieldStats& fs,
                            const std::string& dec_val,
                            const std::string& ref_val,
                            const std::string& biz_index,
                            const std::string& channel) {
    fs.mismatch++;
    if (fs.examples.size() < 5)
        fs.examples.push_back({dec_val, ref_val, biz_index, channel});
}

// ---- 从已解析行中提取字段 ----

static Row extractRow(const std::vector<std::string>& cols,
                      const std::unordered_map<std::string, int>& hdr) {
    auto get = [&](const char* name) -> std::string {
        auto it = hdr.find(name);
        if (it == hdr.end() || it->second >= (int)cols.size()) return "";
        return cols[it->second];
    };
    Row r;
    r.biz_index    = get("BizIndex");
    r.channel      = get("Channel");
    r.tick_time    = get("TickTime");
    r.security_id  = get("SecurityID");
    r.type         = get("Type");
    r.buy_order_no = get("BuyOrderNO");
    r.sell_order_no= get("SellOrderNO");
    r.price        = get("Price");
    r.qty          = get("Qty");
    r.trade_money  = get("TradeMoney");
    r.bs_flag      = get("TickBSFlag");
    return r;
}

static void compareRows(const Row& dec, const Row& ref,
                         FieldStats stats[kNumFields]) {
    auto cmp = [&](int idx, const std::string& d, const std::string& r) {
        if (d != r) recordMismatch(stats[idx], d, r, ref.biz_index, ref.channel);
    };
    cmp(0, dec.security_id,              ref.security_id);
    cmp(1, normalizeTickTime(dec.tick_time), normalizeTickTime(ref.tick_time));
    cmp(2, dec.type,                     ref.type);
    cmp(3, dec.buy_order_no,             ref.buy_order_no);
    cmp(4, dec.sell_order_no,            ref.sell_order_no);
    cmp(5, dec.price,                    ref.price);
    cmp(6, dec.qty,                      ref.qty);
    cmp(7, dec.trade_money,              ref.trade_money);
    cmp(8, dec.bs_flag,                  ref.bs_flag);
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

    // 读表头
    std::string dec_hdr_line, ref_hdr_line;
    if (!std::getline(dec_file, dec_hdr_line)) { std::cerr << "decoded CSV 为空\n"; return 1; }
    if (!std::getline(ref_file, ref_hdr_line)) { std::cerr << "reference CSV 为空\n"; return 1; }

    auto dec_hdr = parseHeader(dec_hdr_line);
    auto ref_hdr = parseHeader(ref_hdr_line);

    // 必须字段检查
    for (const char* f : {"BizIndex","Channel","TickTime"}) {
        if (!dec_hdr.count(f)) { std::cerr << "decoded CSV 缺少列: " << f << "\n"; return 1; }
        if (!ref_hdr.count(f)) { std::cerr << "reference CSV 缺少列: " << f << "\n"; return 1; }
    }

    // 滑动窗口: key(channel:bizindex) → decoded Row
    // ε = 1 tick (百分之一秒) 的容差
    constexpr uint32_t kTickEps = 1;

    std::unordered_map<std::string, Row> pending;  // decoded 行缓冲
    pending.reserve(8192);

    FieldStats stats[kNumFields];
    int64_t ref_total   = 0;
    int64_t dec_total   = 0;
    int64_t matched     = 0;
    int64_t all_correct = 0;
    int64_t missing     = 0;

    // 存储 missing/extra 样例
    constexpr int kMaxSample = 10;
    std::vector<Row> missing_samples, extra_samples;

    // decoded 文件游标 (逐行预读)
    std::string dec_line;
    bool dec_has_next = (bool)std::getline(dec_file, dec_line);

    auto readDecRow = [&]() -> Row {
        auto cols = splitCsv(dec_line);
        return extractRow(cols, dec_hdr);
    };

    // 流式处理参考文件
    std::string ref_line;
    while (std::getline(ref_file, ref_line)) {
        if (ref_line.empty()) continue;
        auto ref_cols = splitCsv(ref_line);
        Row ref_row = extractRow(ref_cols, ref_hdr);
        if (ref_row.biz_index.empty()) continue;
        ++ref_total;

        uint32_t ref_tt = parseTickTime(ref_row.tick_time);

        // 把 decoded 里 TickTime ≤ ref_tt + ε 的行都推入 pending
        while (dec_has_next) {
            Row dr = readDecRow();
            uint32_t dt = parseTickTime(dr.tick_time);
            if (dt > ref_tt + kTickEps) break;
            ++dec_total;
            std::string key = makeKey(dr.channel, dr.biz_index);
            pending[key] = std::move(dr);
            dec_has_next = (bool)std::getline(dec_file, dec_line);
        }

        // 查找匹配
        std::string key = makeKey(ref_row.channel, ref_row.biz_index);
        auto it = pending.find(key);
        if (it == pending.end()) {
            ++missing;
            if ((int)missing_samples.size() < kMaxSample)
                missing_samples.push_back(ref_row);
        } else {
            ++matched;
            bool ok = true;
            // 比对字段
            const Row& dr = it->second;
            int before = 0;
            for (int i = 0; i < kNumFields; ++i) before += (stats[i].mismatch > 0 ? 0 : 0); // dummy
            int64_t err_before = 0;
            for (auto& s : stats) err_before += s.mismatch;
            compareRows(dr, ref_row, stats);
            int64_t err_after = 0;
            for (auto& s : stats) err_after += s.mismatch;
            if (err_after == err_before) ++all_correct;
            pending.erase(it);
        }

        // 定期清理 pending 中远落后的 decoded 行 (TickTime << ref_tt)
        // 避免内存无限增长 (偶发乱序导致的孤儿行)
        if (ref_total % 100000 == 0) {
            uint32_t cutoff = (ref_tt > 200) ? ref_tt - 200 : 0;
            for (auto it2 = pending.begin(); it2 != pending.end(); ) {
                if (parseTickTime(it2->second.tick_time) < cutoff) {
                    if ((int)extra_samples.size() < kMaxSample)
                        extra_samples.push_back(it2->second);
                    it2 = pending.erase(it2);
                } else {
                    ++it2;
                }
            }
        }
    }

    // 把 decoded 文件剩余行都收进来 (在 ref 文件末尾之后的 decoded 行)
    while (dec_has_next) {
        Row dr = readDecRow();
        ++dec_total;
        std::string key = makeKey(dr.channel, dr.biz_index);
        pending[key] = std::move(dr);
        dec_has_next = (bool)std::getline(dec_file, dec_line);
    }

    // pending 里剩余的都是 extra (decoded 有，ref 没有)
    int64_t extra = int64_t(pending.size());
    for (auto& [k, r] : pending) {
        if ((int)extra_samples.size() < kMaxSample)
            extra_samples.push_back(r);
    }

    // ---- 输出报告 ----

    double hit_pct     = ref_total > 0 ? 100.0 * matched     / ref_total : 0.0;
    double correct_pct = ref_total > 0 ? 100.0 * all_correct / ref_total : 0.0;

    std::cout << "\n=== 9/5803 验证结果 ===\n"
              << "参考总行数:          " << ref_total   << "\n"
              << "解码总行数:          " << dec_total   << "\n\n"
              << "命中 (key 匹配):     " << matched
              << "  命中率: " << std::fixed << std::setprecision(4) << hit_pct << "%\n"
              << "完全正确:            " << all_correct
              << "  总正确率: " << correct_pct << "%\n"
              << "缺失 (ref有dec无):   " << missing    << "\n"
              << "多余 (dec有ref无):   " << extra      << "\n";

    std::cout << "\n--- 字段级错误 (命中行中) ---\n";
    for (int i = 0; i < kNumFields; ++i) {
        if (stats[i].mismatch > 0)
            std::cout << "  " << kFieldNames[i] << ": " << stats[i].mismatch << " 处不一致\n";
    }
    bool any_field_err = false;
    for (auto& s : stats) if (s.mismatch > 0) { any_field_err = true; break; }
    if (!any_field_err) std::cout << "  (无字段不一致)\n";

    std::cout << "\n--- 每字段前5条不一致样例 ---\n";
    for (int i = 0; i < kNumFields; ++i) {
        if (stats[i].examples.empty()) continue;
        std::cout << "[" << kFieldNames[i] << "]\n";
        for (auto& ex : stats[i].examples) {
            std::cout << "  decoded=" << ex.decoded
                      << "  ref="     << ex.ref
                      << "  BizIndex=" << ex.biz_index
                      << "  Channel="  << ex.channel << "\n";
        }
    }

    if (!missing_samples.empty()) {
        std::cout << "\n--- 缺失行样例 (前" << kMaxSample << "条) ---\n";
        for (auto& r : missing_samples) {
            std::cout << "  BizIndex=" << r.biz_index
                      << " Channel=" << r.channel
                      << " TickTime=" << r.tick_time
                      << " Type=" << r.type << "\n";
        }
    }

    if (!extra_samples.empty()) {
        std::cout << "\n--- 多余行样例 (前" << kMaxSample << "条) ---\n";
        for (auto& r : extra_samples) {
            std::cout << "  BizIndex=" << r.biz_index
                      << " Channel=" << r.channel
                      << " TickTime=" << r.tick_time
                      << " Type=" << r.type << "\n";
        }
    }

    std::cout << "\n";
    return 0;
}
