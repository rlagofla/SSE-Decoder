#pragma once
// 9_5803_struct.hpp — 上交所 (9, 5803) 通道逐笔行情 (成交 + 委托 混合) 结构
//
// 通道身份确认: 参考《上海证券交易所LDDS系统竞价Level-2行情接口说明书》v2.0.8
// (2023/03/13), 本通道模板 5803 是 UA5801 (逐笔委托) + UA3201 (逐笔成交) 合并后
// 的统一流, 每条记录通过 1B ASCII Action 字符 ('A'/'D'/'T'/'C') 区分事件类型。
//
// ---- 字节层结构 ----
//
//   PMAP          (1B, MSB=1 停止) —— 7 bit 位图, 控制后续 copy/default 字段是否出现
//   TemplateID    (2B FAST = 5803, 即 `2d ab`)
//   [BizIndex]    (FAST u64 mandatory, 业务序列号) —— 帧首记录出现
//   [Channel]     (FAST u32 mandatory, 通道号)     —— 帧首记录出现
//   [SecurityID]  (6B ASCII, 前 5 字节 '0'..'9' MSB=0, 第 6 字节 MSB=1)
//                                                   —— 首次 + 证券切换时出现
//   [OrderTime]   (FAST u32 **nullable**, 行情时间 HHMMSSXX, e.g. 9535063 = 09:53:50.63)
//   [Action]      (1B FAST char, 'T'/'A'/'D'/'C')   —— 缺失则继承上一条
//   中间 FAST 整数序列 (随 Action 不同):
//     'A' (新增委托):  OrderNO(u64 null), Price(u32 null ×1000), Qty(u64 null ×1000),
//                     TradeMoney(u64 null ×1e5, 恒为 0, 有时省略)
//     'D' (撤单):      OrderNO(u64 null), Price(u32 null ×1000), Qty(u64 null ×1000)
//     'C' (取消):      同 'D'
//     'T' (成交):      BidApplSeq(u64 null), TradeApplSeq/OfferApplSeq(u64 null),
//                     Price(u32 null ×1000), Qty(u64 null ×1000), TradeMoney(u64 null ×1e5)
//   BSFlag        (1B FAST char, 'B' / 'S' / 'N', 编码值 0xC2 / 0xD3 / 0xCE)
//   ExtCode       (1B RAW, 取值 'A'/'H'/'I'/'J'/'K'/'N' 等, 可能是帧尾分类字节)
//
// ---- FAST nullable 关键规则 ----
//
// 所有标注 "null" 的字段是 FAST 可空整数: 编码值 V 表示
//   V == 0x80 (编码 0, stop 置位)  →  NULL / 缺省
//   V >  0                         →  真实值 = V - 1
// 所以 pcap 里的原始值一律比 CSV 业务数值大 1, 这是编码, 不是 off-by-one bug。
//
// ---- 价格/数量精度 ----
//
//   Price       : STEP 三位小数 "6.330" → FAST 存整数 6330 → nullable 编码 6331
//   Qty         : STEP 三位小数 "1100.000" (实际 1100 股) → FAST 存 1100000 → 编码 1100001
//   TradeMoney  : STEP 五位小数 "73716.34000" → FAST 存 7371634000 → 编码 7371634001

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace sse95803 {

// FAST stop-bit 变长无符号整数解码。
// 返回 {value, 消耗字节数}; 未遇 stop-bit 则返回 {acc, 0}。
inline std::pair<uint64_t, size_t> readFast(const uint8_t* p, size_t n) {
    uint64_t v = 0;
    for (size_t i = 0; i < n; ++i) {
        v = (v << 7) | uint64_t(p[i] & 0x7F);
        if (p[i] & 0x80) return {v, i + 1};
    }
    return {v, 0};
}

// 识别 6 字节 ASCII 证券代码: 前 5 字节 '0'..'9' (MSB=0), 第 6 字节 MSB=1 且低 7bit 为 '0'..'9'。
inline bool tryReadAsciiSecID(const uint8_t* p, size_t n, std::string& out) {
    if (n < 6) return false;
    for (size_t i = 0; i < 5; ++i) {
        uint8_t b = p[i];
        if (b < 0x30 || b > 0x39) return false;
    }
    uint8_t last = p[5];
    if (!(last & 0x80)) return false;
    uint8_t lc = last & 0x7F;
    if (lc < 0x30 || lc > 0x39) return false;
    out.assign(reinterpret_cast<const char*>(p), 5);
    out.push_back(char(lc));
    return true;
}

// 一条记录的解析结果 (不拷贝源字节, 仅保存 raw 指针)
struct TickRecord {
    const uint8_t* raw     = nullptr;
    size_t         raw_len = 0;

    uint8_t   pmap        = 0;
    uint64_t  template_id = 0;  // 期望 = 5803

    // SecurityID: 若 has_security_id=false 则 security_id 来自继承
    bool         has_security_id = false;
    std::string  security_id;

    // Action: 若 has_action=false 则 action 来自继承
    bool  has_action = false;
    char  action     = 0;  // 'T' / 'A' / 'D' / 'C' / 0

    // 帧级前导字段 (仅首条记录有, 位于 TID~SecID 或 SecID~Action 之间)
    std::vector<uint64_t> prefix_ints;
    std::vector<size_t>   prefix_widths;

    // 中间 FAST int 字段 (位于 Action 之后, 尾部之前)
    std::vector<uint64_t> ints;
    std::vector<size_t>   widths;

    // 尾部
    bool    has_bs_flag = false;
    char    bs_flag     = 0;  // 'B' / 'S' / 'N'
    bool    has_ext     = false;
    uint8_t ext_code    = 0;
};

// 按 `2d ab` TID 标记拆解码后 body 为一条条 TickRecord
class TickStreamParser {
public:
    TickStreamParser(const uint8_t* body, size_t len)
        : body_(body), len_(len) {
        // 这里意思是说，TID 是 Template id，这个5803正好也是sub channel，表示就是逐条行情的template，按照这个tid解析后面的字段

        // 扫 2d ab (= TID=5803 的 FAST 编码). 要求:
        //   1. i >= 1 (前面得有 PMAP 字节)
        //   2. body[i-1] 必须是 FAST stop-bit 字节 (MSB=1), 这是 PMAP 的基本要求
        //   3. 与上一个 tid_pos_ 至少间隔 14B (最短合法记录体量)
        // 以上三条能过滤绝大多数"字段值 = 5803"导致的伪 TID 命中。
        for (size_t i = 1; i + 1 < len_; ++i) {
            if (body_[i] != 0x2d || body_[i + 1] != 0xab) continue;
            if (!(body_[i - 1] & 0x80)) continue;
            if (!tid_pos_.empty() && i - tid_pos_.back() < 14) continue;
            tid_pos_.push_back(i);
        }
    }

    size_t record_count() const { return tid_pos_.size(); }

    // 解析第 idx 条记录 (从 0 开始)。会继承前一条的 SecID/Action。
    bool parse(size_t idx, TickRecord& rec) {
        rec = TickRecord{};  // 清空
        if (idx >= tid_pos_.size()) return false;

        size_t tid = tid_pos_[idx];
        if (tid == 0) return false;

        // PMAP 固定 1 字节, 位于 TID 前一个字节
        size_t start = tid - 1;

        // 记录末尾 = 下一条 PMAP 位置 (1B), 或 body 末尾
        size_t end = (idx + 1 < tid_pos_.size())
                         ? (tid_pos_[idx + 1] - 1)
                         : len_;
        if (end <= start + 3) return false;

        rec.raw     = body_ + start;
        rec.raw_len = end - start;

        rec.pmap = body_[start];

        auto [tv, tn] = readFast(body_ + start + 1, rec.raw_len - 1);
        if (tn == 0) return false;
        rec.template_id = tv;

        size_t off = 1 + tn;  // 相对 start 的偏移

        // 尝试 6B ASCII SecID。
        // 一般记录 SecID 紧随 TID; 但每帧首条可能有帧级前导 FAST 字段 (frame seq / flag),
        // 这里允许跳过 0~3 个前导 FAST 字段再找 ASCII SecID。
        std::string sid;
        size_t scan_off = off;
        for (int attempt = 0; attempt < 4 && scan_off + 6 <= rec.raw_len; ++attempt) {
            if (tryReadAsciiSecID(body_ + start + scan_off,
                                  rec.raw_len - scan_off, sid)) {
                // 保存前导 FAST 字段 (仅帧首记录存在)
                size_t cursor = off;
                while (cursor < scan_off) {
                    auto [v, w] = readFast(body_ + start + cursor,
                                           scan_off - cursor);
                    if (w == 0) break;
                    rec.prefix_ints.push_back(v);
                    rec.prefix_widths.push_back(w);
                    cursor += w;
                }
                rec.has_security_id = true;
                rec.security_id     = sid;
                off = scan_off + 6;
                cur_sec_ = sid;
                break;
            }
            auto [v, w] = readFast(body_ + start + scan_off,
                                   rec.raw_len - scan_off);
            if (w == 0) break;
            scan_off += w;
        }
        if (!rec.has_security_id) {
            rec.security_id = cur_sec_;
        }

        // 探测尾部: 优先匹配 2B tail [BSFlag + ExtCode], 否则看末尾 1B 是 BSFlag 还是 ExtCode
        size_t tail_len = 0;
        auto isBSChar = [](uint8_t b) {
            if (!(b & 0x80)) return false;
            uint8_t c = b & 0x7F;
            return c == 'B' || c == 'S' || c == 'N';
        };
        if (rec.raw_len >= off + 2) {
            uint8_t last   = body_[start + rec.raw_len - 1];
            uint8_t second = body_[start + rec.raw_len - 2];
            if (isBSChar(second)) {
                rec.has_bs_flag = true;
                rec.bs_flag     = char(second & 0x7F);
                rec.has_ext     = true;
                rec.ext_code    = last;
                tail_len        = 2;
            } else if (isBSChar(last)) {
                // 短记录: 只有 BSFlag, 没有 ExtCode
                rec.has_bs_flag = true;
                rec.bs_flag     = char(last & 0x7F);
                tail_len        = 1;
            } else if (rec.raw_len >= off + 1) {
                rec.has_ext  = true;
                rec.ext_code = last;
                tail_len     = 1;
            }
        }

        // 尝试 Action (紧随 SecID); 允许跳过 0~2 个前导 FAST 字段
        // (首条记录 SecID 和 Action 之间可能有额外帧级字段)
        {
            size_t scan_off = off;
            for (int attempt = 0; attempt < 3 && scan_off < rec.raw_len - tail_len;
                 ++attempt) {
                uint8_t b = body_[start + scan_off];
                if ((b & 0x80)) {
                    uint8_t c = b & 0x7F;
                    if (c == 'T' || c == 'A' || c == 'D' || c == 'C') {
                        // SecID 与 Action 之间的跳过字段也归为帧级前导
                        size_t cursor = off;
                        while (cursor < scan_off) {
                            auto [v, w] = readFast(body_ + start + cursor,
                                                   scan_off - cursor);
                            if (w == 0) break;
                            rec.prefix_ints.push_back(v);
                            rec.prefix_widths.push_back(w);
                            cursor += w;
                        }
                        rec.has_action = true;
                        rec.action     = char(c);
                        off = scan_off + 1;
                        cur_action_ = rec.action;
                        break;
                    }
                }
                auto [v, w] = readFast(body_ + start + scan_off,
                                       rec.raw_len - tail_len - scan_off);
                if (w == 0) break;
                scan_off += w;
            }
        }
        if (!rec.has_action) rec.action = cur_action_;

        // 中间 FAST 整数字段 (直到 mid_end)
        size_t mid_end = rec.raw_len - tail_len;
        while (off < mid_end) {
            auto [v, w] = readFast(body_ + start + off, mid_end - off);
            if (w == 0) break;
            rec.ints.push_back(v);
            rec.widths.push_back(w);
            off += w;
        }
        return true;
    }

private:
    const uint8_t*      body_;
    size_t              len_;
    std::vector<size_t> tid_pos_;
    std::string         cur_sec_;
    char                cur_action_ = 0;
};

// ---- 业务层解码 ----
//
// TickBusiness: 一条记录的业务语义, 字段名对齐通联 CSV (mdl_4_24_0.csv):
//   BizIndex, Channel, SecurityID, TickTime, Type,
//   BuyOrderNO, SellOrderNO, Price, Qty, TradeMoney, TickBSFlag, ExtCode
struct TickBusiness {
    uint64_t    biz_index  = 0;     // 业务序号 (与 CSV BizIndex 对齐)
    uint32_t    channel    = 0;     // 通道号
    std::string security_id;        // "601106" etc
    uint32_t    tick_time  = 0;     // HHMMSSXX, 9535063 = 09:53:50.63
    char        type       = 0;     // 'A'/'D'/'T'/'C'
    uint64_t    buy_order_no  = 0;  // 'A'/'D'+BS='B' 填此, 'T' 填 BidApplSeq
    uint64_t    sell_order_no = 0;  // 'A'/'D'+BS='S' 填此, 'T' 填 OfferApplSeq
    int64_t     price_e3   = 0;     // Price × 1000 (STEP 三位小数的整数表达)
    int64_t     qty_e3     = 0;     // Qty   × 1000
    int64_t     money_e5   = 0;     // TradeMoney × 10^5
    char        bs_flag    = 0;     // 'B'/'S'/'N'
    uint8_t     ext_code   = 0;     // ExtCode 原始字节
    bool        valid      = false; // 解码成功
};

// FAST nullable 解码: V==0 → NULL (is_null=true), 否则 V-1
inline std::pair<uint64_t, bool> decNull(uint64_t enc) {
    if (enc == 0) return {0, true};
    return {enc - 1, false};
}

// 跨记录状态, 承载 increment/copy 操作符继承
struct BusinessState {
    uint64_t last_biz_index = 0;
    uint32_t last_channel   = 0;
    uint32_t last_tick_time = 0;
    // SecurityID 和 Action 的继承由 TickStreamParser 内部处理
};

// 按 Action 约定返回中间字段预期数量 ('A' 可为 3 或 4, 'D'/'C' 为 3, 'T' 为 5)
inline size_t expectedMiddleCount(char action, size_t avail) {
    switch (action) {
        case 'A': return (avail >= 4) ? 4 : 3;
        case 'D':
        case 'C': return 3;
        case 'T': return 5;
        default:  return 0;
    }
}

// 把原始 TickRecord 映射到业务字段。返回 false 表示记录无效 (phantom / 截断), 此时不会触动
// BusinessState (调用方应该把这条记录当不存在, 不要计入下一条的 +1)。
inline bool decodeBusiness(const TickRecord& rec, BusinessState& st, TickBusiness& out) {
    out = TickBusiness{};
    out.security_id = rec.security_id;
    out.bs_flag     = rec.bs_flag;
    out.ext_code    = rec.ext_code;
    out.type        = rec.action;

    // Action 继承 (wire 里没有 Action 字节) 时, TickTime 可能会流入 middle_ints 的前端。
    // 按 Action 模板期望数量反推: 超出的前 k 个中间 int 其实是前导字段。
    std::vector<uint64_t> prefix_ints = rec.prefix_ints;
    std::vector<uint64_t> middle_ints(rec.ints.begin(), rec.ints.end());
    if (!rec.has_action && rec.action) {
        size_t want = expectedMiddleCount(rec.action, middle_ints.size());
        while (want > 0 && middle_ints.size() > want) {
            prefix_ints.push_back(middle_ints.front());
            middle_ints.erase(middle_ints.begin());
        }
    }

    // 先做合法性检查: Action 和 MiddleInts 数量必须匹配模板, 否则直接返回 false
    // 不要先改 st 再失败, 否则会串到下一条记录。
    auto want_middle = [&]() -> size_t {
        switch (rec.action) {
            case 'A': return (middle_ints.size() >= 4) ? 4 : 3;
            case 'D':
            case 'C': return 3;
            case 'T': return 5;
            default:  return 0;
        }
    };
    size_t want = want_middle();
    if (want == 0 || middle_ints.size() < want) return false;

    // --- 继承 / 帧级前导字段 ---
    // 线缆字段顺序: (BizIndex, Channel, TickTime) 三个字段各占 PMAP 一位。
    // 实测本通道的出现组合只有 {∅, {TickTime}, {三者全}}, 没观察到单独 Channel。
    // 推断 PMAP 位逻辑: 三位各自控制一个字段是否显式出现, 省略则按操作符继承:
    //   BizIndex  (mandatory + increment): 省略 → 上条 +1
    //   Channel   (mandatory + Copy      ): 省略 → 继承上条
    //   TickTime  (nullable  + Copy      ): 省略 → 继承上条; 显式出现还要 -1 (nullable)
    // 按 prefix_ints 条数分派 (n=2 情况尚未实测, 暂按 [Channel, TickTime] 处理):
    size_t n = prefix_ints.size();
    auto applyTickTime = [&](uint64_t enc) {
        auto [t, is_null] = decNull(enc);
        if (!is_null) {
            out.tick_time = uint32_t(t);
            st.last_tick_time = out.tick_time;
        } else {
            out.tick_time = st.last_tick_time;
        }
    };
    switch (n) {
        case 3:
            out.biz_index = prefix_ints[0];
            out.channel   = uint32_t(prefix_ints[1]);
            st.last_biz_index = out.biz_index;
            st.last_channel   = out.channel;
            applyTickTime(prefix_ints[2]);
            break;
        case 2:
            out.biz_index = ++st.last_biz_index;
            out.channel   = uint32_t(prefix_ints[0]);
            st.last_channel = out.channel;
            applyTickTime(prefix_ints[1]);
            break;
        case 1:
            out.biz_index = ++st.last_biz_index;
            out.channel   = st.last_channel;
            applyTickTime(prefix_ints[0]);
            break;
        default:
            out.biz_index = ++st.last_biz_index;
            out.channel   = st.last_channel;
            out.tick_time = st.last_tick_time;
            break;
    }

    // --- 业务字段 ---
    const auto& m = middle_ints;
    auto getN = [&](size_t idx) -> uint64_t {
        if (idx >= m.size()) return 0;
        auto [v, is_null] = decNull(m[idx]);
        return is_null ? 0 : v;
    };

    switch (rec.action) {
        case 'A':
        case 'D':
        case 'C': {
            uint64_t order_no = getN(0);
            out.price_e3 = int64_t(getN(1));
            out.qty_e3   = int64_t(getN(2));
            if (want >= 4) out.money_e5 = int64_t(getN(3)) * 100;  // ×10^3 → ×10^5 对齐
            if (rec.bs_flag == 'B') out.buy_order_no = order_no;
            else                    out.sell_order_no = order_no;
            break;
        }
        case 'T': {
            out.buy_order_no  = getN(0);
            out.sell_order_no = getN(1);
            out.price_e3      = int64_t(getN(2));
            out.qty_e3        = int64_t(getN(3));
            out.money_e5      = int64_t(getN(4));
            break;
        }
        default:
            return false;
    }
    out.valid = true;
    return true;
}

// 格式化辅助
inline std::string fmtDecFixed(int64_t v, int digits) {
    // v 是整数形式的 "×10^digits" 定点数, 输出 "X.XXX" (三位小数) 或 "X.XXXXX" (五位)
    if (digits <= 0) {
        char b[32];
        std::snprintf(b, sizeof(b), "%lld", (long long)v);
        return b;
    }
    int64_t scale = 1;
    for (int i = 0; i < digits; ++i) scale *= 10;
    int64_t hi = v / scale, lo = v % scale;
    if (lo < 0) lo = -lo;
    char fmt[32], buf[64];
    std::snprintf(fmt, sizeof(fmt), "%%lld.%%0%dlld", digits);
    std::snprintf(buf, sizeof(buf), fmt, (long long)hi, (long long)lo);
    return buf;
}

inline std::string fmtTickTime(uint32_t t) {
    // HHMMSSXX (XX=百分之一秒) → "HH:MM:SS.XX"
    uint32_t xx = t % 100;
    uint32_t ss = (t / 100) % 100;
    uint32_t mm = (t / 10000) % 100;
    uint32_t hh = t / 1000000;
    char b[16];
    std::snprintf(b, sizeof(b), "%02u:%02u:%02u.%02u", hh, mm, ss, xx);
    return b;
}

}  // namespace sse95803
