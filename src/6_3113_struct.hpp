#pragma once
// 6_3113_struct.hpp — 上交所 (6, 3113) 通道单指数快照结构
//
// 抓包观测：body 明文 FAST stop-bit 变长整数编码
// (每字节 7bit 数据，MSB=1 表示字段结束)。
// 单帧承载一条指数, 共 13 个字段; 总字节数随值大小在 40B~57B 之间浮动:
//
//   idx  字段                          说明 (宽度随值变化)
//    1   header_a                      观测恒定 (典型 14332), 作用待定
//    2   template_id                   = 3113 (和外层 channel_lo 相同)
//    3   update_time                   HHMMSS 六位十进制 (如 95351 = 09:53:51)
//    4   security_id                   6 位 ASCII (如 "000001")
//    5   last_px                       最新价 (×10^-5)
//    6   px_b                          疑似前收 PreClose (×10^-5)
//    7   total_volume                  总成交量
//    8   px_c                          价格字段 (×10^-5)
//    9   px_d                          观测恒等于 px_b (×10^-5)
//   10   px_e                          价格字段 (×10^-5)
//   11   field_f                       同批次多帧间常量 (典型 9535090)
//   12   total_value                   疑似总成交额
//   13   flag                          观测 = 1
//
// 注：px_c / px_d / px_e 的精确语义 (开/高/低/均价) 需交易所 FAST 模板才能钉死，
// 但数值本身可直接读出。

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

namespace sse63113 {

// FAST stop-bit 变长无符号整数解码
// 返回 {value, 消耗字节数}; 未遇到 stop-bit 则返回 {0, 0} 表示失败
inline std::pair<uint64_t, size_t> readFast(const uint8_t* p, size_t maxlen) {
    uint64_t v = 0;
    for (size_t i = 0; i < maxlen; ++i) {
        uint8_t b = p[i];
        v = (v << 7) | uint64_t(b & 0x7F);
        if (b & 0x80) return {v, i + 1};
    }
    return {0, 0};
}

// 定位下一个 stop-bit 字节, 返回包含它在内的字段长度; 0 表示越界未找到
inline size_t scanFastLen(const uint8_t* p, size_t maxlen) {
    for (size_t i = 0; i < maxlen; ++i)
        if (p[i] & 0x80) return i + 1;
    return 0;
}

// (6, 3113) 单指数快照 view，不拷贝字节，仅持有 raw_ 指针 + 长度
class IndexSnapshotView {
public:
    static constexpr size_t kMaxSize = 57;   // 观测到的最大 body 长度, 仅作参考
    static constexpr size_t kMinSize = 40;   // 观测到的最小 body 长度

    IndexSnapshotView(const uint8_t* p, size_t n) : raw_(p), n_(n) {
        parsed_ = parse();
    }

    bool   valid()        const { return parsed_; }
    size_t consumedSize() const { return consumed_; }

    uint64_t header_a()    const { return f1_; }
    uint64_t template_id() const { return f2_; }              // 恒 = 3113
    uint32_t update_time() const { return uint32_t(f3_); }    // HHMMSS

    // 6 位 ASCII 证券代码；每字节取低 7bit 即原字符
    std::string security_id() const {
        std::string s;
        s.reserve(sec_n_);
        for (size_t i = 0; i < sec_n_; ++i)
            s.push_back(char(raw_[sec_off_ + i] & 0x7F));
        return s;
    }

    uint64_t last_px()      const { return last_px_; }
    uint64_t px_b()         const { return px_b_; }
    uint64_t total_volume() const { return total_vol_; }
    uint64_t px_c()         const { return px_c_; }
    uint64_t px_d()         const { return px_d_; }
    uint64_t px_e()         const { return px_e_; }
    uint64_t field_f()      const { return field_f_; }
    uint64_t total_value()  const { return total_val_; }
    uint64_t flag()         const { return flag_; }

private:
    bool parse() {
        if (n_ < kMinSize) return false;

        size_t off = 0;
        auto step = [&](uint64_t& out) {
            auto [v, w] = readFast(raw_ + off, n_ - off);
            if (w == 0) return false;
            out = v;
            off += w;
            return true;
        };

        if (!step(f1_))  return false;
        if (!step(f2_))  return false;
        if (!step(f3_))  return false;

        size_t sn = scanFastLen(raw_ + off, n_ - off);
        if (sn == 0) return false;
        sec_off_ = off;
        sec_n_   = sn;
        off     += sn;

        if (!step(last_px_))   return false;
        if (!step(px_b_))      return false;
        if (!step(total_vol_)) return false;
        if (!step(px_c_))      return false;
        if (!step(px_d_))      return false;
        if (!step(px_e_))      return false;
        if (!step(field_f_))   return false;
        if (!step(total_val_)) return false;
        if (!step(flag_))      return false;

        consumed_ = off;
        return off <= n_;
    }

    const uint8_t* raw_;
    size_t         n_;
    bool           parsed_   = false;
    size_t         consumed_ = 0;
    size_t         sec_off_  = 0;
    size_t         sec_n_    = 0;
    uint64_t       f1_ = 0, f2_ = 0, f3_ = 0;
    uint64_t       last_px_  = 0, px_b_ = 0, total_vol_ = 0;
    uint64_t       px_c_     = 0, px_d_ = 0, px_e_      = 0;
    uint64_t       field_f_  = 0, total_val_ = 0, flag_ = 0;
};

}  // namespace sse63113
