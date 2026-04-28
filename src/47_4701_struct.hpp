#pragma once
// 47_4701_struct.hpp — 上交所 (47, 4701) 通道的 M101 / M201 消息结构
//
// 基于对 data/output.pcap 中该通道的逆向分析。所有数值字段均为大端 (BE)，
// 字符串字段为 ASCII 或 GBK (Symbol)。每条结构以"view"形式给出，持有原始
// 字节指针 + 长度，不做拷贝，读访问时现场转字节序。
//
// 通道广播分布（根据抓包统计）：
//   每条 TCP 流内 99.95% 是 M201（L2 聚合快照，ZIP 压缩），其余少量是
//   M101（交易阶段状态通知，48B 明文，阶段切换时发一帧）。

#include <cstdint>
#include <cstring>
#include <string_view>

namespace sse {

// -------- 大端读取 --------

inline uint16_t readBE16(const uint8_t* p) {
    return (uint16_t(p[0]) << 8) | uint16_t(p[1]);
}
inline uint32_t readBE32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) <<  8) |  uint32_t(p[3]);
}
inline uint64_t readBE64(const uint8_t* p) {
    return (uint64_t(readBE32(p)) << 32) | uint64_t(readBE32(p + 4));
}

// ================================================================
// M101: 交易阶段状态通知 (48B 明文, 不压缩)
// 对应 FIX h = TradingSessionStatus 的盛立 ODP 变体。
// 每当市场阶段变化 (如 T111 连续竞价 → T100 开盘前) 时广播一帧。
// ----------------------------------------------------------------
//   off  len  field              备注
//    0    4   total_len          = 48
//    4    4   label              "M101"
//    8    8   sending_time       同 M201 时间戳编码
//   16    8   msg_seq_num
//   24    4   const_c73f         = 0x0000C73F
//   28    4   category           = 0x00000103
//   32    8   trading_phase      ASCII，"T100    ""T111    ""T118    ""T200    "
//   40    4   counter1           含义待定 (累计帧数或涉及证券数)
//   44    4   counter2           同上
// ================================================================

class M101View {
public:
    static constexpr size_t kSize = 48;

    M101View(const uint8_t* p, size_t n) : raw_(p), n_(n) {}

    bool valid() const {
        return n_ >= kSize && std::memcmp(raw_ + 4, "M101", 4) == 0;
    }

    uint32_t         total_len()     const { return readBE32(raw_ + 0);  }
    std::string_view label()         const { return {rcp(raw_ + 4),  4}; }
    uint64_t         sending_time()  const { return readBE64(raw_ + 8);  }
    uint64_t         msg_seq_num()   const { return readBE64(raw_ + 16); }
    uint32_t         const_c73f()    const { return readBE32(raw_ + 24); }
    uint32_t         category()      const { return readBE32(raw_ + 28); }
    std::string_view trading_phase() const { return {rcp(raw_ + 32), 8}; }
    uint32_t         counter1()      const { return readBE32(raw_ + 40); }
    uint32_t         counter2()      const { return readBE32(raw_ + 44); }

private:
    static const char* rcp(const uint8_t* p) {
        return reinterpret_cast<const char*>(p);
    }
    const uint8_t* raw_;
    size_t         n_;
};

// ================================================================
// M201: L2 聚合快照包 (变长, 通常 ZIP 压缩传输)
// 结构: 49B 固定包头 + no_entries × 变长证券 entry。
// ----------------------------------------------------------------
// 固定包头 (49B):
//   off  len  field
//    0    4   total_len       含自身, 等于解压后总字节数
//    4    4   label           "M201"
//    8    8   sending_time
//   16    8   msg_seq_num
//   24    4   const_c73f      = 0x0000C73F
//   28    4   category        = 0x00000103 (和 M101 相同)
//   32    8   zero_pad        全 0
//   40    4   trade_date      十进制形式, 如 20260114
//   44    3   marker          "000"
//   47    2   no_entries      本帧内证券条数
// ================================================================

class M201Header {
public:
    static constexpr size_t kSize = 49;

    M201Header(const uint8_t* p, size_t n) : raw_(p), n_(n) {}

    bool valid() const {
        return n_ >= kSize && std::memcmp(raw_ + 4, "M201", 4) == 0;
    }

    uint32_t         total_len()    const { return readBE32(raw_ + 0);  }
    std::string_view label()        const { return {rcp(raw_ + 4),  4}; }
    uint64_t         sending_time() const { return readBE64(raw_ + 8);  }
    uint64_t         msg_seq_num()  const { return readBE64(raw_ + 16); }
    uint32_t         const_c73f()   const { return readBE32(raw_ + 24); }
    uint32_t         category()     const { return readBE32(raw_ + 28); }
    uint32_t         trade_date()   const { return readBE32(raw_ + 40); }
    std::string_view marker()       const { return {rcp(raw_ + 44), 3}; }
    uint16_t         no_entries()   const { return readBE16(raw_ + 47); }

private:
    static const char* rcp(const uint8_t* p) {
        return reinterpret_cast<const char*>(p);
    }
    const uint8_t* raw_;
    size_t         n_;
};

// ================================================================
// M201 证券条目 (SecurityEntry): 69B 固定部分 + no_md_entries × 19B MDEntry
// ----------------------------------------------------------------
// 固定部分 (69B):
//   off  len  field
//    0    1   security_type       01 / 00 等
//    1    1   record_tag          0x4F / 0xF0 等 (厂商内部分类)
//    2    5   md_stream_id        ASCII "MD002"
//    7    8   security_id         ASCII, 6 位代码 + 右补空格 "600031  "
//   15    8   symbol              GBK, 4 汉字 (*ST 品种为 "*ST岩石")
//   23    8   pre_close_px        uint64, ×10^5
//   31    8   total_volume_traded uint64
//   39    8   num_trades          uint64
//   47    8   total_value_traded  uint64
//   55    8   trading_phase_code  ASCII "T111    "
//   63    4   last_update_time
//   67    2   no_md_entries       通常 = 14 (最新+开+高+低 + 5买 + 5卖)
// ================================================================

class SecurityEntryView {
public:
    static constexpr size_t kFixedSize = 69;

    SecurityEntryView(const uint8_t* p, size_t n) : raw_(p), n_(n) {}

    bool hasHeader() const { return n_ >= kFixedSize; }

    uint8_t          security_type()       const { return raw_[0]; }
    uint8_t          record_tag()          const { return raw_[1]; }
    std::string_view md_stream_id()        const { return {rcp(raw_ + 2),  5}; }
    std::string_view security_id()         const { return {rcp(raw_ + 7),  8}; }
    const uint8_t*   symbol_gbk()          const { return raw_ + 15; }   // 8 字节 GBK
    uint64_t         pre_close_px()        const { return readBE64(raw_ + 23); }
    uint64_t         total_volume_traded() const { return readBE64(raw_ + 31); }
    uint64_t         num_trades()          const { return readBE64(raw_ + 39); }
    uint64_t         total_value_traded()  const { return readBE64(raw_ + 47); }
    std::string_view trading_phase_code()  const { return {rcp(raw_ + 55), 8}; }
    uint32_t         last_update_time()    const { return readBE32(raw_ + 63); }
    uint16_t         no_md_entries()       const { return readBE16(raw_ + 67); }

    size_t totalSize() const {
        return kFixedSize + size_t(no_md_entries()) * 19;
    }
    const uint8_t* md_entries_begin() const { return raw_ + kFixedSize; }

private:
    static const char* rcp(const uint8_t* p) {
        return reinterpret_cast<const char*>(p);
    }
    const uint8_t* raw_;
    size_t         n_;
};

// ================================================================
// MDEntry (19B) — M201 证券内的行情条目
// ----------------------------------------------------------------
//   off  len  field
//    0    1   entry_type     ASCII
//                              '0' = Bid  买盘
//                              '1' = Ask  卖盘
//                              '2' = Last 最新成交价
//                              '4' = Open 开盘价
//                              '7' = High 最高价
//                              '8' = Low  最低价
//    1    1   pad_space      恒为 0x20
//    2    8   price          uint64, ×10^5
//   10    8   qty            uint64 (买卖盘为挂单量, Last 为最新单量)
//   18    1   position_no    买卖盘档位编号 0..4; 统计价字段为 0
// ================================================================

class MDEntryView {
public:
    static constexpr size_t kSize = 19;

    explicit MDEntryView(const uint8_t* p) : raw_(p) {}

    char     entry_type()  const { return char(raw_[0]); }
    uint8_t  pad_space()   const { return raw_[1]; }
    uint64_t price()       const { return readBE64(raw_ + 2); }
    uint64_t qty()         const { return readBE64(raw_ + 10); }
    uint8_t  position_no() const { return raw_[18]; }

private:
    const uint8_t* raw_;
};

// -------- 语义查表 --------

inline const char* tradingPhaseDesc(std::string_view code) {
    size_t n = code.size();
    while (n > 0 && code[n - 1] == ' ') --n;
    std::string_view s = code.substr(0, n);
    if (s == "T100") return "开盘前";
    if (s == "T111") return "连续竞价中";
    if (s == "T118") return "闭市";
    if (s == "T200") return "收盘集合竞价";
    return "未知";
}

inline const char* mdEntryTypeDesc(char t) {
    switch (t) {
        case '0': return "Bid";
        case '1': return "Ask";
        case '2': return "Last";
        case '4': return "Open";
        case '7': return "High";
        case '8': return "Low";
        default:  return "?";
    }
}

}  // namespace sse
