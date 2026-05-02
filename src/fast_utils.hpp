#pragma once
// fast_utils.hpp — FAST 协议底层工具函数（无业务依赖，可被多个解码器复用）

#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <string>
#include <utility>

namespace fast {

enum class Status {
    Ok,
    InsufficientBytes,  // buffer 剩余字节不足
    InvalidEncoding,    // 字节内容不符合预期格式（非数字、stop-bit 缺失等）
};

// FAST stop-bit 变长无符号整数解码
// 成功时 out 填解码值，consumed 填消耗字节数
inline Status readFast(const uint8_t* p, size_t n, uint64_t& out, size_t& consumed) {
    out = 0; consumed = 0;
    if (n == 0) return Status::InsufficientBytes;
    uint64_t v = 0;
    for (size_t i = 0; i < n; ++i) {
        v = (v << 7) | uint64_t(p[i] & 0x7F);
        if (p[i] & 0x80) {
            out = v; consumed = i + 1;
            return Status::Ok;
        }
    }
    return Status::InsufficientBytes;
}

// 读取 stop-bit 终止的 PMAP，最多 2 字节（14 bits，覆盖 12 个字段位）
// FAST 规范：payload 内 MSB 优先，第 1 字节 bit6 → PMAP position 0，…
inline Status readPmap(const uint8_t* p, size_t n, uint16_t& bits, size_t& consumed) {
    bits = 0; consumed = 0;
    if (n == 0) return Status::InsufficientBytes;
    for (size_t i = 0; i < n && i < 2; ++i) {
        uint8_t b = p[i];
        uint8_t payload = b & 0x7F;
        for (int j = 0; j < 7; ++j) {
            if ((payload >> (6 - j)) & 1)
                bits |= uint16_t(1u << (i * 7 + j));
        }
        consumed = i + 1;
        if (b & 0x80) return Status::Ok;
    }
    return Status::InsufficientBytes;
}

// 读取 6 字节 ASCII 证券代码（前 5 字节为 0x30-0x39，第 6 字节有 stop-bit 且低 7 位为 0x30-0x39）
inline Status readAsciiSecID(const uint8_t* p, size_t n, std::string& out) {
    if (n < 6) return Status::InsufficientBytes;
    for (size_t i = 0; i < 5; ++i) {
        if (p[i] < 0x30 || p[i] > 0x39) return Status::InvalidEncoding;
    }
    uint8_t last = p[5];
    if (!(last & 0x80))             return Status::InvalidEncoding;
    uint8_t lc = last & 0x7F;
    if (lc < 0x30 || lc > 0x39)    return Status::InvalidEncoding;
    out.assign(reinterpret_cast<const char*>(p), 5);
    out.push_back(char(lc));
    return Status::Ok;
}

// FAST int → ASCII 字符串（用于 TradingPhaseCode，不会失败）
inline std::string fastIntToAscii(uint64_t v) {
    if (v == 0) return "";
    std::string s;
    while (v > 0) {
        s += char(v & 0x7F);
        v >>= 7;
    }
    std::reverse(s.begin(), s.end());
    return s;
}

// FAST nullable 解码: V==0 → NULL(返回 {0, true}), V>0 → {V-1, false}
inline std::pair<uint64_t, bool> decNull(uint64_t enc) {
    if (enc == 0) return {0, true};
    return {enc - 1, false};
}

}  // namespace fast
