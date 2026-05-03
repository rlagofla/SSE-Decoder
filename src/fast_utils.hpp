#pragma once
// fast_utils.hpp — FAST 协议底层工具函数（无业务依赖，可被多个解码器复用）

#include <cstddef>
#include <cstdint>
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

// 通用 stop-bit ASCII 读取（与 readFast 相同的停止位机制，每字节低 7 位为字符）
// 用于 SecurityID、TradingPhaseCode 等任意长度 ASCII 字段
inline Status readAscii(const uint8_t* p, size_t n, std::string& out, size_t& consumed) {
    out.clear(); consumed = 0;
    if (n == 0) return Status::InsufficientBytes;
    for (size_t i = 0; i < n; ++i) {
        out.push_back(char(p[i] & 0x7F));
        consumed = i + 1;
        if (p[i] & 0x80) return Status::Ok;
    }
    return Status::InsufficientBytes;
}

// FAST nullable 解码: V==0 → NULL(返回 {0, true}), V>0 → {V-1, false}
inline std::pair<uint64_t, bool> decNull(uint64_t enc) {
    if (enc == 0) return {0, true};
    return {enc - 1, false};
}

}  // namespace fast
