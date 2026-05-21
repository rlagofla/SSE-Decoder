#pragma once
// utils.hpp — 通用工具函数（FAST 解码、二进制读取、inflate、格式化、网络工具）

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include <zlib.h>
#include <TcpReassembly.h>

namespace utils {

// ---- FAST 协议底层 ----

// FAST 操作算子
enum class FastOp {
    None,         // 无 PMAP 控制，直接读取
    NoneNull,     // 无 PMAP 控制，直接读取 (Nullable)
    Copy,         // PMAP=0: 字典; PMAP=1: 读取更新字典
    CopyNull,     // PMAP=0: 字典; PMAP=1: 读取 Nullable (非 Null 更新字典)
    Inc,          // PMAP=0: 字典+1; PMAP=1: 读取更新字典
    Default,      // PMAP=0: 默认值; PMAP=1: 读取，不更新字典
    DefaultNull   // PMAP=0: 返回 0; PMAP=1: 读取 Nullable (Null 返回 0)，无字典
};

class FastReader {
public:
    FastReader(const uint8_t* body, size_t len) : body_(body), len_(len) {}

    size_t cursor() const { return cursor_; }
    bool empty() const { return cursor_ >= len_; }
    void skip(size_t n) { cursor_ += n; }

    void setPmap(uint64_t pmap) { pmap_ = pmap; }
    bool hasBit(int bit) const { return (pmap_ & (1ull << bit)) != 0; }

    // 1. bit + dict + out (Copy, Inc, CopyNull, Default)
    template <FastOp Op, typename T>
    bool readNum(int bit, T& dict_val, T& out) {
        if constexpr (Op == FastOp::Copy) {
            if (!hasBit(bit)) { out = dict_val; return true; }
            uint64_t v; if (!_readUint(v)) return false;
            dict_val = static_cast<T>(v);
            out = dict_val; return true;
        } 
        else if constexpr (Op == FastOp::CopyNull) {
            if (!hasBit(bit)) { out = dict_val; return true; }
            uint64_t v; if (!_readUint(v)) return false;
            if (v == 0) { out = 0; return true; }
            dict_val = static_cast<T>(v - 1);
            out = dict_val; return true;
        }
        else if constexpr (Op == FastOp::Inc) {
            if (!hasBit(bit)) { ++dict_val; out = dict_val; return true; }
            uint64_t v; if (!_readUint(v)) return false;
            dict_val = static_cast<T>(v);
            out = dict_val; return true;
        }
        return false;
    }

    // 2. bit + out (Default, DefaultNull)
    template <FastOp Op, typename T>
    bool readNum(int bit, T& out) {
        if constexpr (Op == FastOp::Default) {
            if (!hasBit(bit)) { out = 0; return true; }
            uint64_t v; if (!_readUint(v)) return false;
            out = static_cast<T>(v); return true;
        }
        else if constexpr (Op == FastOp::DefaultNull) {
            if (!hasBit(bit)) { out = 0; return true; }
            uint64_t v; if (!_readUint(v)) return false;
            out = (v == 0) ? 0 : static_cast<T>(v - 1); return true;
        }
        return false;
    }

    // 3. out only (None, NoneNull)
    template <FastOp Op, typename T>
    bool readNum(T& out) {
        if constexpr (Op == FastOp::None) {
            uint64_t v; if (!_readUint(v)) return false;
            out = static_cast<T>(v); return true;
        }
        else if constexpr (Op == FastOp::NoneNull) {
            uint64_t v; if (!_readUint(v)) return false;
            out = (v == 0) ? 0 : static_cast<T>(v - 1); return true;
        }
        return false;
    }

    // String: bit + dict + out (Copy)
    template <FastOp Op>
    bool readString(int bit, std::string& dict_val, std::string& out) {
        if constexpr (Op == FastOp::Copy) {
            if (!hasBit(bit)) { out = dict_val; return true; }
            if (!_readString(dict_val)) return false;
            out = dict_val; return true;
        }
        return false;
    }

    // String: bit + out (Copy)
    template <FastOp Op>
    bool readString(int bit, std::string& out) {
        if constexpr (Op == FastOp::Default) {
            if (!hasBit(bit)) { out = "Default"; return true; }
            return _readString(out);
        }
        return false;
    }

    // String: out only (None)
    template <FastOp Op>
    bool readString(std::string& out) {
        if constexpr (Op == FastOp::None) {
            return _readString(out);
        }
        return false;
    }

private:
    bool _readUint(uint64_t& out) {
        out = 0;
        uint64_t v = 0;
        while (cursor_ < len_) {
            uint8_t b = body_[cursor_++];
            v = (v << 7) | (b & 0x7F);
            if (b & 0x80) { out = v; return true; }
        }
        return false;
    }

    bool _readString(std::string& out) {
        out.clear();
        while (cursor_ < len_) {
            uint8_t b = body_[cursor_++];
            out.push_back(char(b & 0x7F));
            if (b & 0x80) return true;
        }
        return false;
    }

    const uint8_t* body_;
    size_t len_;
    size_t cursor_ = 0;
    uint64_t pmap_ = 0;
};

// ---- 二进制读取 ----

inline uint32_t readBE32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) <<  8) |  uint32_t(p[3]);
}

// ---- 字符串转义（用于 spdlog，防止控制字符破坏终端输出） ----

inline std::string escapeStr(const std::string& s) {
    std::string r;
    r.reserve(s.size() * 2);
    for (unsigned char c : s) {
        switch (c) {
            case '\n': r += "\\n";  break;
            case '\r': r += "\\r";  break;
            case '\t': r += "\\t";  break;
            case '\b': r += "\\b";  break;
            default:
                if (c < 0x20 || c == 0x7f) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\x%02x", c);
                    r += buf;
                } else {
                    r += char(c);
                }
        }
    }
    return r;
}

// ---- 格式化 ----

inline std::string fmtDecFixed(int64_t v, int digits) {
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
    uint32_t xx = t % 100;
    uint32_t ss = (t / 100) % 100;
    uint32_t mm = (t / 10000) % 100;
    uint32_t hh = t / 1000000;
    char b[16];
    std::snprintf(b, sizeof(b), "%02u:%02u:%02u.%02u", hh, mm, ss, xx);
    return b;
}


inline std::string fmtSnapTime(uint32_t t) {
    uint32_t ss = t % 100;
    uint32_t mm = (t / 100) % 100;
    uint32_t hh = (t / 10000) % 100;
    char b[16];
    std::snprintf(b, sizeof(b), "%02u:%02u:%02u", hh, mm, ss);
    return b;
}

inline std::string fmtPktTime(const timespec& ts) {
    time_t sec = ts.tv_sec;
    struct tm t{};
    localtime_r(&sec, &t);
    char b[24];
    std::snprintf(b, sizeof(b), "%02d:%02d:%02d.%03ld", t.tm_hour, t.tm_min, t.tm_sec, ts.tv_nsec / 1000000L);
    return b;
}

// ---- 网络工具 ----

inline bool portMatch(const pcpp::ConnectionData& c, uint16_t port) {
    return port == 0 || c.srcPort == port || c.dstPort == port;
}

}  // namespace utils
