#pragma once
// utils.hpp — 通用工具函数（FAST 解码、二进制读取、inflate、格式化、网络工具）

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include <zlib.h>
#include <TcpReassembly.h>
#include <spdlog/spdlog.h>

// ---- FAST 协议底层 ----

namespace fast {

enum class Status {
    Ok,
    InsufficientBytes,
    InvalidEncoding,
};

// stop-bit 变长无符号整数解码
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

// stop-bit ASCII 读取（SecurityID、TradingPhaseCode 等任意长度字段）
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

// nullable 解码: V==0 → NULL {0, true}, V>0 → {V-1, false}
inline std::pair<uint64_t, bool> decNull(uint64_t enc) {
    if (enc == 0) return {0, true};
    return {enc - 1, false};
}

}  // namespace fast

// ---- 二进制读取 ----

inline uint32_t readBE32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) <<  8) |  uint32_t(p[3]);
}

// ---- inflate ----

inline bool rawInflateZipLFH(const uint8_t* body, size_t n, std::vector<uint8_t>& out) {
    if (n < 30 || body[0] != 'P' || body[1] != 'K' ||
        body[2] != 3 || body[3] != 4) {
        spdlog::warn("[inflate] ZIP LFH 魔数校验失败: n={} head={:02x} {:02x} {:02x} {:02x}",
                     n,
                     n > 0 ? body[0] : 0, n > 1 ? body[1] : 0,
                     n > 2 ? body[2] : 0, n > 3 ? body[3] : 0);
        return false;
    }

    uint16_t method = uint16_t(body[8]) | (uint16_t(body[9]) << 8);
    if (method != 8) {
        spdlog::warn("[inflate] 压缩方式不是 deflate(8): method={}", method);
        return false;
    }

    uint16_t name_len  = uint16_t(body[26]) | (uint16_t(body[27]) << 8);
    uint16_t extra_len = uint16_t(body[28]) | (uint16_t(body[29]) << 8);
    size_t   start     = 30u + name_len + extra_len;
    if (start >= n) {
        spdlog::warn("[inflate] ZIP LFH 数据区偏移超出 buffer: start={} n={}", start, n);
        return false;
    }

    size_t compressed_size = n - start;
    if (compressed_size > std::numeric_limits<uInt>::max()) {
        spdlog::warn("[inflate] 压缩数据长度超出 uInt 上限: compressed_size={}", compressed_size);
        return false;
    }

    z_stream zs{};
    if (inflateInit2(&zs, -MAX_WBITS) != Z_OK) {
        spdlog::error("[inflate] inflateInit2 失败");
        return false;
    }
    zs.next_in  = const_cast<Bytef*>(body + start);
    zs.avail_in = uInt(compressed_size);

    out.clear();
    std::vector<uint8_t> buf(64 * 1024);
    int ret;
    do {
        zs.next_out  = buf.data();
        zs.avail_out = uInt(buf.size());

        uInt before_in  = zs.avail_in;
        uInt before_out = zs.avail_out;

        ret = inflate(&zs, Z_NO_FLUSH);

        if (ret != Z_OK && ret != Z_STREAM_END) {
            spdlog::warn("[inflate] inflate 返回错误: ret={} msg={} avail_in={} compressed_size={}",
                        ret, zs.msg ? zs.msg : "(null)", zs.avail_in, compressed_size);
            inflateEnd(&zs);
            return false;
        }

        if (zs.avail_in == before_in && zs.avail_out == before_out) {
            spdlog::warn("[inflate] inflate 无进展，放弃: avail_in={} avail_out={}",
                        zs.avail_in, zs.avail_out);
            inflateEnd(&zs);
            return false;
        }

        out.insert(out.end(), buf.data(), buf.data() + (buf.size() - zs.avail_out));
    } while (ret != Z_STREAM_END);

    inflateEnd(&zs);
    return ret == Z_STREAM_END;
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

// ---- 网络工具 ----

inline bool portMatch(const pcpp::ConnectionData& c, uint16_t port) {
    return port == 0 || c.srcPort == port || c.dstPort == port;
}
