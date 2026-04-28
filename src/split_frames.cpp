// split_frames: 从上交所行情 pcap 里拆帧并打印
//
// 流程：
//   1) PcapPlusPlus 读 pcap + TcpReassembly 做 TCP 流重组
//   2) 每条流内部按 0x0004C453 魔数切帧
//   3) 解析 40B 包头（大端字段，见下方说明）
//   4) 若 compressed==1，用 zlib 裸 deflate 解压（跳过 ZIP Local File Header）
//   5) 按 (type,sub) 做计数，并对指定通道打印前 N 帧的 hex dump + 字段解读
//
// 外层 40 字节包头（大端；offset 单位：字节）:
//   [0  .. 3 ]  u32  magic       恒为 0x0004C453
//   [4  .. 7 ]  u32  length      整帧长度（含这 40B 头）
//   [8  .. 11]  u32  channel_hi  通道路由 tag 高 32 位（业务主类）
//   [12 .. 15]  u32  channel_lo  通道路由 tag 低 32 位（业务子类）
//   [16 .. 19]  u32  seq         按 (hi, lo) 分组严格 +1 递增
//   [20 .. 23]  u32  zero        观测恒 0
//   [24 .. 27]  u32  t24         疑似时间戳（仅部分通道有值）
//   [28 .. 31]  u32  flag_28     通道静态 flag（每通道几乎恒定）
//   [32 .. 35]  u32  compressed  压缩位：0=明文 1=ZIP+raw-deflate
//   [36 .. 39]  u32  flag_36     通道静态 flag（0/1/15）
//
// 用法：
//   split_frames <pcap_file> [filter_port=5261] [type,sub] [max_print=5]
//
//   filter_port : TCP 端口过滤（一般是 5261，服务端端口）
//   type,sub    : 只打印指定通道（如 47,4701）；填 "-" 或不填则每个通道打印若干条
//   max_print   : 每个通道最多打印几帧

#include <cstdint>
#include <cstring>
#include <deque>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include <zlib.h>

#include <Packet.h>
#include <PcapFileDevice.h>
#include <TcpReassembly.h>

// -------- 工具 --------

static inline uint32_t be32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) <<  8) |  uint32_t(p[3]);
}

// ZIP Local File Header + 裸 deflate 的流式解压。
// 包体为标准 PK\x03\x04 头（30B），之后是 filename(n) + extra(m)，再后面是 deflate 数据。
// 没有 central directory，所以 zipfile 库读不了，自己走 inflateInit2(-MAX_WBITS)。
static bool rawInflateZipLFH(const uint8_t* body, size_t n, std::vector<uint8_t>& out) {
    if (n < 30 || body[0] != 'P' || body[1] != 'K' ||
        body[2] != 3 || body[3] != 4) return false;
    uint16_t name_len  = uint16_t(body[26]) | (uint16_t(body[27]) << 8);
    uint16_t extra_len = uint16_t(body[28]) | (uint16_t(body[29]) << 8);
    size_t   start     = 30u + name_len + extra_len;
    if (start >= n) return false;

    z_stream zs{};
    if (inflateInit2(&zs, -MAX_WBITS) != Z_OK) return false;
    zs.next_in  = const_cast<Bytef*>(body + start);
    zs.avail_in = uInt(n - start);

    out.clear();
    std::vector<uint8_t> buf(64 * 1024);
    int ret;
    do {
        zs.next_out  = buf.data();
        zs.avail_out = uInt(buf.size());
        ret = inflate(&zs, Z_SYNC_FLUSH);
        if (ret == Z_NEED_DICT || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
            inflateEnd(&zs); return false;
        }
        out.insert(out.end(), buf.data(), buf.data() + (buf.size() - zs.avail_out));
    } while (ret != Z_STREAM_END && zs.avail_in > 0);

    inflateEnd(&zs);
    return true;
}

// 按 hexdump -C 风格打印 buf[0..len)，最多打印 max_bytes 字节
static void hexDump(std::ostream& os, const uint8_t* buf, size_t len,
                    size_t max_bytes = 128) {
    size_t n = std::min(len, max_bytes);
    for (size_t i = 0; i < n; i += 16) {
        size_t row = std::min<size_t>(16, n - i);
        os << "      " << std::hex << std::setw(4) << std::setfill('0') << i
           << "  ";
        for (size_t j = 0; j < 16; ++j) {
            if (j < row) {
                os << std::setw(2) << std::setfill('0')
                   << unsigned(buf[i + j]) << ' ';
            } else {
                os << "   ";
            }
            if (j == 7) os << ' ';
        }
        os << " |";
        for (size_t j = 0; j < row; ++j) {
            uint8_t c = buf[i + j];
            os << char((c >= 32 && c < 127) ? c : '.');
        }
        os << "|\n" << std::dec;
    }
    if (len > n) {
        os << "      ... (剩余 " << (len - n) << " 字节省略)\n";
    }
}

// -------- 每条 TCP 流的帧切分器（魔数前缀帧） --------

class FrameSplitter {
public:
    static constexpr uint32_t kMagic = 0x0004C453u;

    struct FrameStats {
        uint64_t count         = 0;
        uint64_t zip_ok        = 0;
        uint64_t zip_fail      = 0;
        uint64_t total_len     = 0;
        // body[4..8) 的 4 字节 label 分布（M201/M101/M102/…）
        std::map<std::string, uint64_t> label_hist;
    };

    struct ChannelKey { uint32_t hi, lo; };
    struct ChannelKeyHash {
        size_t operator()(const std::pair<uint32_t,uint32_t>& k) const noexcept {
            return (size_t(k.first) << 32) ^ size_t(k.second);
        }
    };

    // 过滤/打印配置
    bool     only_specific = false;
    uint32_t want_hi = 0, want_lo = 0;
    size_t   max_print_per_channel = 5;

    // 统计
    using Key = std::pair<uint32_t,uint32_t>;
    std::unordered_map<Key, FrameStats, ChannelKeyHash> stats;
    std::unordered_map<Key, size_t,     ChannelKeyHash> printed;
    // 每通道最多额外打印多少条 M101（会话首帧），默认 1
    size_t                                              max_m101_per_channel = 1;
    std::unordered_map<Key, size_t,     ChannelKeyHash> m101_printed;

    // 喂入新到达的字节，内部累积并尝试切帧
    void feed(const uint8_t* data, size_t len, const std::string& stream_tag) {
        buf_.insert(buf_.end(), data, data + len);

        while (buf_.size() >= 40) {
            // 重新对齐到 magic
            size_t idx = scanMagic();
            if (idx == std::string::npos) {
                // buf 里没找到任何 magic，保留末尾 3 字节供跨包拼接
                if (buf_.size() > 3) {
                    size_t drop = buf_.size() - 3;
                    lost_bytes_ += drop;
                    buf_.erase(buf_.begin(), buf_.begin() + drop);
                }
                return;
            }
            if (idx > 0) {
                lost_bytes_ += idx;
                buf_.erase(buf_.begin(), buf_.begin() + idx);
            }
            if (buf_.size() < 40) return;

            uint32_t length = be32(&buf_[4]);
            if (length < 40 || length > 16u * 1024u * 1024u) {
                // 长度不合理，跳 4 字节继续找
                lost_bytes_ += 4;
                buf_.erase(buf_.begin(), buf_.begin() + 4);
                continue;
            }
            if (buf_.size() < length) return;  // 还没收齐一整帧

            processFrame(&buf_[0], length, stream_tag);
            buf_.erase(buf_.begin(), buf_.begin() + length);
        }
    }

    // 打印全流程结束时的统计表
    void printSummary(std::ostream& os) const {
        os << "\n=== 通道统计（按帧数降序） ===\n";
        std::vector<std::pair<Key, FrameStats>> v(stats.begin(), stats.end());
        std::sort(v.begin(), v.end(),
                  [](const auto& a, const auto& b){ return a.second.count > b.second.count; });
        os << "  type  sub   frames        bytes   zip_ok  zip_fail\n";
        for (const auto& [k, s] : v) {
            os << "  " << std::setw(4) << k.first << "  "
               << std::setw(4) << k.second << "  "
               << std::setw(6) << s.count << "  "
               << std::setw(12) << s.total_len << "  "
               << std::setw(6)  << s.zip_ok << "  "
               << std::setw(6)  << s.zip_fail << "\n";
            if (!s.label_hist.empty()) {
                os << "      labels(body[4:8]):";
                for (const auto& [lbl, cnt] : s.label_hist) {
                    os << "  \"" << lbl << "\"=" << cnt;
                }
                os << "\n";
            }
        }
        os << "  lost_bytes=" << lost_bytes_ << " (找不到 magic 而丢弃)\n";
    }

private:
    std::vector<uint8_t> buf_;
    uint64_t             lost_bytes_ = 0;

    // 返回当前 buf_ 中第一个 magic 的下标；找不到返回 npos
    size_t scanMagic() const {
        // buf_ 足够大时用 KMP/memmem 更快；这里用简单顺序搜索，足够 demo
        if (buf_.size() < 4) return std::string::npos;
        size_t n = buf_.size() - 3;
        for (size_t i = 0; i < n; ++i) {
            if (buf_[i] == 0x00 && buf_[i+1] == 0x04 &&
                buf_[i+2] == 0xC4 && buf_[i+3] == 0x53) {
                return i;
            }
        }
        return std::string::npos;
    }

    void processFrame(const uint8_t* f, uint32_t length, const std::string& tag) {
        uint32_t hi   = be32(f + 8);
        uint32_t lo   = be32(f + 12);
        uint32_t seq  = be32(f + 16);
        uint32_t zero = be32(f + 20);
        uint32_t t24  = be32(f + 24);
        uint32_t fl28 = be32(f + 28);
        uint32_t comp = be32(f + 32);
        uint32_t fl36 = be32(f + 36);
        const uint8_t* body = f + 40;
        size_t         blen = length - 40;

        Key  k{hi, lo};
        auto& s = stats[k];
        s.count++;
        s.total_len += length;

        // 若压缩则解压
        std::vector<uint8_t> inflated;
        const uint8_t* payload = body;
        size_t         plen    = blen;
        bool           zip_ok  = false;
        if (comp == 1) {
            if (rawInflateZipLFH(body, blen, inflated)) {
                s.zip_ok++;
                payload = inflated.data();
                plen    = inflated.size();
                zip_ok  = true;
            } else {
                s.zip_fail++;
            }
        }

        // 统计 body[4..8) 的 4 字节 label 分布（例如 M201/M101/M102）
        if (plen >= 8) {
            std::string lbl(reinterpret_cast<const char*>(payload + 4), 4);
            bool printable = true;
            for (char c : lbl) {
                if (static_cast<uint8_t>(c) < 0x20 || static_cast<uint8_t>(c) >= 0x7F) {
                    printable = false; break;
                }
            }
            if (!printable) {
                char buf[20];
                std::snprintf(buf, sizeof(buf), "\\x%02x%02x%02x%02x",
                              uint8_t(lbl[0]), uint8_t(lbl[1]),
                              uint8_t(lbl[2]), uint8_t(lbl[3]));
                lbl = buf;
            }
            s.label_hist[lbl]++;
        }

        // 是否打印这条
        bool want = only_specific
                      ? (hi == want_hi && lo == want_lo)
                      : true;
        if (!want) return;

        bool is_m101 = (plen >= 8 &&
                        payload[4] == 'M' && payload[5] == '1' &&
                        payload[6] == '0' && payload[7] == '1');
        if (is_m101) {
            // M101 走独立配额，与 max_print 不冲突
            auto& mcnt = m101_printed[k];
            if (mcnt >= max_m101_per_channel) return;
            mcnt++;
        } else {
            size_t& pcnt = printed[k];
            if (pcnt >= max_print_per_channel) return;
            pcnt++;
        }

        // === 帧概览 ===
        std::cout << "\n================ [" << tag << "] frame#" << s.count
                  << "  (type=" << hi << ", sub=" << lo << ")  seq=" << seq
                  << "  total_len=" << length << " ================\n";

        // === 1) 40B 外层头，按 4 字节一组：hex + 字段含义 ===
        std::cout << "-- 40B 头 (大端) --\n";
        auto hdrLine = [&](unsigned off, const char* name, const std::string& meaning) {
            std::cout << "  [0x" << std::hex << std::setw(2) << std::setfill('0')
                      << off << std::dec << std::setfill(' ') << "]  "
                      << std::hex << std::setfill('0')
                      << std::setw(2) << unsigned(f[off])     << ' '
                      << std::setw(2) << unsigned(f[off + 1]) << ' '
                      << std::setw(2) << unsigned(f[off + 2]) << ' '
                      << std::setw(2) << unsigned(f[off + 3])
                      << std::dec << std::setfill(' ')
                      << "   " << std::left << std::setw(11) << name
                      << std::right << " = " << meaning << "\n";
        };
        {
            std::ostringstream m;
            m << "0x" << std::hex << std::setw(8) << std::setfill('0') << be32(f)
              << " (魔数, 期望 0x0004c453)";
            hdrLine(0, "magic", m.str());
        }
        { std::ostringstream m; m << length << " (整帧长度, 含此 40B 头)";
          hdrLine(4,  "length",     m.str()); }
        { std::ostringstream m; m << hi << " (业务主类 / type)";
          hdrLine(8,  "channel_hi", m.str()); }
        { std::ostringstream m; m << lo << " (业务子类 / sub)";
          hdrLine(12, "channel_lo", m.str()); }
        { std::ostringstream m; m << seq << " (按 (type,sub) 严格 +1 递增)";
          hdrLine(16, "seq",        m.str()); }
        { std::ostringstream m; m << zero << " (观测恒为 0)";
          hdrLine(20, "zero",       m.str()); }
        { std::ostringstream m;
          m << "0x" << std::hex << t24 << std::dec << " (疑似时间戳)";
          hdrLine(24, "t24",        m.str()); }
        { std::ostringstream m;
          m << "0x" << std::hex << fl28 << std::dec << " (通道静态 flag)";
          hdrLine(28, "flag_28",    m.str()); }
        { std::ostringstream m;
          m << comp << " (" << (comp == 1 ? "ZIP+deflate" : "明文") << ")";
          hdrLine(32, "compressed", m.str()); }
        { std::ostringstream m; m << fl36 << " (通道静态 flag)";
          hdrLine(36, "flag_36",    m.str()); }

        // === 2) body 部分：hex + ASCII，整段不截断 ===
        if (comp == 1 && zip_ok) {
            std::cout << "-- body (ZIP 解压后)  size=" << plen
                      << "  (原始密文 " << blen << " 字节) --\n";
        } else if (comp == 1) {
            std::cout << "-- body (ZIP 解压失败, 原始密文)  size=" << blen << " --\n";
        } else {
            std::cout << "-- body (明文)  size=" << plen << " --\n";
        }
        hexDump(std::cout, payload, plen, plen);
    }

    // 尝试识别 body 内部的应用层包头（M201/M102/M101 标签形式）
    void tryInterpretAppHeader(const uint8_t* p, size_t n) const {
        if (n >= 8) {
            uint32_t app_len = be32(p);
            if (p[4] == 'M' && (p[5] == '1' || p[5] == '2' || p[5] == '3')) {
                std::string tag(reinterpret_cast<const char*>(p + 4), 4);
                std::cout << "    [app-hdr] label=\"" << tag << "\""
                          << "  declared_len=" << app_len;
                if (n >= 48) {
                    uint32_t date = be32(p + 40);
                    std::cout << "  trade_date=" << date;
                }
                std::cout << "\n";
            }
        }
    }
};

// -------- pcap TCP 回调 --------

struct Context {
    uint16_t                                                      filter_port = 0;
    bool                                                          only_specific = false;
    uint32_t                                                      want_hi = 0, want_lo = 0;
    size_t                                                        max_print = 5;
    std::unordered_map<uint32_t, std::unique_ptr<FrameSplitter>>  streams;
    std::unordered_map<uint32_t, std::string>                     stream_tags;
};

static bool portMatch(const pcpp::ConnectionData& c, uint16_t port) {
    return port == 0 || c.srcPort == port || c.dstPort == port;
}

static void onConnStart(const pcpp::ConnectionData& c, void* cookie) {
    auto* ctx = static_cast<Context*>(cookie);
    if (!portMatch(c, ctx->filter_port)) return;

    auto sp = std::make_unique<FrameSplitter>();
    sp->only_specific         = ctx->only_specific;
    sp->want_hi               = ctx->want_hi;
    sp->want_lo               = ctx->want_lo;
    sp->max_print_per_channel = ctx->max_print;

    std::ostringstream ss;
    ss << c.srcIP.toString() << ":" << c.srcPort
       << "->" << c.dstIP.toString() << ":" << c.dstPort;
    ctx->stream_tags[c.flowKey] = ss.str();
    ctx->streams[c.flowKey]     = std::move(sp);

    std::cout << "[start] " << ctx->stream_tags[c.flowKey] << "\n";
}

static void onTcpData(int8_t /*side*/, const pcpp::TcpStreamData& data, void* cookie) {
    auto* ctx = static_cast<Context*>(cookie);
    auto  it  = ctx->streams.find(data.getConnectionData().flowKey);
    if (it == ctx->streams.end()) return;
    it->second->feed(reinterpret_cast<const uint8_t*>(data.getData()),
                     data.getDataLength(),
                     ctx->stream_tags[data.getConnectionData().flowKey]);
}

static void onConnEnd(const pcpp::ConnectionData& c,
                      pcpp::TcpReassembly::ConnectionEndReason,
                      void* cookie) {
    auto* ctx = static_cast<Context*>(cookie);
    auto  it  = ctx->streams.find(c.flowKey);
    if (it == ctx->streams.end()) return;
    std::cout << "[end]   " << ctx->stream_tags[c.flowKey] << "\n";
    it->second->printSummary(std::cout);
    ctx->streams.erase(it);
    ctx->stream_tags.erase(c.flowKey);
}

// -------- main --------

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "用法: " << argv[0]
                  << " <pcap_file> [filter_port=5261] [type,sub] [max_print=5]\n"
                  << "  例: " << argv[0] << " data/output.pcap 5261 47,4701 5\n";
        return 1;
    }

    Context ctx;
    ctx.filter_port = (argc >= 3) ? uint16_t(std::stoi(argv[2])) : 5261;
    if (argc >= 4 && std::string(argv[3]) != "-") {
        std::string s = argv[3];
        auto comma = s.find(',');
        if (comma == std::string::npos) {
            std::cerr << "错误: type,sub 参数格式应为 \"47,4701\"\n";
            return 1;
        }
        ctx.only_specific = true;
        ctx.want_hi = uint32_t(std::stoul(s.substr(0, comma)));
        ctx.want_lo = uint32_t(std::stoul(s.substr(comma + 1)));
    }
    if (argc >= 5) ctx.max_print = size_t(std::stoul(argv[4]));

    pcpp::PcapFileReaderDevice reader(argv[1]);
    if (!reader.open()) {
        std::cerr << "错误: 无法打开 pcap " << argv[1] << "\n";
        return 1;
    }

    std::cout << "读取 " << argv[1] << "  filter_port=" << ctx.filter_port;
    if (ctx.only_specific) {
        std::cout << "  filter_channel=(" << ctx.want_hi << "," << ctx.want_lo << ")";
    }
    std::cout << "  max_print=" << ctx.max_print << "\n";

    pcpp::TcpReassembly reassembly(onTcpData, &ctx, onConnStart, onConnEnd);
    pcpp::RawPacket     raw;
    uint64_t            packets = 0;
    while (reader.getNextPacket(raw)) {
        reassembly.reassemblePacket(&raw);
        if (++packets % 5'000'000 == 0) {
            std::cout << "  已处理 " << packets << " 包\n";
        }
    }
    reassembly.closeAllConnections();
    reader.close();
    std::cout << "\n完成。packets=" << packets << "\n";
    return 0;
}
