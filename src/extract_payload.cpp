// 使用 PcapPlusPlus 从上交所行情 pcap 中提取 TCP payload。
//
// 结构参考 szse_decoder/src/main.cpp，但上交所行情走 TCP（端口 7000），
// 因此这里使用 TcpReassembly 做 TCP 流重组。对每一条命中过滤端口的 TCP
// 连接，在输出目录下生成两个原始字节文件：
//   <srcIP>_<srcPort>__<dstIP>_<dstPort>.c2s.bin   （发起方 -> 响应方）
//   <srcIP>_<srcPort>__<dstIP>_<dstPort>.s2c.bin   （响应方 -> 发起方）
//
// 用法：extract_payload <pcap_file> [output_dir=./payload] [filter_port=7000]

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <unordered_map>

#include <Packet.h>
#include <PcapFileDevice.h>
#include <TcpReassembly.h>

namespace fs = std::filesystem;

// 单条 TCP 流对应的两个方向的输出文件及累计字节数
struct StreamFiles {
    std::ofstream c2s;            // 客户端 -> 服务端 方向（hex dump 文本）
    std::ofstream s2c;            // 服务端 -> 客户端 方向（hex dump 文本）
    std::string   base;           // 文件名前缀（不含后缀）
    uint64_t      bytes_c2s = 0;  // c2s 已写字节数（原始 payload 字节）
    uint64_t      bytes_s2c = 0;  // s2c 已写字节数（原始 payload 字节）
    uint64_t      missing   = 0;  // 预留：重组时缺失的字节数
};

// 把 buf[0..len) 以 hexdump -C 的格式追加写入 ofs：
//   偏移(16位十六进制)  16 个字节十六进制  |ASCII 可见字符|
// offset 参数为本段字节在流内的起始偏移（跨次调用累计）。
static void writeHexDump(std::ofstream& ofs,
                         const unsigned char* buf,
                         size_t               len,
                         uint64_t             offset) {
    constexpr size_t kLine = 16;  // 每行 16 字节
    for (size_t i = 0; i < len; i += kLine) {
        size_t n = std::min(kLine, len - i);
        // 左侧：8 位十六进制偏移
        ofs << std::hex << std::setw(8) << std::setfill('0') << (offset + i) << "  ";
        // 中间：16 字节十六进制，中间空格分两组
        for (size_t j = 0; j < kLine; ++j) {
            if (j < n) {
                ofs << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<unsigned>(buf[i + j]) << ' ';
            } else {
                ofs << "   ";  // 不足一行时用空格补齐，保持列对齐
            }
            if (j == 7) ofs << ' ';  // 每 8 字节之间多加一个空格
        }
        // 右侧：ASCII 可见字符（不可见字符用 .）
        ofs << " |";
        for (size_t j = 0; j < n; ++j) {
            unsigned char ch = buf[i + j];
            ofs << static_cast<char>(std::isprint(ch) ? ch : '.');
        }
        ofs << "|\n" << std::dec;  // 恢复十进制，避免影响后续 << 的格式
    }
}

// 跨回调共享的上下文，通过 cookie 指针传入
struct Context {
    fs::path                                  out_dir;          // 输出目录
    uint16_t                                  filter_port = 0;  // 0 表示不过滤
    std::unordered_map<uint32_t, StreamFiles> streams;          // flowKey -> 流文件
    uint64_t                                  accepted_conns = 0;
    uint64_t                                  skipped_conns  = 0;
};

// 判断该连接的源/目的端口是否命中过滤端口
static bool matchesPort(const pcpp::ConnectionData& c, uint16_t port) {
    return port == 0 || c.srcPort == port || c.dstPort == port;
}

// TCP 连接建立回调：为命中端口的连接预先打开输出文件
static void onConnStart(const pcpp::ConnectionData& c, void* cookie) {
    auto* ctx = static_cast<Context*>(cookie);
    if (!matchesPort(c, ctx->filter_port)) {
        ctx->skipped_conns++;
        return;
    }
    auto& s = ctx->streams[c.flowKey];
    s.base  = c.srcIP.toString() + "_" + std::to_string(c.srcPort) + "__" +
             c.dstIP.toString() + "_" + std::to_string(c.dstPort);
    // 以文本模式打开，写入 hexdump 可读格式
    s.c2s.open((ctx->out_dir / (s.base + ".c2s.txt")).string());
    s.s2c.open((ctx->out_dir / (s.base + ".s2c.txt")).string());
    ctx->accepted_conns++;
    std::cout << "[start] " << s.base << "\n";
}

// TCP 数据就绪回调：按方向把重组后的字节追加到对应文件
static void onTcpData(int8_t side, const pcpp::TcpStreamData& data, void* cookie) {
    auto* ctx = static_cast<Context*>(cookie);
    auto  it  = ctx->streams.find(data.getConnectionData().flowKey);
    if (it == ctx->streams.end()) return;  // 连接建立阶段已被过滤掉

    auto&       s   = it->second;
    const auto* buf = reinterpret_cast<const unsigned char*>(data.getData());
    size_t      len = data.getDataLength();
    // side == 0 表示从 "发起方" 发出，side == 1 表示从 "响应方" 发出
    if (side == 0) {
        writeHexDump(s.c2s, buf, len, s.bytes_c2s);
        s.bytes_c2s += len;
    } else {
        writeHexDump(s.s2c, buf, len, s.bytes_s2c);
        s.bytes_s2c += len;
    }
}

// TCP 连接结束回调：关闭文件，打印统计，并从 map 中移除
static void onConnEnd(const pcpp::ConnectionData&              c,
                      pcpp::TcpReassembly::ConnectionEndReason reason,
                      void*                                    cookie) {
    auto* ctx = static_cast<Context*>(cookie);
    auto  it  = ctx->streams.find(c.flowKey);
    if (it == ctx->streams.end()) return;
    auto& s = it->second;
    s.c2s.close();
    s.s2c.close();
    std::cout << "[end]   " << s.base << "  c2s=" << s.bytes_c2s
              << "B  s2c=" << s.bytes_s2c << "B  reason=" << reason << "\n";
    ctx->streams.erase(it);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "用法: " << argv[0]
                  << " <pcap_file> [output_dir=./payload] [filter_port=7000]\n";
        return 1;
    }

    Context ctx;
    ctx.out_dir     = (argc >= 3) ? argv[2] : "./payload";
    ctx.filter_port = (argc >= 4) ? static_cast<uint16_t>(std::stoi(argv[3])) : 7000;
    fs::create_directories(ctx.out_dir);

    pcpp::PcapFileReaderDevice reader(argv[1]);
    if (!reader.open()) {
        std::cerr << "错误：无法打开 pcap 文件 " << argv[1] << "\n";
        return 1;
    }

    // 构造 TCP 重组器，注册三个回调并把 ctx 作为 userCookie 传入
    pcpp::TcpReassembly reassembly(onTcpData, &ctx, onConnStart, onConnEnd);

    std::cout << "读取 " << argv[1] << " -> " << ctx.out_dir
              << "  (filter_port=" << ctx.filter_port << ")\n";

    pcpp::RawPacket raw;
    uint64_t        packets = 0;
    while (reader.getNextPacket(raw)) {
        reassembly.reassemblePacket(&raw);
        // 每处理 500 万包打印一次进度，避免刷屏
        if (++packets % 5'000'000 == 0) {
            std::cout << "  已处理 " << packets << " 个包\n";
        }
    }
    // 对仍未收到 FIN/RST 的连接做一次强制关闭，确保统计和文件被刷出
    reassembly.closeAllConnections();
    reader.close();

    std::cout << "完成。packets=" << packets
              << "  accepted_conns=" << ctx.accepted_conns
              << "  skipped_conns=" << ctx.skipped_conns << "\n";
    return 0;
}
