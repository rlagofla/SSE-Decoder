// main.cpp — 上交所 (9, 5803) 逐笔行情解码器 (pcap 文件输入)
//
// 用法:
//   decode_9_5803 <pcap> <hi> <lo> [filter_port=5261]

#include <iostream>
#include <sstream>
#include <PcapFileDevice.h>
#include <Packet.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "utils.hpp"
#include "SsePipeline.hpp"


void onConnStart(const pcpp::ConnectionData& c, void* cookie) {
    auto* ctx = static_cast<Context*>(cookie);
    if (!portMatch(c, ctx->filter_port)) {
        spdlog::trace("[conn] 端口不匹配（filter={}），跳过 {}:{} -> {}:{}",
                      ctx->filter_port,
                      c.srcIP.toString(), c.srcPort,
                      c.dstIP.toString(), c.dstPort);
        return;
    }
    auto sp = std::make_unique<Splitter>();
    sp->want_hi = ctx->want_hi;
    sp->want_lo = ctx->want_lo;
    std::ostringstream ss;
    ss << c.srcIP.toString() << ":" << c.srcPort
       << "->" << c.dstIP.toString() << ":" << c.dstPort;
    sp->stream_tag = ss.str();
    spdlog::info("[conn] 新连接: {}", sp->stream_tag);
    ctx->streams[c.flowKey] = std::move(sp);
}

void onTcpData(int8_t, const pcpp::TcpStreamData& data, void* cookie) {
    auto* ctx = static_cast<Context*>(cookie);
    auto  it  = ctx->streams.find(data.getConnectionData().flowKey);
    if (it == ctx->streams.end()) {
        spdlog::trace("[conn] 收到未跟踪连接的数据 flowKey={}",
                      data.getConnectionData().flowKey);
        return;
    }
    it->second->feed(reinterpret_cast<const uint8_t*>(data.getData()),
                     data.getDataLength());
}

void onConnEnd(const pcpp::ConnectionData& c,
               pcpp::TcpReassembly::ConnectionEndReason reason, void* cookie) {
    auto* ctx = static_cast<Context*>(cookie);
    auto  it  = ctx->streams.find(c.flowKey);
    if (it != ctx->streams.end()) {
        spdlog::info("[conn] 连接结束: {} reason={}",
                     it->second->stream_tag, static_cast<int>(reason));
        ctx->streams.erase(it);
    }
}

int main(int argc, char** argv) {
    // spdlog::set_level(spdlog::level::trace);
    spdlog::set_default_logger(spdlog::stderr_color_mt("console"));

    if (argc < 4) {
        std::cerr << "用法: " << argv[0] << " <pcap> <hi> <lo> [filter_port=5261]\n";
        return 1;
    }

    Context ctx;
    ctx.want_hi     = uint32_t(std::stoul(argv[2]));
    ctx.want_lo     = uint32_t(std::stoul(argv[3]));
    ctx.filter_port = (argc >= 5) ? uint16_t(std::stoi(argv[4])) : 5261;

    pcpp::PcapFileReaderDevice reader(argv[1]);
    if (!reader.open()) {
        spdlog::error("[conn] 打开 pcap 失败: {}", argv[1]);
        return 1;
    }

    pcpp::TcpReassembly reassembly(onTcpData, &ctx, onConnStart, onConnEnd);
    pcpp::RawPacket     raw;
    while (reader.getNextPacket(raw)) reassembly.reassemblePacket(&raw);
    reassembly.closeAllConnections();
    reader.close();
    return 0;
}
