// main.cpp — 上交所 (9, 5803) 逐笔行情解码器
//
// 用法:
//   decode <pcap>          <hi> <lo> [filter_port=5261]   # 离线文件
//   decode --iface <名称>  <hi> <lo> [filter_port=5261]   # 实时抓包

#include <iostream>
#include <sstream>
#include <string>
#include <PcapFileDevice.h>
#include <PcapLiveDevice.h>
#include <PcapLiveDeviceList.h>
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

    bool        live_mode  = false;
    std::string source;     // pcap 文件路径 或 网卡名

    // 解析 --iface 标志
    int pos = 1;
    if (argc > 2 && std::string(argv[1]) == "--iface") {
        live_mode = true;
        source    = argv[2];
        pos       = 3;
    } else if (argc > 1) {
        source = argv[1];
        pos    = 2;
    }

    if (argc - pos < 2) {
        std::cerr << "用法:\n"
                  << "  " << argv[0] << " <pcap>         <hi> <lo> [filter_port=5261]\n"
                  << "  " << argv[0] << " --iface <名称> <hi> <lo> [filter_port=5261]\n";
        return 1;
    }

    Context ctx;
    ctx.want_hi     = uint32_t(std::stoul(argv[pos]));
    ctx.want_lo     = uint32_t(std::stoul(argv[pos + 1]));
    ctx.filter_port = (argc - pos >= 3) ? uint16_t(std::stoi(argv[pos + 2])) : 5261;

    pcpp::TcpReassembly reassembly(onTcpData, &ctx, onConnStart, onConnEnd);

    if (live_mode) {
        auto* dev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByName(source);
        if (!dev) {
            spdlog::error("[conn] 找不到网卡: {}", source);
            return 1;
        }
        if (!dev->open()) {
            spdlog::error("[conn] 打开网卡失败: {}", source);
            return 1;
        }
        spdlog::info("[conn] 开始监听网卡: {}", source);
        dev->startCapture([](pcpp::RawPacket* raw, pcpp::PcapLiveDevice*, void* cookie) {
            static_cast<pcpp::TcpReassembly*>(cookie)->reassemblePacket(raw);
        }, &reassembly);

        std::string line;
        std::getline(std::cin, line);  // 回车退出

        dev->stopCapture();
        dev->close();
    } else {
        pcpp::PcapFileReaderDevice reader(source);
        if (!reader.open()) {
            spdlog::error("[conn] 打开 pcap 失败: {}", source);
            return 1;
        }
        pcpp::RawPacket raw;
        while (reader.getNextPacket(raw)) reassembly.reassemblePacket(&raw);
        reader.close();
    }

    reassembly.closeAllConnections();
    return 0;
}
