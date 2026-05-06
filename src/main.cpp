// main.cpp — 上交所行情解码器
//
// 用法:
//   decode <config.toml>

#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <PcapFileDevice.h>
#include <PcapLiveDevice.h>
#include <PcapLiveDeviceList.h>
#include <Packet.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include "config.hpp"
#include "pipeline.hpp"
#include "utils.hpp"

void onConnStart(const pcpp::ConnectionData& c, void* cookie) {
    auto* ctx = static_cast<Context*>(cookie);
    if (!utils::portMatch(c, ctx->filter_port)) {
        spdlog::trace("[conn] 端口不匹配（filter={}），跳过 {}:{} -> {}:{}", ctx->filter_port, c.srcIP.toString(), c.srcPort, c.dstIP.toString(), c.dstPort);
        return;
    }
    auto sp = std::make_unique<Splitter>();
    sp->ctx = ctx;
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
        spdlog::trace("[conn] 收到未跟踪连接的数据 flowKey={}", data.getConnectionData().flowKey);
        return;
    }
    it->second->feed(reinterpret_cast<const uint8_t*>(data.getData()), data.getDataLength());
}

void onConnEnd(const pcpp::ConnectionData& c,
               pcpp::TcpReassembly::ConnectionEndReason reason, void* cookie) {
    auto* ctx = static_cast<Context*>(cookie);
    auto  it  = ctx->streams.find(c.flowKey);
    if (it != ctx->streams.end()) {
        spdlog::info("[conn] 连接结束: {} reason={}", it->second->stream_tag, static_cast<int>(reason));
        ctx->streams.erase(it);
    }
}

int main(int argc, char** argv) {
    spdlog::set_default_logger(spdlog::stderr_color_mt("console"));

    if (argc < 2) {
        std::cerr << "用法: " << argv[0] << " <config.toml>\n";
        return 1;
    }

    Config cfg;
    try {
        cfg = loadConfig(argv[1]);
    } catch (const std::exception& e) {
        spdlog::error("配置加载失败: {}", e.what());
        return 1;
    }

    // 设置日志级别
    {
        auto lvl = spdlog::level::info;
        if      (cfg.log_level == "trace") lvl = spdlog::level::trace;
        else if (cfg.log_level == "debug") lvl = spdlog::level::debug;
        else if (cfg.log_level == "warn")  lvl = spdlog::level::warn;
        else if (cfg.log_level == "error") lvl = spdlog::level::err;
        spdlog::set_level(lvl);
    }

    // 打开各类型的输出文件，构建 Context
    // ofstreams 在 main 栈上存活，ActiveType 持非拥有指针
    std::vector<std::unique_ptr<std::ofstream>> outfiles;
    Context ctx;
    ctx.filter_port = cfg.port;

    for (auto& tc : cfg.types) {
        auto ofs = std::make_unique<std::ofstream>(tc.output);
        if (!ofs->is_open()) {
            spdlog::error("无法打开输出文件: {}", tc.output);
            return 1;
        }
        ActiveType at{ tc.hi, tc.lo, tc.dedup, ofs.get() };
        ctx.types.push_back(at);
        outfiles.push_back(std::move(ofs));
        spdlog::info("[main] 类型 ({},{}) -> {}", tc.hi, tc.lo, tc.output);
    }

    pcpp::TcpReassembly reassembly(onTcpData, &ctx, onConnStart, onConnEnd);

    if (cfg.mode == "iface") {
        auto* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(cfg.source);
        if (!dev) {
            spdlog::error("[conn] 找不到网卡: {}", cfg.source);
            return 1;
        }
        if (!dev->open()) {
            spdlog::error("[conn] 打开网卡失败: {}", cfg.source);
            return 1;
        }
        spdlog::info("[conn] 开始监听网卡: {}", cfg.source);
        dev->startCapture([](pcpp::RawPacket* raw, pcpp::PcapLiveDevice*, void* cookie) {
            static_cast<pcpp::TcpReassembly*>(cookie)->reassemblePacket(raw);
        }, &reassembly);

        std::string line;
        std::getline(std::cin, line);   // 按回车退出

        dev->stopCapture();
        dev->close();
    } else {
        pcpp::PcapFileReaderDevice reader(cfg.source);
        if (!reader.open()) {
            spdlog::error("[conn] 打开 pcap 失败: {}", cfg.source);
            return 1;
        }
        pcpp::RawPacket raw;
        while (reader.getNextPacket(raw)) reassembly.reassemblePacket(&raw);
        reader.close();
    }

    reassembly.closeAllConnections();
    return 0;
}
