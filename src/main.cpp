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
#include <Packet.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include "config.hpp"
#include "live.hpp"
#include "pipeline.hpp"
#include "utils.hpp"

#include <IPv4Layer.h>
#include <TcpLayer.h>
#include <arpa/inet.h>
#include <csignal>



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

    {
        auto lvl = spdlog::level::info;
        if      (cfg.log_level == "trace") lvl = spdlog::level::trace;
        else if (cfg.log_level == "debug") lvl = spdlog::level::debug;
        else if (cfg.log_level == "warn")  lvl = spdlog::level::warn;
        else if (cfg.log_level == "error") lvl = spdlog::level::err;
        spdlog::set_level(lvl);
    }

    std::vector<std::unique_ptr<std::ofstream>> outfiles;
    std::vector<ActiveType> types;

    for (auto& tc : cfg.types) {
        auto ofs = std::make_unique<std::ofstream>(tc.output);
        if (!ofs->is_open()) {
            spdlog::error("无法打开输出文件: {}", tc.output);
            return 1;
        }
        types.push_back({ tc.category_id, tc.msg_type, tc.dedup, ofs.get() });
        outfiles.push_back(std::move(ofs));
        spdlog::info("[main] 类型 ({},{}) -> {}", tc.category_id, tc.msg_type, tc.output);
    }

    Pipeline pipeline;
    pipeline.ConfigureTypes(std::move(types));
    pipeline.Start();

    if (cfg.mode == "iface") {
        static std::atomic<bool> g_stop{false};
        auto sig_handler = [](int) { g_stop.store(true); };
        std::signal(SIGINT,  sig_handler);
        std::signal(SIGTERM, sig_handler);

        cfg.iface.iface = cfg.source;
        spdlog::info("[iface] 启动 backend={} iface={} bin_dir={}",
                     cfg.iface.backend, cfg.iface.iface, cfg.iface.bin_dir);

        std::string err;
        int rc = RunIfaceMode(cfg.iface, pipeline, cfg.port, g_stop, &err);
        if (rc != 0) spdlog::error("[iface] {}", err);

        pipeline.Stop();
        return rc;
    } else {
        pcpp::PcapFileReaderDevice reader(cfg.source);
        if (!reader.open()) {
            spdlog::error("[conn] 打开 pcap 失败: {}", cfg.source);
            return 1;
        }
        pcpp::RawPacket raw;
        while (reader.getNextPacket(raw)) {
            pcpp::Packet pkt(&raw);
            auto* ip  = pkt.getLayerOfType<pcpp::IPv4Layer>();
            auto* tcp = pkt.getLayerOfType<pcpp::TcpLayer>();
            
            if (tcp && ip) {
                pcpp::ConnectionData conn;
                conn.srcIP = ip->getSrcIPAddress();
                conn.dstIP = ip->getDstIPAddress();
                conn.srcPort = ntohs(tcp->getTcpHeader()->portSrc);
                conn.dstPort = ntohs(tcp->getTcpHeader()->portDst);
                
                if (utils::portMatch(conn, cfg.port)) {
                    uint32_t seq = ntohl(tcp->getTcpHeader()->sequenceNumber);
                    size_t payload_len = tcp->getLayerPayloadSize();
                    if (payload_len > 0) {
                        pipeline.OnTcpData(tcp->getLayerPayload(), payload_len, seq);
                    }
                }
            } else {
                spdlog::debug("[diag] 非IPv4/TCP包");
            }
        }
        reader.close();

        pipeline.Drain();
        pipeline.Stop();
        return 0;
    }
}
