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

struct Cookie {
    Pipeline*  pl;
    uint16_t   port;
    timespec   last_ts{};
};

void onTcpData(int8_t, const pcpp::TcpStreamData& data, void* cookie) {
    auto* c = static_cast<Cookie*>(cookie);
    const auto& conn = data.getConnectionData();
    if (!utils::portMatch(conn, c->port)) return;
    if (size_t missing = data.getMissingByteCount(); missing > 0)
        spdlog::warn("[reasm] flow={} 丢失 {} 字节, 本次交付 {} 字节",
                     conn.flowKey, missing, data.getDataLength());
    char tag[64];
    std::snprintf(tag, sizeof(tag), "%s:%u->%s:%u",
        conn.srcIP.toString().c_str(), conn.srcPort,
        conn.dstIP.toString().c_str(), conn.dstPort);
    c->pl->OnTcpData(tag, c->last_ts,
        reinterpret_cast<const uint8_t*>(data.getData()), data.getDataLength());
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
        Cookie ck{ &pipeline, cfg.port, {} };

        pcpp::TcpReassemblyConfiguration tcpcfg;
        tcpcfg.maxOutOfOrderFragments = 64;
        pcpp::TcpReassembly reassembly(onTcpData, &ck, nullptr, nullptr, tcpcfg);

        pcpp::PcapFileReaderDevice reader(cfg.source);
        if (!reader.open()) {
            spdlog::error("[conn] 打开 pcap 失败: {}", cfg.source);
            return 1;
        }
        pcpp::RawPacket raw;
        while (reader.getNextPacket(raw)) {
            ck.last_ts = raw.getPacketTimeStamp();

            // ---- 诊断 ----
            pcpp::Packet pkt(&raw);
            auto* ip  = pkt.getLayerOfType<pcpp::IPv4Layer>();
            auto* tcp = pkt.getLayerOfType<pcpp::TcpLayer>();
            if (tcp) {
                bool isSyn = tcp->getTcpHeader()->synFlag;
                bool isAck = tcp->getTcpHeader()->ackFlag;
                spdlog::debug("[diag] TCP {}:{}->{} SYN={} ACK={} dataLen={}",
                    ip ? ip->getSrcIPAddress().toString() : "?",
                    ntohs(tcp->getTcpHeader()->portSrc),
                    ntohs(tcp->getTcpHeader()->portDst),
                    isSyn, isAck, tcp->getLayerPayloadSize());
            } else {
                spdlog::debug("[diag] 非TCP包");
            }
            // ---- 诊断结束 ----

            reassembly.reassemblePacket(&raw);
        }
        reader.close();

        reassembly.closeAllConnections();
        pipeline.Drain();
        pipeline.Stop();
        return 0;
    }
}
