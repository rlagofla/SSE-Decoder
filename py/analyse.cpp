// analyse.cpp — pcap 数据包分布统计，结果写入 CSV 供 Python 分析

#include <ctime>
#include <fstream>
#include <map>
#include <string>
#include <vector>

#include <EthLayer.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <IcmpLayer.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include "analyse_config.hpp"

static bool portMatches(uint16_t src, uint16_t dst) {
    if (FILTER_PORTS.empty()) return true;
    for (int p : FILTER_PORTS)
        if (src == p || dst == p) return true;
    return false;
}

template<typename K>
static bool writeCSV(const std::map<K, long>& m, const std::string& path, const char* header) {
    std::ofstream f(path);
    if (!f.is_open()) { spdlog::error("无法创建文件: {}", path); return false; }
    f << header << "\n";
    for (const auto& [k, c] : m) f << k << "," << c << "\n";
    return true;
}

int main() {
    spdlog::set_default_logger(spdlog::stderr_color_mt("console"));

    pcpp::PcapFileReaderDevice reader(PCAP_FILE);
    if (!reader.open()) {
        spdlog::error("打开 pcap 失败: {}", PCAP_FILE);
        return 1;
    }

    struct PerMin { long pkt = 0; long bytes = 0; };

    // key: "IP,port"，用逗号方便 Python 直接 read_csv
    std::map<std::string, long>   src_ip_port;
    std::map<std::string, long>   dst_ip_port;
    std::map<std::string, PerMin> per_minute;   // key: "YYYY-MM-DD HH:MM"
    std::map<std::string, long>   proto_all;    // 全量包协议分布
    std::map<std::string, long>   proto_matched;// 命中端口的包协议分布
    long total = 0, matched = 0;
    long magic_hit = 0, magic_miss = 0;         // payload 开头是否为 00 04 c4 53

    pcpp::RawPacket raw;
    while (reader.getNextPacket(raw)) {
        ++total;
        pcpp::Packet pkt(&raw, pcpp::OsiModelTransportLayer);

        // 全量协议统计（在端口过滤之前）
        {
            std::string proto;
            if      (pkt.getLayerOfType<pcpp::TcpLayer>())  proto = "TCP";
            else if (pkt.getLayerOfType<pcpp::UdpLayer>())  proto = "UDP";
            else if (pkt.getLayerOfType<pcpp::IcmpLayer>()) proto = "ICMP";
            else if (pkt.getLayerOfType<pcpp::IPv4Layer>()) proto = "IPv4-other";
            else if (pkt.getLayerOfType<pcpp::IPv6Layer>()) proto = "IPv6";
            else if (pkt.getLayerOfType<pcpp::EthLayer>())  proto = "Eth-other";
            else                                             proto = "other";
            ++proto_all[proto];
        }

        auto* ip4 = pkt.getLayerOfType<pcpp::IPv4Layer>();
        if (!ip4) continue;

        uint16_t src_port = 0, dst_port = 0;
        size_t   payload  = 0;
        std::string proto_name;
        if (auto* tcp = pkt.getLayerOfType<pcpp::TcpLayer>()) {
            src_port   = tcp->getSrcPort();
            dst_port   = tcp->getDstPort();
            payload    = tcp->getLayerPayloadSize();
            proto_name = "TCP";
        } else if (auto* udp = pkt.getLayerOfType<pcpp::UdpLayer>()) {
            src_port   = udp->getSrcPort();
            dst_port   = udp->getDstPort();
            payload    = udp->getLayerPayloadSize();
            proto_name = "UDP";
        } else {
            proto_name = "IPv4-other";
        }

        if (!portMatches(src_port, dst_port)) continue;
        ++matched;
        ++proto_matched[proto_name];

        // 魔数校验
        if (payload >= 4) {
            const uint8_t* pd = nullptr;
            if (auto* tcp = pkt.getLayerOfType<pcpp::TcpLayer>())      pd = tcp->getLayerPayload();
            else if (auto* udp = pkt.getLayerOfType<pcpp::UdpLayer>()) pd = udp->getLayerPayload();
            if (pd && pd[0]==0x00 && pd[1]==0x04 && pd[2]==0xc4 && pd[3]==0x53) ++magic_hit;
            else ++magic_miss;
        }

        // payload hex 打印（受 PAYLOAD_PRINT_BYTES 控制）
        if (PAYLOAD_PRINT_BYTES != 0 && payload > 0) {
            const uint8_t* pd = nullptr;
            size_t pd_len = 0;
            if (auto* tcp = pkt.getLayerOfType<pcpp::TcpLayer>()) {
                pd = tcp->getLayerPayload();
                pd_len = tcp->getLayerPayloadSize();
            } else if (auto* udp = pkt.getLayerOfType<pcpp::UdpLayer>()) {
                pd = udp->getLayerPayload();
                pd_len = udp->getLayerPayloadSize();
            }
            if (pd && pd_len > 0) {
                size_t print_len = (PAYLOAD_PRINT_BYTES < 0)
                    ? pd_len
                    : std::min(pd_len, size_t(PAYLOAD_PRINT_BYTES));
                auto ts2 = raw.getPacketTimeStamp();
                time_t s2 = ts2.tv_sec;
                struct tm tm2{};
                localtime_r(&s2, &tm2);
                char tbuf[20];
                std::strftime(tbuf, sizeof(tbuf), "%H:%M:%S", &tm2);
                spdlog::info("[payload] {} {}:{}->{} {} len={} (printing {})",
                    tbuf, src_port, dst_port, proto_name, pd_len, print_len);
                for (size_t off = 0; off < print_len; off += 16) {
                    char hex[64] = {};
                    size_t row = std::min(print_len - off, size_t(16));
                    for (size_t i = 0; i < row; ++i)
                        std::snprintf(hex + i * 3, 4, "%02x ", pd[off + i]);
                    spdlog::info("  {:04x}: {}", off, hex);
                }
            }
        }

        std::string src_ip = ip4->getSrcIPAddress().toString();
        std::string dst_ip = ip4->getDstIPAddress().toString();
        ++src_ip_port[src_ip + "," + std::to_string(src_port)];
        ++dst_ip_port[dst_ip + "," + std::to_string(dst_port)];

        auto   ts  = raw.getPacketTimeStamp();
        time_t sec = ts.tv_sec;
        struct tm t{};
        localtime_r(&sec, &t);
        char buf[20];
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", &t);
        auto& pm = per_minute[buf];
        ++pm.pkt;
        pm.bytes += long(payload);

        if (total % 1000000 == 0)
            spdlog::info("已处理 {}M 包... 时间 {}", total / 1000000, buf);
    }
    reader.close();

    spdlog::info("共 {} 包，命中 {} 包，开始写文件...", total, matched);
    spdlog::info("魔数统计: 命中={} 未命中={} (payload<4字节不计入)", magic_hit, magic_miss);

    writeCSV(src_ip_port,   OUT_SRC_IP_PORT,    "src_ip,src_port,count");
    writeCSV(dst_ip_port,   OUT_DST_IP_PORT,    "dst_ip,dst_port,count");
    writeCSV(proto_all,     OUT_PROTO_ALL,       "proto,count");
    writeCSV(proto_matched, OUT_PROTO_MATCHED,   "proto,count");
    {
        std::ofstream f(OUT_PER_MINUTE);
        f << "minute,count,bytes\n";
        for (const auto& [k, v] : per_minute) f << k << "," << v.pkt << "," << v.bytes << "\n";
    }

    spdlog::info("完成 -> {}, {}, {}, {}, {}",
        OUT_SRC_IP_PORT, OUT_DST_IP_PORT, OUT_PER_MINUTE,
        OUT_PROTO_ALL, OUT_PROTO_MATCHED);
    return 0;
}
