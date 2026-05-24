#include "live.hpp"

#include <algorithm>
#include <string>

#include <IPv4Layer.h>
#include <TcpLayer.h>
#include <RawPacket.h>
#include <Packet.h>
#include <arpa/inet.h>
#include <spdlog/spdlog.h>

#include "capture_backend.hpp"
#include "thread_affinity.hpp"
#include "utils.hpp"

int RunIfaceMode(const IfaceConfig& cfg, Pipeline& pipeline, uint16_t port_filter,
                 std::atomic<bool>& stop, std::string* err_msg) {
    PinCurrentThreadToCpu(cfg.capture_cpu);

    std::string be_err;
    auto be = capture::CreateBackend(cfg.backend, be_err);
    if (!be) {
        if (err_msg) *err_msg = be_err;
        return 1;
    }

    capture::OpenRetryOptions retry;
    retry.max_attempts      = std::max(1, cfg.open_max_attempts);
    retry.retry_interval_ms = std::max(0, cfg.open_retry_ms);

    std::string cap_err;
    bool cap_ok = be->RunLive(
        cfg.iface, cfg.promisc, cfg.snaplen, stop,
        [&](const capture::CapturedPacket& p) {
            timespec ts;
            ts.tv_sec  = static_cast<time_t>(p.ts_ns / 1000000000ULL);
            ts.tv_nsec = static_cast<long>(p.ts_ns % 1000000000ULL);

            pcpp::RawPacket raw(p.data, static_cast<int>(p.len),
                                ts, false, pcpp::LINKTYPE_ETHERNET);

            pcpp::Packet pkt(&raw);
            auto* ip  = pkt.getLayerOfType<pcpp::IPv4Layer>();
            auto* tcp = pkt.getLayerOfType<pcpp::TcpLayer>();
            if (!tcp || !ip) return;

            pcpp::ConnectionData conn;
            conn.srcIP = ip->getSrcIPAddress();
            conn.dstIP = ip->getDstIPAddress();
            conn.srcPort = ntohs(tcp->getTcpHeader()->portSrc);
            conn.dstPort = ntohs(tcp->getTcpHeader()->portDst);
            if (!utils::portMatch(conn, port_filter)) return;

            uint32_t seq = ntohl(tcp->getTcpHeader()->sequenceNumber);
            size_t payload_len = tcp->getLayerPayloadSize();
            if (payload_len > 0) {
                pipeline.OnTcpData(tcp->getLayerPayload(), payload_len, seq);
            }
        },
        cap_err, retry);

    if (!cap_ok) {
        if (err_msg) *err_msg = cap_err.empty() ? "capture failed" : cap_err;
    } else if (!cap_err.empty()) {
        spdlog::warn("[iface] capture: {}", cap_err);
    }

    // 退出前把队列中残留 frame 都跑完，再 flush CSV
    pipeline.Drain();
    pipeline.FlushOutputs();
    spdlog::info("[iface] 抓包结束，已 flush CSV");

    return cap_ok ? 0 : 1;
}
