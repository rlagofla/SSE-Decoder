#include "live.hpp"

#include <algorithm>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include <IPv4Layer.h>
#include <TcpLayer.h>
#include <RawPacket.h>
#include <Packet.h>
#include <arpa/inet.h>
#include <spdlog/spdlog.h>

#include "bin_io.hpp"
#include "capture_backend.hpp"
#include "thread_affinity.hpp"
#include "utils.hpp"

namespace {

static std::string effectiveBinPrefix(const IfaceConfig& cfg) {
    std::string p = cfg.bin_prefix;
    if (p.empty()) p = "cap_" + cfg.iface;
    return p;
}

}  // namespace

int RunIfaceMode(const IfaceConfig& cfg, Pipeline& pipeline, uint16_t port_filter,
                 std::atomic<bool>& stop, std::string* err_msg) {
    bin::BinRotateSync sync;
    sync.write_segment.store(1);
    sync.capture_running.store(true);

    const std::string prefix = effectiveBinPrefix(cfg);

    std::string writer_err;
    std::string reader_err;

    std::thread writer_thread([&]() {
        PinCurrentThreadToCpu(cfg.writer_cpu);

        std::string be_err;
        auto be = capture::CreateBackend(cfg.backend, be_err);
        if (!be) {
            std::cerr << "[iface writer] " << be_err << std::endl;
            stop.store(true);
            sync.capture_running.store(false);
            return;
        }

        bin::BinRecorder rec;
        rec.AttachRotateSync(&sync);
        rec.AttachStopOnIoError(&stop);

        std::string open_err;
        if (!rec.Open(cfg.bin_dir, prefix, cfg.segment_bytes, &open_err)) {
            std::cerr << "[iface writer] " << open_err << std::endl;
            stop.store(true);
            sync.capture_running.store(false);
            return;
        }

        capture::OpenRetryOptions retry;
        retry.max_attempts      = std::max(1, cfg.open_max_attempts);
        retry.retry_interval_ms = std::max(0, cfg.open_retry_ms);

        std::string cap_err;
        bool cap_ok = be->RunLive(
            cfg.iface, cfg.promisc, cfg.snaplen, stop,
            [&](const capture::CapturedPacket& p) {
                rec.WriteRecord(p.ts_ns, p.data, p.len);
            },
            cap_err, retry);

        if (!cap_ok) {
            std::cerr << "[iface writer] capture failed";
            if (!cap_err.empty()) std::cerr << ": " << cap_err;
            std::cerr << std::endl;
            stop.store(true);
        } else if (!cap_err.empty()) {
            std::cerr << "[iface writer] capture: " << cap_err << std::endl;
        }

        rec.Close();
        sync.capture_running.store(false);
    });

    std::thread reader_thread([&]() {
        PinCurrentThreadToCpu(cfg.reader_cpu);

        bin::BinReader rd;
        rd.AttachRotateSync(&sync);

        std::string open_err;
        if (!rd.Open(cfg.bin_dir, prefix, &open_err)) {
            std::cerr << "[iface reader] " << open_err << std::endl;
            return;
        }
        if (cfg.delete_bin_after_read) rd.SetDeleteSegmentAfterRead(true);

        if (cfg.flush_csv_per_segment) {
            rd.SetOnSegmentClosed([&](int seg) {
                // Drain 保证 Worker idle 后再 flush，避免与 Worker 写 CSV 竞争
                pipeline.Drain();
                pipeline.FlushOutputs();
                spdlog::info("[iface] seg={} 已刷 CSV", seg);
            });
        }

        std::vector<uint8_t> pkt_buf;
        for (;;) {
            uint64_t ts_ns;
            if (!rd.ReadNext(&ts_ns, &pkt_buf)) {
                if (stop.load() && !sync.capture_running.load() && rd.exhausted()) break;
                continue;
            }
            timespec ts;
            ts.tv_sec  = static_cast<time_t>(ts_ns / 1000000000ULL);
            ts.tv_nsec = static_cast<long>(ts_ns % 1000000000ULL);

            pcpp::RawPacket raw(pkt_buf.data(), static_cast<int>(pkt_buf.size()),
                                ts, false, pcpp::LINKTYPE_ETHERNET);
            
            pcpp::Packet pkt(&raw);
            auto* ip  = pkt.getLayerOfType<pcpp::IPv4Layer>();
            auto* tcp = pkt.getLayerOfType<pcpp::TcpLayer>();
            
            if (tcp && ip) {
                pcpp::ConnectionData conn;
                conn.srcIP = ip->getSrcIPAddress();
                conn.dstIP = ip->getDstIPAddress();
                conn.srcPort = ntohs(tcp->getTcpHeader()->portSrc);
                conn.dstPort = ntohs(tcp->getTcpHeader()->portDst);
                
                if (utils::portMatch(conn, port_filter)) {
                    uint32_t seq = ntohl(tcp->getTcpHeader()->sequenceNumber);
                    size_t payload_len = tcp->getLayerPayloadSize();
                    if (payload_len > 0) {
                        // char tag[64];
                        // std::snprintf(tag, sizeof(tag), "%s:%u->%s:%u",
                        //     conn.srcIP.toString().c_str(), conn.srcPort,
                        //     conn.dstIP.toString().c_str(), conn.dstPort);
                        pipeline.OnTcpData(tcp->getLayerPayload(), payload_len, seq);
                    }
                }
            }
        }

        pipeline.Drain();
        pipeline.FlushOutputs();

        spdlog::info("[iface] reader 采集结束，seg={}", rd.ReadSegmentNumber());
        if (cfg.delete_bin_after_read) rd.CloseAndDeleteCurrentSegment();
    });

    writer_thread.join();
    reader_thread.join();
    return 0;
}