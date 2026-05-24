#include "live.hpp"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <string>
#include <thread>

#include <IPv4Layer.h>
#include <PcapFileDevice.h>
#include <Packet.h>
#include <RawPacket.h>
#include <TcpLayer.h>
#include <arpa/inet.h>
#include <spdlog/spdlog.h>

#include <rigtorp/SPSCQueue.h>
#include "capture_backend.hpp"
#include "thread_affinity.hpp"
#include "utils.hpp"

namespace {

// dump 路径用的原始 frame 缓冲。data 容量 2048 字节，能覆盖标准 MTU(1500)。
// 若 frame 超过该尺寸 capture 线程会 error 日志并跳过 dump（不影响 pipeline）。
constexpr size_t kDumpFrameCap = 2048;

struct RawPacketBuf {
    uint64_t ts_ns;
    uint32_t len;
    uint8_t  data[kDumpFrameCap];
};

void DumpWorker(const std::string& path, int cpu,
                utils::ObjectPool<RawPacketBuf>& pool,
                rigtorp::SPSCQueue<RawPacketBuf*>& queue,
                std::atomic<bool>& stop) {
    PinCurrentThreadToCpu(cpu);

    pcpp::PcapFileWriterDevice writer(path, pcpp::LINKTYPE_ETHERNET);
    if (!writer.open()) {
        spdlog::error("[dump] 无法打开 pcap 输出文件: {}", path);
        return;
    }
    spdlog::info("[dump] 开始写入 {}", path);

    auto write_one = [&](RawPacketBuf* buf) {
        timespec ts;
        ts.tv_sec  = static_cast<time_t>(buf->ts_ns / 1000000000ULL);
        ts.tv_nsec = static_cast<long>(buf->ts_ns % 1000000000ULL);
        pcpp::RawPacket raw(buf->data, static_cast<int>(buf->len),
                            ts, false, pcpp::LINKTYPE_ETHERNET);
        if (!writer.writePacket(raw)) {
            spdlog::error("[dump] writePacket 失败");
        }
        pool.free(buf);
    };

    while (!stop.load(std::memory_order_acquire)) {
        RawPacketBuf** front = queue.front();
        if (!front) {
            _mm_pause();
            continue;
        }
        write_one(*front);
        queue.pop();
    }
    // 退出前把队列里残留的全部写完
    while (auto* front = queue.front()) {
        write_one(*front);
        queue.pop();
    }
    writer.close();
    spdlog::info("[dump] 已关闭 pcap 输出 {}", path);
}

}  // namespace

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

    // dump 功能（可选）：efvi callback 把每个 frame 拷贝一份到 SPSCQueue，dump 线程写 pcap
    const bool dump_enabled = !cfg.dump_pcap.empty();
    std::unique_ptr<utils::ObjectPool<RawPacketBuf>> dump_pool;
    std::unique_ptr<rigtorp::SPSCQueue<RawPacketBuf*>> dump_queue;
    std::thread dump_thread;
    std::atomic<bool> dump_stop{false};
    std::atomic<uint64_t> dump_drops{0};
    std::atomic<uint64_t> dump_oversize{0};
    if (dump_enabled) {
        dump_pool = std::make_unique<utils::ObjectPool<RawPacketBuf>>(cfg.dump_pool_size);
        dump_queue = std::make_unique<rigtorp::SPSCQueue<RawPacketBuf*>>(cfg.dump_pool_size);
        dump_thread = std::thread(DumpWorker, cfg.dump_pcap, cfg.dump_cpu,
                                  std::ref(*dump_pool), std::ref(*dump_queue),
                                  std::ref(dump_stop));
        spdlog::info("[iface] dump 开启 path={} pool_size={} cpu={}",
                     cfg.dump_pcap, cfg.dump_pool_size, cfg.dump_cpu);
    }

    std::string cap_err;
    bool cap_ok = be->RunLive(
        cfg.iface, cfg.promisc, cfg.snaplen, stop,
        [&](const capture::CapturedPacket& p) {
            // ---- dump 路径（旁路，不阻塞）----
            if (dump_enabled) {
                if (p.len > kDumpFrameCap) {
                    dump_oversize.fetch_add(1, std::memory_order_relaxed);
                    spdlog::error("[dump] frame 超过 {} 字节 (len={}), 跳过 dump (累计 {})",
                                  kDumpFrameCap, p.len,
                                  dump_oversize.load(std::memory_order_relaxed));
                } else {
                    RawPacketBuf* buf = dump_pool->alloc();
                    if (!buf) {
                        dump_drops.fetch_add(1, std::memory_order_relaxed);
                    } else {
                        buf->ts_ns = p.ts_ns;
                        buf->len = static_cast<uint32_t>(p.len);
                        std::memcpy(buf->data, p.data, p.len);
                        if (!dump_queue->try_push(buf)) {
                            // SPSC 满（理论上 pool 满已经先触发，但稳妥起见兜底）
                            dump_pool->free(buf);
                            dump_drops.fetch_add(1, std::memory_order_relaxed);
                        }
                    }
                }
            }

            // ---- 解码路径 ----
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

    if (dump_enabled) {
        dump_stop.store(true, std::memory_order_release);
        dump_thread.join();
        const uint64_t drops = dump_drops.load(std::memory_order_relaxed);
        const uint64_t oversize = dump_oversize.load(std::memory_order_relaxed);
        if (drops || oversize) {
            spdlog::error("[dump] 结束统计: 池满丢弃={} frame超长丢弃={} —— pcap 文件不完整，请勿当作完整流量使用",
                          drops, oversize);
        } else {
            spdlog::info("[dump] 结束统计: 无丢弃，pcap 完整");
        }
    }

    return cap_ok ? 0 : 1;
}
