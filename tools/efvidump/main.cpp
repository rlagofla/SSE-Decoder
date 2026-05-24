// tools/efvidump/main.cpp — efvi 专用原始帧 pcap 落盘工具
//
// 架构：
//   主线程：capture::IBackend::RunLive() — efvi 抓包 + 重试逻辑全在 efvi_backend.cpp
//   Worker 线程：SPSCQueue → PcapFileWriterDevice
//
// 用法：
//   efvidump <iface> <output.pcap> [选项]
//     --promisc           混杂模式（默认关闭）
//     --pool  N           FrameBuf 池大小（默认 65536）
//     --cap-cpu   N       抓包线程绑核（默认 -1，不绑）
//     --worker-cpu N      写包线程绑核（默认 -1，不绑）
//     --retry N           efvi init 最大重试次数（默认 30）
//     --retry-ms  N       重试间隔 ms（默认 2000）

#include <atomic>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <immintrin.h>
#include <iostream>
#include <string>
#include <thread>
#include <time.h>

#include <PcapFileDevice.h>
#include <RawPacket.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <rigtorp/SPSCQueue.h>

#include "capture_backend.hpp"
#include "thread_affinity.hpp"
#include "utils.hpp"

// efvi PKT_BUF_SIZE = 2048，与 src/live.cpp 对齐
static constexpr size_t kFrameCap = 2048;

struct FrameBuf {
    uint64_t ts_ns;
    uint32_t len;
    uint8_t  data[kFrameCap];
};

static std::atomic<bool> g_stop{false};

static void sig_handler(int) { g_stop.store(true, std::memory_order_relaxed); }

// ---- Worker 线程：SPSC 出队 → 写 pcap ----
static void worker_thread(const std::string& path, int cpu,
                           utils::ObjectPool<FrameBuf>& pool,
                           rigtorp::SPSCQueue<FrameBuf*>& queue,
                           std::atomic<bool>& stop) {
    PinCurrentThreadToCpu(cpu);

    pcpp::PcapFileWriterDevice writer(path, pcpp::LINKTYPE_ETHERNET);
    if (!writer.open()) {
        spdlog::error("[worker] 无法打开输出文件: {}", path);
        return;
    }
    spdlog::info("[worker] 开始写入 {}", path);

    uint64_t written = 0;

    auto write_one = [&](FrameBuf* buf) {
        timespec ts;
        ts.tv_sec  = static_cast<time_t>(buf->ts_ns / 1000000000ULL);
        ts.tv_nsec = static_cast<long>(buf->ts_ns % 1000000000ULL);
        pcpp::RawPacket raw(buf->data, static_cast<int>(buf->len),
                            ts, false, pcpp::LINKTYPE_ETHERNET);
        if (!writer.writePacket(raw))
            spdlog::error("[worker] writePacket 失败");
        else
            ++written;
        pool.free(buf);
    };

    while (!stop.load(std::memory_order_acquire)) {
        FrameBuf** front = queue.front();
        if (!front) { _mm_pause(); continue; }
        write_one(*front);
        queue.pop();
    }
    // 退出前把残留全部写完
    while (FrameBuf** front = queue.front()) {
        write_one(*front);
        queue.pop();
    }

    writer.close();
    spdlog::info("[worker] 已关闭 {} (写入 {} 帧)", path, written);
}

int main(int argc, char** argv) {
    spdlog::set_default_logger(spdlog::stderr_color_mt("efvidump"));

    if (argc < 3) {
        std::cerr << "用法: " << argv[0] << " <iface> <output.pcap> [选项]\n"
                  << "  --promisc           混杂模式（默认关闭）\n"
                  << "  --pool  N           FrameBuf 池大小（默认 65536）\n"
                  << "  --cap-cpu   N       抓包线程绑核（默认 -1，不绑）\n"
                  << "  --worker-cpu N      写包线程绑核（默认 -1，不绑）\n"
                  << "  --retry N           efvi init 最大重试次数（默认 30）\n"
                  << "  --retry-ms  N       重试间隔 ms（默认 2000）\n";
        return 1;
    }

    const std::string iface    = argv[1];
    const std::string out_pcap = argv[2];

    bool   promisc    = false;
    size_t pool_size  = 65536;
    int    cap_cpu    = -1;
    int    worker_cpu = -1;
    int    max_retry  = 30;
    int    retry_ms   = 2000;

    for (int i = 3; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--promisc") {
            promisc = true;
        } else if (a == "--pool" && i + 1 < argc) {
            pool_size = static_cast<size_t>(std::stoul(argv[++i]));
        } else if (a == "--cap-cpu" && i + 1 < argc) {
            cap_cpu = std::stoi(argv[++i]);
        } else if (a == "--worker-cpu" && i + 1 < argc) {
            worker_cpu = std::stoi(argv[++i]);
        } else if (a == "--retry" && i + 1 < argc) {
            max_retry = std::stoi(argv[++i]);
        } else if (a == "--retry-ms" && i + 1 < argc) {
            retry_ms = std::stoi(argv[++i]);
        } else {
            spdlog::warn("[main] 未知参数 '{}'，忽略", a);
        }
    }

    spdlog::info("[main] iface={} out={} promisc={} pool={} cap_cpu={} worker_cpu={}",
                 iface, out_pcap, promisc, pool_size, cap_cpu, worker_cpu);

    std::signal(SIGINT,  sig_handler);
    std::signal(SIGTERM, sig_handler);

    utils::ObjectPool<FrameBuf> pool(pool_size);
    rigtorp::SPSCQueue<FrameBuf*> queue(pool_size);

    uint64_t drops_pool  = 0;
    uint64_t drops_queue = 0;
    uint64_t oversize    = 0;

    std::atomic<bool> worker_stop{false};
    std::thread wt(worker_thread, std::cref(out_pcap), worker_cpu,
                   std::ref(pool), std::ref(queue), std::ref(worker_stop));

    PinCurrentThreadToCpu(cap_cpu);

    std::string be_err;
    auto be = capture::CreateBackend("efvi", be_err);
    if (!be) {
        spdlog::error("[main] 创建 efvi backend 失败: {}", be_err);
        worker_stop.store(true, std::memory_order_release);
        wt.join();
        return 1;
    }

    capture::OpenRetryOptions retry{max_retry, retry_ms};

    spdlog::info("[main] 启动 efvi backend，开始抓包（Ctrl-C 停止）");

    std::string cap_err;
    bool cap_ok = be->RunLive(
        iface, promisc, /*snaplen=*/65535, g_stop,
        [&](const capture::CapturedPacket& p) {
            if (p.len > kFrameCap) {
                ++oversize;
                spdlog::error("[capture] frame 超长 len={} > {} (累计 {})",
                              p.len, kFrameCap, oversize);
                return;
            }

            FrameBuf* buf = pool.alloc();
            if (!buf) { ++drops_pool; return; }

            buf->ts_ns = p.ts_ns;
            buf->len   = static_cast<uint32_t>(p.len);
            std::memcpy(buf->data, p.data, p.len);

            if (!queue.try_push(buf)) {
                pool.free(buf);
                ++drops_queue;
            }
        },
        cap_err, retry);

    if (!cap_ok)
        spdlog::error("[main] RunLive 失败: {}", cap_err);
    else if (!cap_err.empty())
        spdlog::warn("[main] RunLive: {}", cap_err);

    spdlog::info("[main] 抓包停止：池满丢弃={} 队满丢弃={} 超长={}",
                 drops_pool, drops_queue, oversize);

    worker_stop.store(true, std::memory_order_release);
    wt.join();

    if (drops_pool || drops_queue || oversize) {
        spdlog::error("[main] 存在丢帧，pcap 文件不完整");
        return 2;
    }
    spdlog::info("[main] 完成，无丢帧");
    return cap_ok ? 0 : 1;
}
