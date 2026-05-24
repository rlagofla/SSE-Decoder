#ifdef USE_EFVI

#include "capture_backend.hpp"
#include <pollnet/Efvi.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <iostream>
#include <memory>
#include <sched.h>
#include <thread>
#include <time.h>

namespace capture {

namespace {

class EfviBackend : public IBackend {
public:
    bool RunLive(const std::string& iface, bool promiscuous, int snaplen,
                 std::atomic<bool>& stop,
                 const std::function<void(const CapturedPacket&)>& on_packet,
                 std::string& err,
                 const OpenRetryOptions& open_retry) override {
        (void)snaplen;
        const int attempts = std::max(1, open_retry.max_attempts);
        EfviEthReceiver rx;
        bool inited = false;
        for (int a = 1; a <= attempts; ++a) {
            if (stop.load(std::memory_order_acquire)) {
                err = "efvi: stop requested before init succeeded";
                return false;
            }
            if (rx.init(iface.c_str(), promiscuous)) {
                inited = true;
                break;
            }
            const char* ee = rx.getLastError();
            err = std::string("efvi: ") + (ee ? ee : "init failed");
            std::cerr << "[efvi] init attempt " << a << "/" << attempts
                      << " iface=" << iface << " failed";
            if (ee && ee[0]) std::cerr << ": " << ee;
            std::cerr << std::endl;
            rx.close();
            if (a < attempts && open_retry.retry_interval_ms > 0)
                std::this_thread::sleep_for(std::chrono::milliseconds(open_retry.retry_interval_ms));
        }
        if (!inited) return false;

        while (!stop.load()) {
            bool got = rx.read([&](const uint8_t* data, uint32_t len) {
                struct timespec ts;
                clock_gettime(CLOCK_REALTIME, &ts);
                uint64_t ts_ns = static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL
                               + static_cast<uint64_t>(ts.tv_nsec);
                CapturedPacket p{ts_ns, data, static_cast<size_t>(len)};
                on_packet(p);
            });
            if (!got) sched_yield();
        }
        rx.close();
        return true;
    }
};

}  // namespace

std::unique_ptr<IBackend> CreateEfviBackend(std::string&) {
    return std::make_unique<EfviBackend>();
}

}  // namespace capture

#endif  // USE_EFVI
