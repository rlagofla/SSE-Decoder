#include "capture_backend.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

#include <PcapLiveDevice.h>
#include <PcapLiveDeviceList.h>
#include <RawPacket.h>
#include <spdlog/spdlog.h>

namespace capture {

#ifdef USE_EFVI
extern std::unique_ptr<IBackend> CreateEfviBackend(std::string& err);
#endif

namespace {

class PcapBackend : public IBackend {
public:
    bool RunLive(const std::string& iface, bool promiscuous, int snaplen,
                 std::atomic<bool>& stop,
                 const std::function<void(const CapturedPacket&)>& on_packet,
                 std::string& err,
                 const OpenRetryOptions& open_retry) override {
        pcpp::PcapLiveDevice* dev =
            pcpp::PcapLiveDeviceList::getInstance().getDeviceByName(iface.c_str());
        if (!dev) {
            err = "pcap live: no device named " + iface;
            return false;
        }

        pcpp::PcapLiveDevice::DeviceMode mode =
            promiscuous ? pcpp::PcapLiveDevice::Promiscuous : pcpp::PcapLiveDevice::Normal;
        int sl = snaplen > 0 ? snaplen : 65535;
        pcpp::PcapLiveDevice::DeviceConfiguration cfg(mode, 0, 0, pcpp::PcapLiveDevice::PCPP_INOUT, sl, 0, true);

        const int attempts = std::max(1, open_retry.max_attempts);
        bool opened = false;
        for (int a = 1; a <= attempts; ++a) {
            if (stop.load(std::memory_order_acquire)) {
                err = "pcap live: stop requested before device open succeeded";
                return false;
            }
            if (dev->open(cfg)) {
                opened = true;
                break;
            }
            err = "pcap live: open failed for " + iface;
            std::cerr << "[pcap live] open attempt " << a << "/" << attempts
                      << " iface=" << iface << " failed" << std::endl;
            if (dev->isOpened()) dev->close();
            if (a < attempts && open_retry.retry_interval_ms > 0)
                std::this_thread::sleep_for(std::chrono::milliseconds(open_retry.retry_interval_ms));
        }
        if (!opened) return false;

        struct Cookie {
            std::atomic<bool>*                                stop;
            const std::function<void(const CapturedPacket&)>* on_packet;
        } cookie;
        cookie.stop      = &stop;
        cookie.on_packet = &on_packet;

        std::thread stats_thread([&]() {
            using Stats = pcpp::IPcapDevice::PcapStats;
            Stats prev{};
            bool have_prev = false;
            while (!stop.load()) {
                std::this_thread::sleep_for(std::chrono::seconds(5));
                if (stop.load()) break;
                Stats st{};
                dev->getStatistics(st);
                if (have_prev) {
                    uint64_t d_recv  = st.packetsRecv   - prev.packetsRecv;
                    uint64_t d_drop  = st.packetsDrop   - prev.packetsDrop;
                    uint64_t d_ifdrp = st.packetsDropByInterface - prev.packetsDropByInterface;
                    spdlog::info("[pcap-stats] recv={} drop={} ifdrop={} | +recv={} +drop={} +ifdrop={}",
                                 st.packetsRecv, st.packetsDrop, st.packetsDropByInterface,
                                 d_recv, d_drop, d_ifdrp);
                } else {
                    spdlog::info("[pcap-stats] recv={} drop={} ifdrop={}",
                                 st.packetsRecv, st.packetsDrop, st.packetsDropByInterface);
                }
                prev = st;
                have_prev = true;
            }
        });

        while (!stop.load()) {
            dev->startCaptureBlockingMode(
                [](pcpp::RawPacket* raw, pcpp::PcapLiveDevice*, void* user) -> bool {
                    auto* c = static_cast<Cookie*>(user);
                    if (c->stop->load()) return true;
                    const timespec& ts_os = raw->getPacketTimeStamp();
                    uint64_t ts_ns = static_cast<uint64_t>(ts_os.tv_sec) * 1000000000ULL
                                   + static_cast<uint64_t>(ts_os.tv_nsec);
                    CapturedPacket p{ts_ns, raw->getRawData(), static_cast<size_t>(raw->getRawDataLen())};
                    (*c->on_packet)(p);
                    return false;
                },
                &cookie, 1.0);
        }
        if (stats_thread.joinable()) stats_thread.join();

        pcpp::IPcapDevice::PcapStats final_st{};
        dev->getStatistics(final_st);
        spdlog::info("[pcap-stats] FINAL recv={} drop={} ifdrop={}",
                     final_st.packetsRecv, final_st.packetsDrop, final_st.packetsDropByInterface);

        dev->close();
        return true;
    }
};

}  // namespace

std::unique_ptr<IBackend> CreateBackend(const std::string& name, std::string& err) {
    std::string b = name;
    for (auto& c : b) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    if (b == "efvi") {
#ifdef USE_EFVI
        return CreateEfviBackend(err);
#else
        err = "efvi backend not built (CMake -DUSE_EFVI=ON and Onload + 3rd/pollnet/Efvi.h)";
        return {};
#endif
    }
    if (b != "pcap" && !b.empty()) {
        err = "unknown backend: " + name + " (use pcap or efvi)";
        return {};
    }
    (void)err;
    return std::make_unique<PcapBackend>();
}

}  // namespace capture
