#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace capture {

struct OpenRetryOptions {
    int max_attempts      = 30;
    int retry_interval_ms = 2000;
};

struct CapturedPacket {
    uint64_t       ts_ns;   // CLOCK_REALTIME 纳秒
    const uint8_t* data;    // 以太网帧首字节
    size_t         len;
};

class IBackend {
public:
    virtual ~IBackend() = default;
    virtual bool RunLive(const std::string& iface, bool promiscuous, int snaplen,
                         std::atomic<bool>& stop,
                         const std::function<void(const CapturedPacket&)>& on_packet,
                         std::string& err,
                         const OpenRetryOptions& open_retry = {}) = 0;
};

std::unique_ptr<IBackend> CreateBackend(const std::string& name, std::string& err);

}  // namespace capture
