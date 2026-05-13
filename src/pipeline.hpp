#pragma once
// pipeline.hpp — 多线程 Pipeline（Assembler + MPMCQueue + Worker）
//
// 架构：
//   主线程：pcpp::TcpReassembly → Assembler::OnTcpData → 入队
//   Worker：出队 → Splitter 切 STEP 帧 → Handler 分发 → ua5803/ua3202 emit → CSV
//
// 单流设计：实测 SSE 全天只有一条 TCP 四元组，Splitter 全局只有一个实例。

#include <atomic>
#include <cstring>
#include <immintrin.h>
#include <memory>
#include <ostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <spdlog/spdlog.h>

#include "MPMCQueue.h"
#include "ua3202.hpp"
#include "ua5803.hpp"
#include "utils.hpp"

// =========================================================
// [配置]
// =========================================================
inline constexpr size_t kTcpDataPoolSize = 32768;  // 32768 × ~65KB ≈ 2GB

// =========================================================
// [数据结构]
// =========================================================

struct StepFrame {
    uint32_t       category_id  = 0;
    uint32_t       msg_type     = 0;
    uint32_t       msg_seq_id   = 0;
    std::string    sending_time;
    const uint8_t* payload      = nullptr;
    size_t         payload_len  = 0;
    size_t         total_len    = 0;
};

struct ActiveType {
    uint32_t      category_id;
    uint32_t      msg_type;
    bool          dedup;
    std::ostream* out;  // 生命周期由 main 管理
};

struct TcpDataItem {
    char     tag[64];          // "src:port->dst:port"，主线程填，Worker 首次用于初始化 stream_tag
    timespec ts;
    size_t   len;
    uint8_t  data[64 * 1024];  // 64KB，覆盖 TCP 单次回调最大数据量
};

// =========================================================
// [ObjectPool] 对象池（对应 SZSE 的 MPMCObjectPool）
// =========================================================
class ObjectPool {
    std::vector<TcpDataItem> storage_;
    rigtorp::MPMCQueue<TcpDataItem*> free_queue_;
public:
    explicit ObjectPool(size_t capacity) : free_queue_(capacity) {
        storage_.resize(capacity);
        for (size_t i = 0; i < capacity; ++i)
            (void)free_queue_.try_push(&storage_[i]);
    }

    TcpDataItem* alloc() {
        TcpDataItem* item = nullptr;
        if (free_queue_.try_pop(item)) return item;
        return nullptr;
    }

    void free(TcpDataItem* ptr) {
        if (ptr) {
            while (!free_queue_.try_push(ptr)) _mm_pause();
        }
    }
};

// =========================================================
// [Handler] 业务帧分发（对应 SZSE 的 SzseBizHandler）
// =========================================================
class Handler {
    std::vector<ActiveType> types_;
public:
    void ConfigureTypes(std::vector<ActiveType> types) { types_ = std::move(types); }

    void OnFrame(const StepFrame& frame, const timespec& ts,
                 const std::string& stream_tag, uint32_t& frame_idx) {
        for (auto& t : types_) {
            if (t.category_id != frame.category_id || t.msg_type != frame.msg_type) continue;

            ++frame_idx;

            if (!frame.payload || frame.payload_len == 0) {
                spdlog::warn("[pipeline] {} frame#{} ts={} payload 为空，跳过 msg_seq_id={}",
                    stream_tag, frame_idx, utils::fmtPktTime(ts), frame.msg_seq_id);
                return;
            }
            spdlog::debug("[pipeline] {} frame#{} ts={} msg_seq_id={} sending_time={} payload_len={}",
                stream_tag, frame_idx, utils::fmtPktTime(ts), frame.msg_seq_id,
                frame.sending_time, frame.payload_len);

            switch ((uint64_t(t.category_id) << 32) | t.msg_type) {
                case (uint64_t(9) << 32) | 5803: {
                    ua5803::Parser parser(frame.payload, frame.payload_len);
                    ua5803::Msg    rec;
                    size_t         rec_idx = 0;
                    while (parser.next(rec)) {
                        ua5803::emit(rec, frame.msg_seq_id, frame_idx, rec_idx++, t.dedup, *t.out);
                        spdlog::trace("[pipeline] ts={}, emit 成功，TickTime {}",
                            utils::fmtPktTime(ts), rec.tick_time);
                    }
                    break;
                }
                case (uint64_t(6) << 32) | 3202: {
                    ua3202::Parser parser(frame.payload, frame.payload_len);
                    ua3202::Msg    rec;
                    size_t         rec_idx = 0;
                    while (parser.next(rec))
                        ua3202::emit(rec, frame.msg_seq_id, frame_idx, rec_idx++, t.dedup, *t.out);
                    break;
                }
                default:
                    spdlog::warn("[pipeline] {} 类型 ({},{}) 已配置但暂未实现，跳过",
                        stream_tag, t.category_id, t.msg_type);
            }
            spdlog::debug("[pipeline] ts={}, handle 成功，类型 ({},{})",
                utils::fmtPktTime(ts), frame.category_id, frame.msg_type);
            return;
        }
        spdlog::debug("[pipeline] {} 帧 category_id={} msg_type={} 不在配置中，跳过 payload_len={}",
            stream_tag, frame.category_id, frame.msg_type, frame.payload_len);
    }
};

// =========================================================
// [Splitter] TCP 字节流切帧（Worker 端，原 pipeline.hpp 改造）
// =========================================================
class Splitter {
public:
    std::string stream_tag;
    Handler*    handler_ = nullptr;

    void feed(const uint8_t* data, size_t len, const timespec& ts) {
        if (kBufCap - wpos_ < len) compact();
        if (kBufCap - wpos_ < len) {
            spdlog::error("[splitter] {} 缓冲区溢出：已缓存 {} 字节 + 新到 {} 字节 > {} KB，清空重置",
                stream_tag, wpos_ - rpos_, len, kBufCap >> 10);
            rpos_ = wpos_ = 0;
            return;
        }
        std::memcpy(buf_ + wpos_, data, len);
        wpos_ += len;
        drain(ts);
    }

private:
    static constexpr uint8_t kMagicBytes[13] = {
        '8','=','S','T','E','P','.','1','.','0','.','0','\x01'
    };
    static constexpr size_t kMagicLen = 13;
    static constexpr size_t kBufCap   = 1u << 20;  // 1MB

    uint8_t  buf_[kBufCap];
    uint32_t frame_idx_ = 0;
    size_t   rpos_      = 0;
    size_t   wpos_      = 0;

    void drain(const timespec& ts) {
        while (true) {
            const uint8_t* base  = buf_ + rpos_;
            size_t         avail = wpos_ - rpos_;

            auto* p = static_cast<const uint8_t*>(memmem(base, avail, kMagicBytes, kMagicLen));
            if (!p) {
                if (avail > kMagicLen - 1) {
                    spdlog::warn("[splitter] ts={}, {} 未找到魔数，丢弃 {} 字节",
                        utils::fmtPktTime(ts), stream_tag, avail - (kMagicLen - 1));
                    rpos_ = wpos_ - (kMagicLen - 1);
                }
                return;
            }
            if (p > base) {
                spdlog::warn("[splitter] ts={}, {} 魔数前有 {} 字节无效数据，跳过",
                    utils::fmtPktTime(ts), stream_tag, p - base);
                rpos_ += p - base;
                base = p; avail = wpos_ - rpos_;
            }

            if (avail < kMagicLen + 4) return;

            if (base[kMagicLen] != '9' || base[kMagicLen + 1] != '=') {
                spdlog::warn("[splitter] ts={}, {} magic 后未找到 9= 字段，跳过魔数",
                    utils::fmtPktTime(ts), stream_tag);
                rpos_ += kMagicLen;
                continue;
            }
            auto* soh = static_cast<const uint8_t*>(
                memchr(base + kMagicLen + 2, '\x01', avail - kMagicLen - 2));
            if (!soh) return;

            size_t body_len = 0;
            bool   parse_ok = true;
            for (auto* q = base + kMagicLen + 2; q < soh; ++q) {
                if (*q < '0' || *q > '9') { parse_ok = false; break; }
                body_len = body_len * 10 + (*q - '0');
            }
            if (!parse_ok) {
                spdlog::warn("[splitter] ts={}, {} 9= 字段值解析失败，跳过魔数",
                    utils::fmtPktTime(ts), stream_tag);
                rpos_ += kMagicLen;
                continue;
            }

            size_t nine_field_len = static_cast<size_t>(soh + 1 - (base + kMagicLen));
            size_t total          = kMagicLen + nine_field_len + body_len + 7;
            if (total > 16u * 1024u * 1024u) {
                spdlog::warn("[splitter] ts={}, {} 帧长度异常 total_len={}，跳过魔数",
                    utils::fmtPktTime(ts), stream_tag, total);
                rpos_ += kMagicLen;
                continue;
            }
            if (avail < total) {
                spdlog::debug("[splitter] ts={}, {} 帧数据不完整: need={} have={}，等待",
                    utils::fmtPktTime(ts), stream_tag, total, avail);
                return;
            }

            StepFrame frame = parseStepFrame(base, total);
            handler_->OnFrame(frame, ts, stream_tag, frame_idx_);
            rpos_ += total;
        }
    }

    void compact() {
        std::memmove(buf_, buf_ + rpos_, wpos_ - rpos_);
        wpos_ -= rpos_;
        rpos_ = 0;
    }

    StepFrame parseStepFrame(const uint8_t* buf, size_t total_len) {
        StepFrame frame;
        frame.total_len = total_len;

        size_t pos = kMagicLen;
        while (pos < total_len && buf[pos] != '\x01') ++pos;
        if (pos < total_len) ++pos;

        uint32_t raw_data_len = 0;

        while (pos < total_len) {
            size_t eq = pos;
            while (eq < total_len && buf[eq] != '=') ++eq;
            if (eq >= total_len) break;

            std::string tag(reinterpret_cast<const char*>(buf + pos), eq - pos);
            pos = eq + 1;

            if (tag == "10") break;

            if (tag == "96") {
                frame.payload     = buf + pos;
                frame.payload_len = raw_data_len;
                pos += raw_data_len;
                if (pos < total_len && buf[pos] == '\x01') ++pos;
                continue;
            }

            size_t soh = pos;
            while (soh < total_len && buf[soh] != '\x01') ++soh;
            std::string value(reinterpret_cast<const char*>(buf + pos), soh - pos);
            pos = soh + 1;

            try {
                if (tag == "35" && value.size() > 2) {
                    frame.msg_type = uint32_t(std::stoul(value.substr(2)));
                } else if (tag == "10142") {
                    frame.category_id = uint32_t(std::stoul(value));
                } else if (tag == "10072") {
                    frame.msg_seq_id = uint32_t(std::stoul(value));
                } else if (tag == "95") {
                    raw_data_len = uint32_t(std::stoul(value));
                } else if (tag == "52") {
                    frame.sending_time = value;
                } else if (tag == "49" && value != "VDE") {
                    spdlog::warn("[pipeline] {} SenderCompID 异常: {}", stream_tag, utils::escapeStr(value));
                } else if (tag == "56" && value != "VSS") {
                    spdlog::warn("[pipeline] {} TargetCompID 异常: {}", stream_tag, utils::escapeStr(value));
                }
            } catch (...) {
                spdlog::warn("[pipeline] {} tag={} 值解析失败: {}", stream_tag, tag, utils::escapeStr(value));
            }
        }

        return frame;
    }
};

// =========================================================
// [Assembler] TCP 数据搬运入队（对应 SZSE 的 SzseAssembler，极简版）
// =========================================================
class Assembler {
    ObjectPool& pool_;
    rigtorp::MPMCQueue<TcpDataItem*>& out_queue_;
    std::atomic<size_t>* pending_;
public:
    Assembler(ObjectPool& pool, rigtorp::MPMCQueue<TcpDataItem*>& q, std::atomic<size_t>* pending)
        : pool_(pool), out_queue_(q), pending_(pending) {}

    // tag 由主线程构建（"src:port->dst:port"），端口过滤由调用方完成
    void OnTcpData(const char* tag, const timespec& ts, const uint8_t* data, size_t len) {
        const size_t kChunk = sizeof(TcpDataItem::data);
        size_t offset = 0;
        while (offset < len) {
            size_t chunk = std::min(len - offset, kChunk);
            TcpDataItem* item = pool_.alloc();
            while (!item) { _mm_pause(); item = pool_.alloc(); }
            std::strncpy(item->tag, tag, sizeof(item->tag) - 1);
            item->tag[sizeof(item->tag) - 1] = '\0';
            item->ts  = ts;
            item->len = chunk;
            std::memcpy(item->data, data + offset, chunk);
            while (!out_queue_.try_push(item)) _mm_pause();
            pending_->fetch_add(1, std::memory_order_release);
            offset += chunk;
        }
    }
};

// =========================================================
// [Worker] 消费线程（对应 SZSE 的 SzseWorker）
// =========================================================
class Worker {
    Splitter splitter_;
    Handler  handler_;
    volatile bool running_ = true;
public:
    Worker() { splitter_.handler_ = &handler_; }

    void ConfigureTypes(std::vector<ActiveType> types) { handler_.ConfigureTypes(std::move(types)); }
    void Stop() { running_ = false; }

    void Run(rigtorp::MPMCQueue<TcpDataItem*>& q, ObjectPool& pool, std::atomic<size_t>* pending) {
        TcpDataItem* item = nullptr;
        while (running_) {
            if (q.try_pop(item)) {
                if (splitter_.stream_tag.empty() && item->tag[0])
                    splitter_.stream_tag = item->tag;
                splitter_.feed(item->data, item->len, item->ts);
                pool.free(item);
                pending->fetch_sub(1, std::memory_order_release);
            } else {
                _mm_pause();
            }
        }
        while (q.try_pop(item)) {
            if (splitter_.stream_tag.empty() && item->tag[0])
                splitter_.stream_tag = item->tag;
            splitter_.feed(item->data, item->len, item->ts);
            pool.free(item);
            pending->fetch_sub(1, std::memory_order_release);
        }
    }
};

// =========================================================
// [Pipeline] 顶层控制器（对应 SZSE 的 SzsePipeline）
// =========================================================
class Pipeline {
    ObjectPool pool_;
    rigtorp::MPMCQueue<TcpDataItem*> queue_;
    Worker worker_;
    std::thread worker_thread_;
    Assembler assembler_;
    std::atomic<size_t> pending_{0};
public:
    Pipeline()
        : pool_(kTcpDataPoolSize),
          queue_(kTcpDataPoolSize),
          assembler_(pool_, queue_, &pending_) {}

    void ConfigureTypes(std::vector<ActiveType> types) { worker_.ConfigureTypes(std::move(types)); }

    void Start() {
        worker_thread_ = std::thread([this] { worker_.Run(queue_, pool_, &pending_); });
    }

    void Drain() {
        while (pending_.load(std::memory_order_acquire) != 0) std::this_thread::yield();
    }

    void Stop() {
        worker_.Stop();
        if (worker_thread_.joinable()) worker_thread_.join();
    }

    void OnTcpData(const char* tag, const timespec& ts, const uint8_t* data, size_t len) {
        assembler_.OnTcpData(tag, ts, data, len);
    }
};
