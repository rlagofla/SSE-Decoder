#pragma once
// pipeline.hpp — 多线程 Pipeline（Assembler + MPMCQueue + Worker）
//
// 架构：
//   主线程：手动解析包 → Assembler::OnTcpData → 切帧 → 入队
//   Worker：出队 → Handler 分发 → ua5803/ua3202 emit → CSV

#include <atomic>
#include <cstring>
#include <immintrin.h>
#include <memory>
#include <ostream>
#include <string>
#include <thread>
#include <vector>

#include <spdlog/spdlog.h>

#include <rigtorp/MPMCQueue.h>
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

struct FrameItem {
    uint32_t category_id  = 0;
    uint32_t msg_type     = 0;
    uint32_t frame_seq    = 0;   // 帧头 16-19 字节，按 (category_id,msg_type) 单调 +1
    bool     compressed   = false;

    size_t   payload_len  = 0;
    uint8_t  payload[64 * 1024];
};

struct ActiveType {
    uint32_t      category_id;
    uint32_t      msg_type;
    bool          dedup;
    std::ostream* out;  // 生命周期由 main 管理
};

// =========================================================
// [Handler] 业务帧分发
// =========================================================
class Handler {
    std::vector<ActiveType> types_;
public:
    void ConfigureTypes(std::vector<ActiveType> types) { types_ = std::move(types); }

    void OnFrame(const FrameItem* frame, const std::string& local_time, uint64_t& rec_idx) {
        for (auto& t : types_) {
            if (t.category_id != frame->category_id || t.msg_type != frame->msg_type) continue;

            if (frame->payload_len == 0) {
                spdlog::warn("[pipeline] frame frame_seq={} payload 为空，跳过", frame->frame_seq);
                return;
            }
            spdlog::debug("[pipeline] frame frame_seq={} compressed={} payload_len={}", frame->frame_seq, frame->compressed, frame->payload_len);

            switch ((uint64_t(t.category_id) << 32) | t.msg_type) {
                case (uint64_t(9) << 32) | 5803: {
                    ua5803::Parser parser(frame->payload, frame->payload_len);
                    ua5803::Msg    rec;
                    while (parser.next(rec)) {
                        ua5803::emit(rec, frame->frame_seq, local_time, rec_idx++, t.dedup, *t.out);
                        spdlog::trace("[pipeline] emit 成功，TickTime {}", rec.tick_time);
                    }
                    break;
                }
                case (uint64_t(6) << 32) | 3202: {
                    ua3202::Parser parser(frame->payload, frame->payload_len);
                    ua3202::Msg    rec;
                    while (parser.next(rec))
                        ua3202::emit(rec, frame->frame_seq, local_time, rec_idx++, t.dedup, *t.out);
                    break;
                }
                default:
                    spdlog::warn("[pipeline] 类型 ({},{}) 已配置但暂未实现，跳过", t.category_id, t.msg_type);
            }
            spdlog::debug("[pipeline] handle 成功，类型 ({},{})", frame->category_id, frame->msg_type);
            return;
        }
        spdlog::debug("[pipeline] 帧 category_id={} msg_type={} 不在配置中，跳过 payload_len={}", frame->category_id, frame->msg_type, frame->payload_len);
    }
};

// =========================================================
// [Assembler] TCP 序列号校验 + 字节流切帧入队
//
// 帧格式（40B 定长头 + payload）:
//   0-3   Magic 0x0004C453 (大端)
//   4-7   整帧长度（含 40B 头, 大端）
//   8-11  category_id (大端)
//   12-15 msg_type    (大端)
//   16-19 frame_seq   (大端, 按 (cat,type) 单调 +1)
//   20-23 = 0
//   24-27 时间戳/相关
//   28-31 0 或 0x08000000
//   32-35 压缩标志 0/1
//   36-39 0/1/0xF
// =========================================================
class Assembler {
    utils::ObjectPool<FrameItem>& pool_;
    rigtorp::MPMCQueue<FrameItem*>& out_queue_;
    std::atomic<size_t>* pending_;

    bool     seq_initialized_ = false;
    uint32_t expected_seq_    = 0;

    static constexpr uint32_t kMagic    = 0x0004C453;
    static constexpr size_t   kHeaderLen = 40;
    static constexpr size_t   kMaxFrame  = 16u * 1024u * 1024u;
    static constexpr size_t   kBufCap    = 1u << 20;  // 1MB

    uint8_t  buf_[kBufCap];
    size_t   rpos_ = 0;
    size_t   wpos_ = 0;

    std::string getBuf() {
        std::string buf_preview = "'";
        size_t preview_len = std::min(wpos_ - rpos_, (size_t)32);
        for (size_t i = 0; i < preview_len; ++i) {
            uint8_t c = buf_[rpos_ + i];
            if (c >= 32 && c <= 126 && c != '\'' && c != '\\') {
                buf_preview += static_cast<char>(c);
            } else {
                char hex[5];
                std::snprintf(hex, sizeof(hex), "\\x%02x", c);
                buf_preview += hex;
            }
        }
        buf_preview += "'";
        return buf_preview;
    }

    bool isLuan = false;

public:
    Assembler(utils::ObjectPool<FrameItem>& pool, rigtorp::MPMCQueue<FrameItem*>& q, std::atomic<size_t>* pending)
        : pool_(pool), out_queue_(q), pending_(pending) {}

    void OnTcpData(const uint8_t* data, size_t len, uint32_t seq) {
        if (!seq_initialized_) {
            expected_seq_ = seq + len;
            seq_initialized_ = true;
            isLuan = false;
        } else {
            int32_t diff = static_cast<int32_t>(seq - expected_seq_);
            if (diff < 0) {
                spdlog::warn("[assembler] 重传包: seq={} expected_seq={} (diff={})，丢弃", seq, expected_seq_, diff);
                isLuan = false;
                return;
            } else if (diff > 0) {
                spdlog::warn("[assembler] 乱序/丢包: seq={} expected_seq={} (diff={})，清空残余缓冲区 (len={}, preview={})", seq, expected_seq_, diff, wpos_ - rpos_, getBuf());
                rpos_ = wpos_ = 0;
                expected_seq_ = seq + len;
                isLuan = true;
            } else {
                expected_seq_ = seq + len;
                isLuan = false;
            }
        }

        if (kBufCap - wpos_ < len) compact();
        if (kBufCap - wpos_ < len) {
            spdlog::error("[assembler] 缓冲区溢出：已缓存 {} 字节 + 新到 {} 字节 > {} KB，清空重置", wpos_ - rpos_, len, kBufCap >> 10);
            rpos_ = wpos_ = 0;
            return;
        }
        std::memcpy(buf_ + wpos_, data, len);
        wpos_ += len;

        drain(seq);
    }

private:
    void drain(uint32_t seq) {
        int cnt = 0;
        while (true) {
            ++cnt;
            const uint8_t* base  = buf_ + rpos_;
            size_t         avail = wpos_ - rpos_;

            // 1. 长度不够读魔数+长度（8 字节），等下一个包
            if (avail < 8) return;

            // 2. 检查魔数；不对则按字节滑动找下一个
            uint32_t magic = utils::readBE32(base);
            if (magic != kMagic) {
                // 在剩余数据里找下一个魔数
                const uint8_t magic_bytes[4] = {0x00, 0x04, 0xC4, 0x53};
                auto* p = static_cast<const uint8_t*>(memmem(base, avail, magic_bytes, 4));
                if (!p) {
                    spdlog::error("[assembler] cnt={} luan={} seq={} exp={}, 未找到魔数，丢弃 {} 字节 {}",
                                  cnt, isLuan, seq, expected_seq_, avail - 3, getBuf());
                    rpos_ = wpos_ - 3;  // 保留最后 3 字节，魔数可能被切断
                    return;
                }
                spdlog::error("[assembler] cnt={} luan={} seq={} exp={}, 魔数前有 {} 字节无效数据，跳过 {}",
                              cnt, isLuan, seq, expected_seq_, p - base, getBuf());
                rpos_ += (p - base);
                continue;
            }

            // 3. 读整帧长度
            uint32_t total = utils::readBE32(base + 4);
            if (total < kHeaderLen || total > kMaxFrame) {
                spdlog::error("[assembler] 帧长度异常 total={}，跳过魔数", total);
                rpos_ += 4;
                continue;
            }

            // 4. 数据不够，等下一个 TCP 包
            if (avail < total) return;

            // 5. 切出完整帧
            FrameItem* item = pool_.alloc();
            while (!item) { _mm_pause(); item = pool_.alloc(); }

            parseFrame(base, total, item);

            while (!out_queue_.try_push(item)) _mm_pause();
            pending_->fetch_add(1, std::memory_order_release);

            // 6. 推进缓冲，循环找下一帧
            rpos_ += total;
        }
    }

    void compact() {
        if (rpos_ > 0 && wpos_ > rpos_) {
            std::memmove(buf_, buf_ + rpos_, wpos_ - rpos_);
        }
        wpos_ -= rpos_;
        rpos_ = 0;
    }

    void parseFrame(const uint8_t* buf, size_t total_len, FrameItem* item) {
        item->category_id = utils::readBE32(buf + 8);
        item->msg_type    = utils::readBE32(buf + 12);
        item->frame_seq   = utils::readBE32(buf + 16);
        item->compressed  = utils::readBE32(buf + 32) != 0;

        size_t payload_len = total_len - kHeaderLen;
        if (payload_len > sizeof(item->payload)) {
            spdlog::error("[assembler] payload 过长 {} > {}，将被截断", payload_len, sizeof(item->payload));
            payload_len = sizeof(item->payload);
        }
        std::memcpy(item->payload, buf + kHeaderLen, payload_len);
        item->payload_len = payload_len;
    }
};

// =========================================================
// [Worker] 消费线程，纯净的无状态分发器
// =========================================================
class Worker {
    Handler  handler_;
    volatile bool running_ = true;
    uint64_t global_rec_idx_ = 1;
public:
    void ConfigureTypes(std::vector<ActiveType> types) { handler_.ConfigureTypes(std::move(types)); }
    void Stop() { running_ = false; }

    void Run(rigtorp::MPMCQueue<FrameItem*>& q, utils::ObjectPool<FrameItem>& pool, std::atomic<size_t>* pending) {
        FrameItem* item = nullptr;
        while (running_) {
            if (q.try_pop(item)) {
                timespec ts;
                clock_gettime(CLOCK_REALTIME, &ts);
                std::string local_time = utils::fmtPktTime(ts);

                handler_.OnFrame(item, local_time, global_rec_idx_);
                pool.free(item);
                pending->fetch_sub(1, std::memory_order_release);
            } else {
                _mm_pause();
            }
        }
        while (q.try_pop(item)) {
            timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            std::string local_time = utils::fmtPktTime(ts);

            handler_.OnFrame(item, local_time, global_rec_idx_);
            pool.free(item);
            pending->fetch_sub(1, std::memory_order_release);
        }
    }
};

// =========================================================
// [Pipeline] 顶层控制器
// =========================================================
class Pipeline {
    utils::ObjectPool<FrameItem> pool_;
    rigtorp::MPMCQueue<FrameItem*> queue_;
    Worker worker_;
    std::thread worker_thread_;
    Assembler assembler_;
    std::atomic<size_t> pending_{0};
    std::vector<std::ostream*> outputs_;
public:
    Pipeline()
        : pool_(kTcpDataPoolSize),
          queue_(kTcpDataPoolSize),
          assembler_(pool_, queue_, &pending_) {}

    void ConfigureTypes(std::vector<ActiveType> types) {
        for (auto& t : types) if (t.out) outputs_.push_back(t.out);
        worker_.ConfigureTypes(std::move(types));
    }

    void Start() {
        worker_thread_ = std::thread([this] { worker_.Run(queue_, pool_, &pending_); });
    }

    void Drain() {
        while (pending_.load(std::memory_order_acquire) != 0) std::this_thread::yield();
    }

    // 调用方须先 Drain()，确保 Worker idle 后再调用，以避免与 Worker 写 CSV 竞争
    void FlushOutputs() {
        for (auto* out : outputs_) out->flush();
    }

    void Stop() {
        worker_.Stop();
        if (worker_thread_.joinable()) worker_thread_.join();
    }

    void OnTcpData(const uint8_t* data, size_t len, uint32_t seq) {
        assembler_.OnTcpData(data, len, seq);
    }
};
