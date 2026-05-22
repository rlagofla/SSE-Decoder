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

struct StepFrameItem {
    uint32_t category_id  = 0;
    uint32_t msg_type     = 0;
    uint32_t msg_seq_id   = 0;
    char     sending_time[24] = {0};

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

    void OnFrame(const StepFrameItem* frame, const std::string& local_time, uint64_t& rec_idx) {
        for (auto& t : types_) {
            if (t.category_id != frame->category_id || t.msg_type != frame->msg_type) continue;

            if (frame->payload_len == 0) {
                spdlog::warn("[pipeline] frame msg_seq_id={} payload 为空，跳过", frame->msg_seq_id);
                return;
            }
            spdlog::debug("[pipeline] frame msg_seq_id={} sending_time={} payload_len={}", frame->msg_seq_id, frame->sending_time, frame->payload_len);

            switch ((uint64_t(t.category_id) << 32) | t.msg_type) {
                case (uint64_t(9) << 32) | 5803: {
                    ua5803::Parser parser(frame->payload, frame->payload_len);
                    ua5803::Msg    rec;
                    while (parser.next(rec)) {
                        ua5803::emit(rec, frame->msg_seq_id, local_time, rec_idx++, t.dedup, *t.out);
                        spdlog::trace("[pipeline] emit 成功，TickTime {}", rec.tick_time);
                    }
                    break;
                }
                case (uint64_t(6) << 32) | 3202: {
                    ua3202::Parser parser(frame->payload, frame->payload_len);
                    ua3202::Msg    rec;
                    while (parser.next(rec))
                        ua3202::emit(rec, frame->msg_seq_id, local_time, rec_idx++, t.dedup, *t.out);
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
// =========================================================
class Assembler {
    utils::ObjectPool<StepFrameItem>& pool_;
    rigtorp::MPMCQueue<StepFrameItem*>& out_queue_;
    std::atomic<size_t>* pending_;

    bool     seq_initialized_ = false;
    uint32_t expected_seq_    = 0;

    static constexpr uint8_t kMagicBytes[13] = {
        '8','=','S','T','E','P','.','1','.','0','.','0','\x01'
    };
    static constexpr size_t kMagicLen = 13;
    static constexpr size_t kBufCap   = 1u << 20;  // 1MB

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
    Assembler(utils::ObjectPool<StepFrameItem>& pool, rigtorp::MPMCQueue<StepFrameItem*>& q, std::atomic<size_t>* pending)
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

            // 1. 如果缓冲区为空（恰好处理完），或者长度短于一个魔数，直接退出等待下一个包
            // 这是一个完全正常、最常见（avail == 0）的退出条件。
            if (avail < kMagicLen) {
                return;
            }

            // 2. 尝试寻找魔数
            auto* p = static_cast<const uint8_t*>(memmem(base, avail, kMagicBytes, kMagicLen));
            if (!p) {
                // 找不到魔数，但总长度大于等于 13。说明这里面是垃圾数据。
                // 仅保留最后 12 个字节（以防魔数被从中间切断），其他的丢弃。
                spdlog::error("[assembler] cnt={} luan={} seq={} exp={}, 未找到魔数，丢弃 {} 字节 {}", cnt, isLuan, seq, expected_seq_, avail - (kMagicLen - 1), getBuf());
                rpos_ = wpos_ - (kMagicLen - 1);
                return;
            }

            // 3. 找到了魔数，但不在开头，说明魔数前有垃圾数据
            if (p > base) {
                spdlog::error("[assembler] cnt={} luan={} seq={} exp={}, 魔数前有 {} 字节无效数据，跳过 {}", cnt, isLuan, seq, expected_seq_, p - base, getBuf());
                rpos_ += (p - base);
                base = p; 
                avail = wpos_ - rpos_;
            }

            // 4. 解析 `9=BodyLength`。先确保长度足够读 `9=`
            if (avail < kMagicLen + 4) {
                return; // 等下一个包
            }

            if (base[kMagicLen] != '9' || base[kMagicLen + 1] != '=') {
                spdlog::error("[assembler] magic 后紧跟的不是 9=，跳过异常魔数");
                rpos_ += kMagicLen;
                continue;
            }
            
            // 找 9=xxx\x01 的结束符
            auto* soh = static_cast<const uint8_t*>(
                memchr(base + kMagicLen + 2, '\x01', avail - kMagicLen - 2));
            if (!soh) {
                return; // 还没收全这个 tag，等下一个包
            }

            size_t body_len = 0;
            bool   parse_ok = true;
            for (auto* q = base + kMagicLen + 2; q < soh; ++q) {
                if (*q < '0' || *q > '9') { parse_ok = false; break; }
                body_len = body_len * 10 + (*q - '0');
            }
            if (!parse_ok) {
                spdlog::error("[assembler] 9= 字段值解析失败，跳过异常魔数");
                rpos_ += kMagicLen;
                continue;
            }

            // 5. 计算这一帧的完整理论长度
            size_t nine_field_len = static_cast<size_t>(soh + 1 - (base + kMagicLen));
            size_t total          = kMagicLen + nine_field_len + body_len + 7; // +7 for 10=000\x01
            
            if (total > 16u * 1024u * 1024u) {
                spdlog::error("[assembler] 帧长度极其异常 total_len={}，跳过魔数");
                rpos_ += kMagicLen;
                continue;
            }

            // 6. 检查当前缓冲数据是否足够切出一个完整帧
            if (avail < total) {
                // 如果恰好跨包了（例如还差几十字节没到），就停在这里等下一个 TCP Payload 到来
                return;
            }

            // 7. 能够完整切出！
            StepFrameItem* item = pool_.alloc();
            while (!item) { _mm_pause(); item = pool_.alloc(); }

            parseStepFrame(base, total, item);

            while (!out_queue_.try_push(item)) _mm_pause();
            pending_->fetch_add(1, std::memory_order_release);
            
            // 8. 推进缓冲，开始下一次循环以寻找下一个帧（如果当前包带有多个帧）
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

    void parseStepFrame(const uint8_t* buf, size_t total_len, StepFrameItem* item) {
        item->category_id = 0;
        item->msg_type = 0;
        item->msg_seq_id = 0;
        item->sending_time[0] = '\0';
        item->payload_len = 0;

        size_t pos = kMagicLen;
        while (pos < total_len && buf[pos] != '\x01') ++pos;
        if (pos >= total_len) {
            spdlog::error("[assembler] parseStepFrame: 寻找首个 SOH 越界");
            return;
        }
        ++pos;

        uint32_t raw_data_len = 0;

        while (pos < total_len) {
            uint32_t tag_num = 0;
            size_t tag_start = pos;
            while (pos < total_len && buf[pos] >= '0' && buf[pos] <= '9') {
                tag_num = tag_num * 10 + (buf[pos] - '0');
                ++pos;
            }
            if (pos >= total_len || buf[pos] != '=') {
                spdlog::error("[assembler] parseStepFrame: 解析 Tag 编号异常 (pos={}), tag_start={}", pos, tag_start);
                break; // Malformed tag
            }
            ++pos; // skip '='

            if (tag_num == 10) break; // End of message

            if (tag_num == 96) {
                item->payload_len = raw_data_len;
                if (raw_data_len > sizeof(item->payload)) {
                    spdlog::error("[assembler] payload 过长 {} > {}，将被截断", raw_data_len, sizeof(item->payload));
                    item->payload_len = sizeof(item->payload);
                }
                if (pos + item->payload_len > total_len) {
                    spdlog::error("[assembler] parseStepFrame: 96 字段 payload 长度越界");
                    break;
                }
                std::memcpy(item->payload, buf + pos, item->payload_len);
                pos += raw_data_len;
                if (pos < total_len && buf[pos] == '\x01') {
                    ++pos;
                } else {
                    spdlog::error("[assembler] parseStepFrame: 96 字段结束后未找到预期 SOH");
                }
                continue;
            }

            size_t soh = pos;
            while (soh < total_len && buf[soh] != '\x01') ++soh;
            if (soh >= total_len) {
                spdlog::error("[assembler] parseStepFrame: Tag {} 寻找结束 SOH 越界", tag_num);
                break;
            }
            size_t val_len = soh - pos;
            const char* val_ptr = reinterpret_cast<const char*>(buf + pos);
            pos = soh + 1; // skip SOH for next tag

            switch (tag_num) {
                case 35: {
                    if (val_len > 2) { // Skip prefix like "UE" or "UA"
                        uint32_t mt = 0;
                        for (size_t i = 2; i < val_len; ++i) {
                            if (val_ptr[i] >= '0' && val_ptr[i] <= '9') {
                                mt = mt * 10 + (val_ptr[i] - '0');
                            }
                        }
                        item->msg_type = mt;
                    }
                    break;
                }
                case 10142: {
                    uint32_t cat = 0;
                    for (size_t i = 0; i < val_len; ++i) {
                        if (val_ptr[i] >= '0' && val_ptr[i] <= '9') cat = cat * 10 + (val_ptr[i] - '0');
                    }
                    item->category_id = cat;
                    break;
                }
                case 10072: {
                    uint32_t seq = 0;
                    for (size_t i = 0; i < val_len; ++i) {
                        if (val_ptr[i] >= '0' && val_ptr[i] <= '9') seq = seq * 10 + (val_ptr[i] - '0');
                    }
                    item->msg_seq_id = seq;
                    break;
                }
                case 95: {
                    uint32_t len = 0;
                    for (size_t i = 0; i < val_len; ++i) {
                        if (val_ptr[i] >= '0' && val_ptr[i] <= '9') len = len * 10 + (val_ptr[i] - '0');
                    }
                    raw_data_len = len;
                    break;
                }
                case 52: {
                    size_t cp_len = std::min(val_len, sizeof(item->sending_time) - 1);
                    std::strncpy(item->sending_time, val_ptr, cp_len);
                    item->sending_time[cp_len] = '\0';
                    break;
                }
                case 49: {
                    if (val_len != 3 || std::strncmp(val_ptr, "VDE", 3) != 0) {
                        spdlog::warn("[assembler] SenderCompID 异常: {}", std::string(val_ptr, val_len));
                    }
                    break;
                }
                case 56: {
                    if (val_len != 3 || std::strncmp(val_ptr, "VSS", 3) != 0) {
                        spdlog::warn("[assembler] TargetCompID 异常: {}", std::string(val_ptr, val_len));
                    }
                    break;
                }
                default:
                    break;
            }
        }
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

    void Run(rigtorp::MPMCQueue<StepFrameItem*>& q, utils::ObjectPool<StepFrameItem>& pool, std::atomic<size_t>* pending) {
        StepFrameItem* item = nullptr;
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
    utils::ObjectPool<StepFrameItem> pool_;
    rigtorp::MPMCQueue<StepFrameItem*> queue_;
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
