#pragma once
// pipeline.hpp — TCP 流切帧框架（StepFrame、ActiveType、Splitter、Context）
//
// 新协议：FIX/STEP 文本格式（端口 9129）
// 帧以 "8=STEP.1.0.0\x01" 开头，9= 给出 body 长度，
// payload 在 96= 字段（长度由 95= 给出），不再有压缩。

#include <cstdint>
#include <cstring>
#include <memory>
#include <ostream>
#include <string>
#include <unordered_map>
#include <vector>

#include <spdlog/spdlog.h>

#include "utils.hpp"
#include "ua3202.hpp"
#include "ua5803.hpp"

// ---- STEP 帧（从 FIX 字段顺序解析而来） ----

struct StepFrame {
    uint32_t       category_id  = 0;    // CategoryID，10142= 的值
    uint32_t       msg_type     = 0;    // MsgType 数字，35=UA3202 → 3202
    uint32_t       msg_seq_id   = 0;    // MsgSeqID，10072= 的值
    std::string    sending_time;        // SendingTime，52= 的值，用于日志
    const uint8_t* payload      = nullptr;
    size_t         payload_len  = 0;    // RawDataLength，95= 的值
    size_t         total_len    = 0;    // 整帧字节数，用于消费 buf_
};

// ---- 运行时每类型配置（含非拥有的输出流指针） ----

struct ActiveType {
    uint32_t      category_id;
    uint32_t      msg_type;
    bool          dedup;
    std::ostream* out;   // 生命周期由 main 管理
};

// ---- 前向声明，Context 中用到 Splitter ----

class Splitter;

struct Context {
    uint16_t filter_port = 9129;
    timespec last_ts{};   // 触发当前回调的 RawPacket 时间戳，由 main 在 reassemblePacket 前更新
    std::vector<ActiveType> types;
    std::unordered_map<uint32_t, std::unique_ptr<Splitter>> streams;
};

// ---- Splitter ----

class Splitter {
public:
    std::string stream_tag;
    Context*    ctx = nullptr;

    void feed(const uint8_t* data, size_t len) {
        if (kBufCap - wpos_ < len) compact();
        if (kBufCap - wpos_ < len) {
            // compact() 后仍不够：说明单帧跨包累积超 1 MB，数据流已错乱
            spdlog::error("[splitter] {} 缓冲区溢出：已缓存 {} 字节 + 新到 {} 字节 > {} KB，清空重置",
                stream_tag, wpos_ - rpos_, len, kBufCap >> 10);
            rpos_ = wpos_ = 0;  // 丢弃全部，等下一个魔数重新同步
            return;
        }
        std::memcpy(buf_ + wpos_, data, len);
        wpos_ += len;
        drain();
    }

private:
    // "8=STEP.1.0.0\x01"
    static constexpr uint8_t kMagicBytes[13] = {
        '8','=','S','T','E','P','.','1','.','0','.','0','\x01'
    };
    static constexpr size_t kMagicLen = 13;
    static constexpr size_t kBufCap   = 1u << 20;  // 1 MB，远大于单帧上限

    uint8_t  buf_[kBufCap];
    uint32_t frame_idx_ = 0;
    size_t   rpos_      = 0;   // 已消费到的位置（读指针）
    size_t   wpos_      = 0;   // 已写入到的位置（写指针）

    void drain() {
        while (true) {
            const uint8_t* base  = buf_ + rpos_;
            size_t         avail = wpos_ - rpos_;

            // 1. 找帧头
            auto* p = static_cast<const uint8_t*>(memmem(base, avail, kMagicBytes, kMagicLen));
            if (!p) {
                if (avail > kMagicLen - 1) {
                    spdlog::warn("[splitter] ts={}, {} 未找到魔数，丢弃 {} 字节", utils::fmtPktTime(ctx->last_ts), stream_tag, avail - (kMagicLen - 1));
                    rpos_ = wpos_ - (kMagicLen - 1);
                }
                return;
            }
            if (p > base) {
                spdlog::warn("[splitter] ts={}, {} 魔数前有 {} 字节无效数据，跳过", utils::fmtPktTime(ctx->last_ts), stream_tag, p - base);
                rpos_ += p - base;
                base = p; avail = wpos_ - rpos_;
            }

            // 2. magic 后至少要有 "9=X\x01" 才够解析
            if (avail < kMagicLen + 4) return;

            // 3. 验证并解析 9=
            if (base[kMagicLen] != '9' || base[kMagicLen + 1] != '=') {
                spdlog::warn("[splitter] ts={}, {} magic 后未找到 9= 字段，跳过魔数", utils::fmtPktTime(ctx->last_ts), stream_tag);
                rpos_ += kMagicLen;
                continue;
            }
            auto* soh = static_cast<const uint8_t*>(memchr(base + kMagicLen + 2, '\x01', avail - kMagicLen - 2));
            if (!soh) return;

            size_t body_len = 0;
            bool   parse_ok = true;
            for (auto* q = base + kMagicLen + 2; q < soh; ++q) {
                if (*q < '0' || *q > '9') { parse_ok = false; break; }
                body_len = body_len * 10 + (*q - '0');
            }
            if (!parse_ok) {
                spdlog::warn("[splitter] ts={}, {} 9= 字段值解析失败，跳过魔数", utils::fmtPktTime(ctx->last_ts), stream_tag);
                rpos_ += kMagicLen;
                continue;
            }

            // 4. 判断完整帧是否到齐
            size_t nine_field_len = static_cast<size_t>(soh + 1 - (base + kMagicLen));
            size_t total          = kMagicLen + nine_field_len + body_len + 7;
            if (total > 16u * 1024u * 1024u) {
                spdlog::warn("[splitter] ts={}, {} 帧长度异常 total_len={}，跳过魔数", utils::fmtPktTime(ctx->last_ts), stream_tag, total);
                rpos_ += kMagicLen;
                continue;
            }
            if (avail < total) {
                spdlog::debug("[splitter] ts={}, {} 帧数据不完整: need={} have={}，等待", utils::fmtPktTime(ctx->last_ts), stream_tag, total, avail);
                return;
            }

            // 5. 解析并交付
            StepFrame frame = parseStepFrame(base, total);
            handleFrame(frame);
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
        // 跳过 "9=<digits>\x01"
        while (pos < total_len && buf[pos] != '\x01') ++pos;
        if (pos < total_len) ++pos;

        uint32_t raw_data_len = 0;

        while (pos < total_len) {
            // 找 '=' 定位 tag 的结束
            size_t eq = pos;
            while (eq < total_len && buf[eq] != '=') ++eq;
            if (eq >= total_len) break;

            std::string tag(reinterpret_cast<const char*>(buf + pos), eq - pos);
            pos = eq + 1; // 跳过 '='

            if (tag == "10") break; // checksum 字段，停止

            if (tag == "96") {
                // 二进制字段，不能用 '\x01' 定位，用 95= 给出的长度
                frame.payload     = buf + pos;
                frame.payload_len = raw_data_len;
                pos += raw_data_len;
                if (pos < total_len && buf[pos] == '\x01') ++pos;
                continue;
            }

            // 普通文本字段，找 '\x01'
            size_t soh = pos;
            while (soh < total_len && buf[soh] != '\x01') ++soh;
            std::string value(reinterpret_cast<const char*>(buf + pos), soh - pos);
            pos = soh + 1;

            try {
                if (tag == "35" && value.size() > 2) {
                    frame.msg_type = uint32_t(std::stoul(value.substr(2))); // "UA3202" → 3202
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

    inline void handleFrame(const StepFrame& frame) {
        for (auto& t : ctx->types) {
            if (t.category_id != frame.category_id || t.msg_type != frame.msg_type) continue;

            ++frame_idx_;

            if (!frame.payload || frame.payload_len == 0) {
                spdlog::warn("[pipeline] {} frame#{} ts={} payload 为空，跳过 msg_seq_id={}", stream_tag, frame_idx_, utils::fmtPktTime(ctx->last_ts), frame.msg_seq_id);
                return;
            }
            spdlog::debug("[pipeline] {} frame#{} ts={} msg_seq_id={} sending_time={} payload_len={}", stream_tag, frame_idx_, utils::fmtPktTime(ctx->last_ts), frame.msg_seq_id, frame.sending_time, frame.payload_len);

            switch ((uint64_t(t.category_id) << 32) | t.msg_type) {
                case (uint64_t(9) << 32) | 5803: {
                    ua5803::Parser parser(frame.payload, frame.payload_len);
                    ua5803::Msg    rec;
                    size_t         rec_idx = 0;
                    while (parser.next(rec)) {
                        ua5803::emit(rec, frame.msg_seq_id, frame_idx_, rec_idx++, t.dedup, *t.out);
                        spdlog::trace("[pipeline] ts={}, emit 成功，TickTime {}", utils::fmtPktTime(ctx->last_ts), rec.tick_time);
                    }
                    break;
                }
                case (uint64_t(6) << 32) | 3202: {
                    ua3202::Parser parser(frame.payload, frame.payload_len);
                    ua3202::Msg    rec;
                    size_t         rec_idx = 0;
                    while (parser.next(rec))
                        ua3202::emit(rec, frame.msg_seq_id, frame_idx_, rec_idx++, t.dedup, *t.out);
                    break;
                }
                default:
                    spdlog::warn("[pipeline] {} 类型 ({},{}) 已配置但暂未实现，跳过", stream_tag, t.category_id, t.msg_type);
            }
            spdlog::debug("[pipeline] ts={}, handle 成功，类型 ({},{})", utils::fmtPktTime(ctx->last_ts), frame.category_id, frame.msg_type);
            return;
        }
        spdlog::debug("[pipeline] {} 帧 category_id={} msg_type={} 不在配置中，跳过 payload_len={}", stream_tag, frame.category_id, frame.msg_type, frame.payload_len);
    }
};
