#pragma once
// pipeline.hpp — TCP 流切帧框架（FrameHeader、ActiveType、Splitter、Context）
//
// inflate 逻辑统一在 handleFrame 里，switch 分发到各 namespace 的 Parser + emit。

#include <cstdint>
#include <memory>
#include <ostream>
#include <string>
#include <unordered_map>
#include <vector>

#include <spdlog/spdlog.h>

#include "utils.hpp"
#include "ua5803.hpp"

// ---- 帧头（40 字节，大端） ----

struct FrameHeader {
    uint32_t magic;
    uint32_t length;
    uint32_t type_hi;
    uint32_t type_lo;
    uint32_t outer_seq;
    uint32_t comp;

    static FrameHeader from(const uint8_t* p) {
        FrameHeader h;
        h.magic     = utils::readBE32(p);
        h.length    = utils::readBE32(p +  4);
        h.type_hi   = utils::readBE32(p +  8);
        h.type_lo   = utils::readBE32(p + 12);
        h.outer_seq = utils::readBE32(p + 16);
        h.comp      = utils::readBE32(p + 32);
        return h;
    }
};

// ---- 运行时每类型配置（含非拥有的输出流指针） ----

struct ActiveType {
    uint32_t      hi;
    uint32_t      lo;
    bool          dedup;
    std::ostream* out;   // 生命周期由 main 管理
};

// ---- 前向声明，Context 中用到 Splitter ----

class Splitter;

struct Context {
    uint16_t filter_port = 5261;
    std::vector<ActiveType> types;
    std::unordered_map<uint32_t, std::unique_ptr<Splitter>> streams;
};

// ---- Splitter ----

class Splitter {
public:
    std::string stream_tag;
    Context*    ctx = nullptr;

    void feed(const uint8_t* data, size_t len) {
        buf_.insert(buf_.end(), data, data + len);
        drain();
    }

private:
    std::vector<uint8_t> buf_;
    uint32_t             frame_idx_ = 0;

    void drain() {
        while (buf_.size() >= 40) {
            size_t idx = scanMagic();
            if (idx == std::string::npos) {
                spdlog::trace("[splitter] {} 未找到魔数，保留尾部 3 字节，丢弃 {} 字节", stream_tag, buf_.size() > 3 ? buf_.size() - 3 : 0u);
                if (buf_.size() > 3) buf_.erase(buf_.begin(), buf_.end() - 3);
                return;
            }
            if (idx > 0) {
                spdlog::trace("[splitter] {} 魔数前有 {} 字节无效数据，跳过", stream_tag, idx);
                buf_.erase(buf_.begin(), buf_.begin() + idx);
            }
            if (buf_.size() < 40) {
                spdlog::trace("[splitter] {} 魔数已对齐但 header 不足 40 字节（{}），等待", stream_tag, buf_.size());
                return;
            }
            FrameHeader hdr = FrameHeader::from(buf_.data());
            if (hdr.length < 40 || hdr.length > 16u * 1024u * 1024u) {
                spdlog::warn("[splitter] {} 帧长度异常 length={}（期望 40~16M），跳过 4 字节继续扫描", stream_tag, hdr.length);
                buf_.erase(buf_.begin(), buf_.begin() + 4);
                continue;
            }
            if (buf_.size() < hdr.length) {
                spdlog::trace("[splitter] {} 帧数据不完整: need={} have={}，等待", stream_tag, hdr.length, buf_.size());
                return;
            }
            handleFrame(buf_.data(), hdr);
            buf_.erase(buf_.begin(), buf_.begin() + hdr.length);
        }
    }

    size_t scanMagic() const {
        if (buf_.size() < 4) return std::string::npos;
        size_t n = buf_.size() - 3;
        for (size_t i = 0; i < n; ++i) {
            if (buf_[i] == 0x00 && buf_[i+1] == 0x04 &&
                buf_[i+2] == 0xC4 && buf_[i+3] == 0x53) return i;
        }
        return std::string::npos;
    }

    inline void handleFrame(const uint8_t* f, const FrameHeader& hdr) {
        for (auto& t : ctx->types) {
            if (t.hi != hdr.type_hi || t.lo != hdr.type_lo) continue;

            ++frame_idx_;

            // inflate（所有类型通用）
            const uint8_t*       body = f + 40;
            size_t               blen = hdr.length - 40;
            std::vector<uint8_t> inflated;
            if (hdr.comp == 1) {
                auto ist = utils::rawInflateZipLFH(body, blen, inflated);
                if (ist != utils::InflateStatus::Ok) {
                    spdlog::warn("[pipeline] {} frame#{} inflate 失败({}), 跳过 outer_seq={}", stream_tag, frame_idx_, utils::zipStatusStr(ist), hdr.outer_seq);
                    return;
                }
                spdlog::trace("[pipeline] {} frame#{} inflate ok: {} -> {} bytes", stream_tag, frame_idx_, blen, inflated.size());
                body = inflated.data();
                blen = inflated.size();
            }
            spdlog::trace("[pipeline] {} frame#{} outer_seq={} comp={} body_len={}", stream_tag, frame_idx_, hdr.outer_seq, hdr.comp, blen);

            // 按类型解析 + 输出
            switch ((uint64_t(t.hi) << 32) | t.lo) {
                case (uint64_t(9) << 32) | 5803: {
                    ua5803::Parser parser(body, blen);
                    ua5803::Msg    rec;
                    size_t         rec_idx = 0;
                    while (parser.next(rec))
                        ua5803::emit(rec, hdr.outer_seq, frame_idx_, rec_idx++, t.dedup, *t.out);
                    break;
                }
                case (uint64_t(6) << 32) | 3202:
                    // ua3202 Parser/emit 待实现，见 ua3202.hpp
                    spdlog::debug("[ua3202] {} frame#{} outer_seq={} — 解析器尚未实现，跳过", stream_tag, frame_idx_, hdr.outer_seq);
                    break;
                default:
                    spdlog::warn("[pipeline] {} 类型 ({},{}) 已配置但暂未实现，跳过", stream_tag, t.hi, t.lo);
            }
            return;
        }
        spdlog::trace("[pipeline] {} 帧类型 ({},{}) 不在配置中，跳过 length={}", stream_tag, hdr.type_hi, hdr.type_lo, hdr.length);
    }
};
