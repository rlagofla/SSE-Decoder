# 多流多网口 + 40B 帧头 重构计划

## 背景

原架构：单网口 → 单 TCP 流 → 单 Pipeline (Assembler + Worker) → 解码 STEP/SOH 帧 → CSV。
现需要：**两个网口、每个网口多条 TCP 流（多路冗余行情）、40B 定长头帧**。

实测单流 ~1500 帧/s，5 流冗余 → 入站 ~7500 帧/s，几乎全是 ZIP 帧。

## 核心架构决策

- **不引入 NIC 抽象层**：网口在数据流上无业务含义，capture 后端各自启 → 同一个 Pipeline。
- **不"每流一个 Pipeline"**：CSV/dedup 分裂、跨实例协调，得不偿失。
- **dedup 前移到 frame 级**：用帧头 16-19 字节的 `frame_seq` 做仲裁。重复 frame **不解压、不 parse**，5× → 1×。
- **下游接受乱序**：下游是 CSV 落盘 (Python pandas 后处理可重排序)，所以用"立即跳号 + 迟到补写 + 判重滑窗"，**不带超时窗、不带 reorder buffer**，最简实现。
  - 注：先前讨论过 bounded reorder buffer 方案 (K=64)，但最终选了乱序透传——因为下游能排序，缓冲只是额外延迟。
- **inflate 放 Handler 而非 Worker**：未配置消费的类型可早退、不解压。
- **单 Worker 线程**：frame 级 dedup 后实际负载就 1×，单线程扛得住。不够再加。

## 目标结构

```
[NIC capture × 2]
  └→ 5-tuple 路由 → Pipeline::OnTcpData(stream_id, data, len, seq)
       └→ Assembler[stream_id] (per-stream, TCP-seq 连续性 + 40B 帧切分)
            └→ 共享 MPMCQueue<FrameItem*>

[Worker 线程]
  └→ pop frame
       └→ Arbiter::OnFrame(frame)
            ├→ 判重 (per (cat,type) 滑窗)，重复直接 free
            └→ 通过则 Handler::OnFrame
                 ├→ 匹配 ActiveType（未匹配早退）
                 ├→ 若 frame.compressed: inflate → payload_view
                 └→ ua5803/ua3202 parser → emit 直接写 CSV
```

## 帧格式（已确认，大端）

| 偏移  | 大小 | 含义 | 用途 |
|---|---|---|---|
| 0-3   | u32 | Magic `0x0004C453` | 切帧 |
| 4-7   | u32 | 整帧长度（含 40B 头） | 切帧 |
| 8-11  | u32 | category_id | 分发 |
| 12-15 | u32 | msg_type | 分发 |
| 16-19 | u32 | frame_seq (按 (cat,type) 单调 +1) | **Arbiter 判重 key** |
| 20-23 | u32 | = 0 | 忽略 |
| 24-27 | u32 | 时间戳/相关 | 忽略 |
| 28-31 | u32 | 0 / 0x08000000 | 忽略 |
| 32-35 | u32 | 压缩标志 0/1 | inflate 路由 |
| 36-39 | u32 | 0/1/0xF | 忽略 |

---

## Step 1 — 40B 帧头 ✅ 已完成

**文件**：`src/pipeline.hpp`

**改动**：
- `StepFrameItem` → `FrameItem`，字段：`category_id, msg_type, frame_seq, compressed, payload_len, payload[64K]`
- 删除：`msg_seq_id, sending_time`
- `Assembler::drain` 重写：
  - 不再找 STEP `8=STEP.1.0.0\x01` 13 字节 magic、不再 SOH/tag 解析
  - 改为：读 4B magic → 读 4B total_len → 攒够 total 字节 → memcpy 出 payload
  - 字段抽取改为大端 u32 定偏移读取
- 保留：TCP seq 连续性检查、buffer compact、对象池入队、MPMCQueue 入队
- Handler/Worker 内 `frame->msg_seq_id` / `sending_time` 全部改为 `frame->frame_seq` / `frame->compressed`

**注意点**：
- ua5803/ua3202 的 `emit` 签名暂时保持不变（`outer_seq` 参数现在传 `frame_seq`，语义改了但兼容）
- 压缩帧此时 parser 会读到压缩数据 → 解析失败，本 step **不能跑 ZIP 流量**，syntax/link 通即可
- `g_seen` 和 `dedup` 参数还在，Step 2 再清

**验证**：
- [ ] `decode` 编译通过
- [ ] 用纯文本帧 pcap (cat=6 msg=3113 是明文) 跑一遍，能切出 frame 并 parse 出 record

---

## Step 2 — Arbiter + Handler inflate + 删 dedup

### 2.1 加 zlib inflate 工具函数

**文件**：`src/utils.hpp`

加一个 helper：

```cpp
namespace utils {
// 把 zlib 压缩的 src 解压到 dst。dst 自动 resize。
// 返回 true 表示成功；失败时 dst 内容未定义。
inline bool inflateZlib(const uint8_t* src, size_t src_len, std::vector<uint8_t>& dst);
}
```

实现用 `z_stream` + `inflateInit/inflate/inflateEnd`，dst 初始容量给 `src_len * 8` 作为经验值，分块扩容到放得下。

### 2.2 在 Handler 加 inflate 路径

**文件**：`src/pipeline.hpp`

```cpp
class Handler {
    std::vector<ActiveType> types_;
    std::vector<uint8_t> inflate_buf_;   // 复用，避免每帧 alloc
    ...
    void OnFrame(const FrameItem* frame, ...) {
        for (auto& t : types_) {
            if (...) continue;  // 早退 = 不解压
            
            const uint8_t* payload_ptr = frame->payload;
            size_t         payload_len = frame->payload_len;
            
            if (frame->compressed) {
                if (!utils::inflateZlib(frame->payload, frame->payload_len, inflate_buf_)) {
                    spdlog::error("[handler] inflate 失败 cat={} type={} frame_seq={}", ...);
                    return;
                }
                payload_ptr = inflate_buf_.data();
                payload_len = inflate_buf_.size();
            }
            
            switch (...) {
                case ...: {
                    ua5803::Parser parser(payload_ptr, payload_len);
                    ...
                }
            }
        }
    }
};
```

### 2.3 加 Arbiter

**文件**：`src/pipeline.hpp`（新增 class，放 Worker 前）

```cpp
class Arbiter {
    // per (cat, msg_type) 状态
    struct State {
        bool initialized = false;
        uint32_t expected_seq = 0;
        // 判重滑窗：记录"已发过"的 seq
        // 简化实现：std::unordered_set<uint32_t>，定期 erase 老的
        // 优化：环形 bitset，base=expected_seq-WINDOW，size=WINDOW
        std::unordered_set<uint32_t> seen;
    };
    std::unordered_map<uint64_t, State> states_;  // key = (cat<<32)|type
    
    Handler& handler_;
    
    static constexpr size_t kWindow = 1024;  // 判重窗
    
public:
    explicit Arbiter(Handler& h) : handler_(h) {}
    
    // 返回 true 表示已被 handler 处理（或合法丢弃），false 不会发生
    void OnFrame(const FrameItem* frame, const std::string& local_time, uint64_t& rec_idx) {
        uint64_t key = (uint64_t(frame->category_id) << 32) | frame->msg_type;
        auto& st = states_[key];
        
        if (!st.initialized) {
            st.initialized = true;
            st.expected_seq = frame->frame_seq;
        }
        
        // 太老的直接丢
        if (frame->frame_seq + kWindow < st.expected_seq) {
            spdlog::debug("[arbiter] cat={} type={} seq={} 超出判重窗(expected={})，丢弃",
                          frame->category_id, frame->msg_type, frame->frame_seq, st.expected_seq);
            return;
        }
        
        // 判重
        if (!st.seen.insert(frame->frame_seq).second) {
            spdlog::trace("[arbiter] cat={} type={} seq={} 重复，丢弃",
                          frame->category_id, frame->msg_type, frame->frame_seq);
            return;
        }
        
        // 清理过期 seen（保持滑窗大小）
        if (st.seen.size() > kWindow * 2) {
            uint32_t threshold = st.expected_seq - kWindow;
            for (auto it = st.seen.begin(); it != st.seen.end(); ) {
                if (*it < threshold) it = st.seen.erase(it);
                else ++it;
            }
        }
        
        // 推进 expected_seq（立即跳号策略）
        if (frame->frame_seq >= st.expected_seq) {
            st.expected_seq = frame->frame_seq + 1;
        }
        
        // 通过仲裁，交 Handler
        handler_.OnFrame(frame, local_time, rec_idx);
    }
};
```

**判重窗 `kWindow=1024` 的选择**：流间最大延迟差 50ms × 1500 帧/s = 75 帧，1024 远超正常乱序、内存 4KB×N(cat,type) 无压力。

### 2.4 Worker 改为持有 Arbiter

**文件**：`src/pipeline.hpp`

```cpp
class Worker {
    Handler  handler_;
    Arbiter  arbiter_{handler_};
    ...
    void Run(...) {
        while (running_) {
            if (q.try_pop(item)) {
                std::string local_time = utils::fmtPktTime(...);
                arbiter_.OnFrame(item, local_time, global_rec_idx_);  // ← 改这里
                pool.free(item);
                pending->fetch_sub(...);
            }
        }
    }
};
```

### 2.5 删除 record 级 dedup

**文件**：`src/ua5803.hpp`、`src/ua3202.hpp`

- 删除 `inline std::unordered_set<...> g_seen;`
- `emit` 函数签名移除 `bool dedup` 参数
- 删除 emit 内 `if (dedup) { ... g_seen.insert ... }` 那段

**文件**：`src/config.hpp`、`src/main.cpp`

- `TypeConfig::dedup`、`ActiveType::dedup` 字段保留（向后兼容 toml），但不再传递给 emit
- 或者干脆删掉，toml 里的 dedup 字段读了不用就行（简单）

**注意**：删完后 `outer_seq` 参数现在传的是 `frame->frame_seq`，CSV 里 `OuterSeq` 列的含义也变了——原来是 STEP `10072` tag，现在是帧头 16-19 字节。对下游来说没区别。

**验证**：
- [ ] 编译通过
- [ ] 单流 ZIP pcap 跑通：inflate + parse + CSV 输出
- [ ] 启用 5 流冗余 pcap (后面 Step 3 才有，本步验证用 2 流 mock 也行)：观察 arbiter 重复丢弃日志

---

## Step 3 — 多流多网口路由

### 3.1 Pipeline 加 stream_id 路由

**文件**：`src/pipeline.hpp`

```cpp
class Pipeline {
    utils::ObjectPool<FrameItem> pool_;
    rigtorp::MPMCQueue<FrameItem*> queue_;
    Worker worker_;
    std::thread worker_thread_;
    std::atomic<size_t> pending_{0};
    std::vector<std::ostream*> outputs_;
    
    // per stream_id 一个 Assembler。stream_id 从 5-tuple 算
    std::unordered_map<uint64_t, std::unique_ptr<Assembler>> assemblers_;
    std::mutex assemblers_mu_;  // capture 线程可能并发新增
    
public:
    // 由 capture 侧传入 stream key（IP+Port 4-tuple 编码）
    void OnTcpData(uint64_t stream_key, const uint8_t* data, size_t len, uint32_t seq) {
        Assembler* asm_ptr;
        {
            std::lock_guard<std::mutex> lk(assemblers_mu_);
            auto it = assemblers_.find(stream_key);
            if (it == assemblers_.end()) {
                auto p = std::make_unique<Assembler>(pool_, queue_, &pending_);
                asm_ptr = p.get();
                assemblers_[stream_key] = std::move(p);
                spdlog::info("[pipeline] 新 TCP 流 key=0x{:016x}", stream_key);
            } else {
                asm_ptr = it->second.get();
            }
        }
        asm_ptr->OnTcpData(data, len, seq);
    }
};
```

**stream_key 编码**（用 4-tuple）：

```cpp
// 在 capture 回调里算
uint64_t stream_key =
    (uint64_t(srcIP.toInt()) << 32) |
    (uint32_t(srcPort) << 16)        |
     uint32_t(dstPort);
// dstIP 不参与：同一 NIC 收到的，dstIP 都是本机
```

或者更稳：5-tuple 全编码进一个 hash（避免 srcPort 复用）。先简单方案。

### 3.2 多 iface 配置

**文件**：`src/config.hpp`

```cpp
struct Config {
    std::string mode = "pcap";
    
    // pcap 模式：单 pcap 文件路径
    std::string pcap_source;
    uint16_t    port = 9129;  // 旧字段，pcap 模式用
    
    // iface 模式：可多个网口
    std::vector<IfaceConfig> ifaces;
    
    std::string log_level = "info";
    std::vector<TypeConfig> types;
};
```

TOML 改成：

```toml
[run]
mode = "iface"

[[iface]]   # 可多个
name = "eth0"
backend = "efvi"
capture_cpu = 2

[[iface]]
name = "eth1"
backend = "efvi"
capture_cpu = 3
```

### 3.3 main.cpp 启多 capture 线程

**文件**：`src/main.cpp`

```cpp
if (cfg.mode == "iface") {
    std::vector<std::thread> capture_threads;
    for (auto& iface_cfg : cfg.ifaces) {
        capture_threads.emplace_back([&iface_cfg, &pipeline, &g_stop]() {
            std::string err;
            RunIfaceMode(iface_cfg, pipeline, g_stop, &err);
            if (!err.empty()) spdlog::error("[iface {}] {}", iface_cfg.iface, err);
        });
    }
    for (auto& t : capture_threads) t.join();
    pipeline.Stop();
}
```

### 3.4 RunIfaceMode 改签名

**文件**：`src/live.cpp`、`src/live.hpp`

- 去掉 `port_filter` 参数（每流自己解 5-tuple，不再用单一 port 过滤）
- 或保留 port 过滤但放进 IfaceConfig 里 (`port_filter` 字段)
- 抓包回调里算 stream_key，调 `pipeline.OnTcpData(stream_key, data, len, seq)`

**dump pcap 功能保留**，但每个 iface 独立 dump 文件（路径在 IfaceConfig 里）。

**验证**：
- [ ] 编译通过
- [ ] 2 iface + 5 流真实流量跑起来
- [ ] 检查日志：每条新 TCP 流都有 "新 TCP 流 key=..." 日志一次
- [ ] Arbiter 重复率 ≈ (N-1)/N （5 流就是 80%）
- [ ] `pending_` 队列水位 < pool 容量的 10% (没积压)
- [ ] CSV 总行数 ≈ 单流跑出来的行数（dedup 后不应×N）

---

## 风险点 / 待观察

1. **判重滑窗大小 1024 是否够**：如果流间延迟差比预期大，可能误判重复。监控 arbiter 丢弃日志，看是不是有正常 frame 被当重复扔了。
2. **`seen` 集合内存增长**：当前用 unordered_set + 定期 erase，长期跑可能碎片。如果跑一整天有问题再换 ring bitset。
3. **`std::lock_guard` on `assemblers_`**：仅在新流第一次出现时上锁，5 个流一辈子总共 5 次，无热路径开销。
4. **CSV emit 单 Worker**：万一不够（zlib + parse 1500 帧/s 应该轻松），后续可以把 emit 拆出来单独线程，加 MPSC 队列。
5. **退出 Drain**：现在 Drain 是看 `pending_==0`，多 iface 后逻辑不变（队列是共享的）。

## 一句话总结

Step 1 砍掉 STEP 协议、换 40B 头；Step 2 砍掉 record 级 dedup、改 frame 级 Arbiter + Handler inflate；Step 3 加 5-tuple 路由 + 多 iface。每步独立编译、独立验证。
