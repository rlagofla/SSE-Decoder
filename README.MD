# SSE Decoder (上交所行情解码器)

高性能上交所行情数据解码工具，支持两种运行模式：pcap 离线、网卡在线直通。

## 运行方式
```bash
./decode <config.toml>
```

---

## 配置文件模板

### 1. PCAP 模式 (分析单个 pcap 文件)
用于对已有的抓包文件进行离线回放和解析。

```toml
[run]
mode   = "pcap"
source = "data/capture"      # pcap 文件路径 (可以省略 .pcap 后缀，程序会自动补全)
port   = 9129                # TCP 端口过滤 (0 表示不过滤)

[log]
level = "info"               # trace/debug/info/warn/error

[[decode]]
category_id = 9
msg_type    = 5803
output      = "out/ua5803.csv"
dedup       = true           # 是否跨流去重
```

### 2. IFACE 模式 (实时网卡抓包，直通解码)
在线抓包，efvi/pcap 拿到包后直接进入 Pipeline 解码，不落盘。
Ctrl+C 触发停止时会自动 Drain 队列并 flush CSV。

```toml
[run]
mode   = "iface"
source = "eth0"              # 网卡名称
port   = 9129

[log]
level = "info"

[iface]
backend               = "pcap"    # "pcap" (标准) 或 "efvi" (Solarflare 高性能)
promisc               = true      # 混杂模式
snaplen               = 65535     # 抓包长度
capture_cpu           = 0         # 抓包+解码主线程绑核 (-1 为不绑)
open_max_attempts     = 30        # 启动时打开网卡重试次数
open_retry_ms         = 2000      # 重试间隔 (ms)

[[decode]]
category_id = 9
msg_type    = 5803
output      = "out/ua5803_live.csv"
dedup       = true
```

---

## 参数说明

### [run]
- `mode`: 运行模式，可选 `pcap` 或 `iface`。
- `source`: 在 `pcap` 模式下为文件路径（若无 `.pcap` 后缀，程序会自动补全）；在 `iface` 模式下为网卡名。
- `port`: 仅处理目标/源端口匹配的消息。

### [iface]
- `backend`: 抓包引擎。`efvi` 仅支持 Solarflare 网卡。
- `capture_cpu`: 抓包+解码主线程绑核。-1 为不绑。Worker 线程（解 frame）由 Pipeline 内部管理，目前未绑核。
