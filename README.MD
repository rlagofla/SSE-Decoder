# SSE Decoder (上交所行情解码器)

高性能上交所行情数据解码工具，支持多种运行模式和实时分卷存储。

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

### 2. IFACE 模式 (实时网卡抓包)
高性能实时抓包并解码，同时将原始数据分卷存入二进制文件。

```toml
[run]
mode   = "iface"
source = "eth0"              # 网卡名称
port   = 9129

[log]
level = "info"

[iface]
backend               = "pcap"    # "pcap" (标准) 或 "efvi" (Solarflare 高性能)
bin_dir               = "bin/"    # 二进制分卷存储目录
bin_prefix            = ""        # 文件前缀，为空则默认为 "cap_<source>"
segment_bytes         = 268435456 # 每个分卷大小 (字节)，默认 256MB
promisc               = true      # 混杂模式
snaplen               = 65535     # 抓包长度
writer_cpu            = 0         # 抓包写文件线程绑核 (-1 为不绑)
reader_cpu            = 1         # 解析线程绑核
open_max_attempts     = 30        # 启动时打开网卡重试次数
open_retry_ms         = 2000      # 重试间隔 (ms)
delete_bin_after_read = false     # 解析完是否删除二进制分卷
flush_csv_per_segment = true      # 分卷切换时强制刷新 CSV 缓冲区

[[decode]]
category_id = 9
msg_type    = 5803
output      = "out/ua5803_live.csv"
dedup       = true
```

### 3. BIN 模式 (离线解析二进制分卷)
用于解析由 `iface` 模式生成的分卷文件。这种模式比直接解析 pcap 更快且支持分段处理。

```toml
[run]
mode   = "bin"
source = "eth0"              # 对应抓包时的网卡名 (用于定位文件前缀)
port   = 9129

[log]
level = "info"

[iface]
bin_dir               = "bin/"
bin_prefix            = ""        # 若非空则忽略 run.source 的默认前缀
reader_cpu            = 1         # 解析线程绑核
delete_bin_after_read = false
flush_csv_per_segment = true

[[decode]]
category_id = 9
msg_type    = 5803
output      = "out/ua5803_bin.csv"
dedup       = true
```

---

## 参数说明

### [run]
- `mode`: 运行模式，可选 `pcap`, `iface`, `bin`。
- `source`: 在 `pcap` 模式下为文件路径（若无 `.pcap` 后缀，程序会自动补全）；在 `iface/bin` 模式下为网卡名。
- `port`: 仅处理目标/源端口匹配的消息。

### [iface]
- `backend`: 抓包引擎。`efvi` 仅支持 Solarflare 网卡。
- `segment_bytes`: 控制原始数据切片大小，便于长期运行下的磁盘管理。
- `writer_cpu` / `reader_cpu`: 建议在 `iface` 模式下分别绑定不同的物理核心以榨取最高性能。
