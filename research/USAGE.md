全部跑通了。总结一下这版：

## 交付清单

**源码**：
- `/home/hljin/sse_decoder/src/split_frames.cpp`（新增，用 PcapPlusPlus + zlib）
- `/home/hljin/sse_decoder/CMakeLists.txt`（加了 target + `find_package(ZLIB)`）

**可执行**：
- `/home/hljin/sse_decoder/build/split_frames`

## 功能

1. 用 `pcpp::TcpReassembly` 做 TCP 重组（和 `extract_payload.cpp` 同一套路子）
2. 每条 TCP 流内部按 `0x0004C453` 魔数切帧，40B 大端头整包解析
3. 若压缩位=1，用 zlib `inflateInit2(-MAX_WBITS)` 裸解 ZIP Local File Header 后面的 deflate
4. 按通道 `(type, sub)` 计数 + 打印带字段解读的 hex dump

## 怎么用

```bash
cd /home/hljin/sse_decoder
source /home/hljin/opt/miniconda3/etc/profile.d/conda.sh && conda activate dev
cmake --build build -j4

# 每个通道各打 2 帧，看样本
./build/split_frames data/output.pcap 5261 - 2

# 只看 (47, 4701) 通道的前 5 帧（M201 标签的股票基金 L2 快照）
./build/split_frames data/output.pcap 5261 47,4701 5

# 只看 (9, 5803) 通道的前 10 帧（FAST-like 紧凑流，最可能是逐笔/合并）
./build/split_frames data/output.pcap 5261 9,5803 10

# 只看 (49, 4901) 通道（MD301 期权 L2 快照）
./build/split_frames data/output.pcap 5261 49,4901 5

# 只统计、不打印任何帧
./build/split_frames data/output.pcap 5261 - 0
```

## 这次跑出的总量数据（5 条 TCP 流合计，总 packets=50001）

| (type, sub)        | 帧数（每流约） | 总字节  | zip 压缩比例    | 载荷形态                                                          |
| ------------------ | -------------- | ------- | --------------- | ----------------------------------------------------------------- |
| **47, 4701**       | ~1990          | 1.86 MB | 1722/1990 = 87% | **M201 标签，实际 MD002/MD004 股票基金 L2 快照**（含 10 档+统计） |
| **6, 3202**        | ~1150          | 2.92 MB | 892/1150 = 78%  | "TRAD T11" 的紧凑 L2 快照                                         |
| **6, 3113**        | ~830           | 78 KB   | 全明文          | 60 字节级短 tick                                                  |
| **9, 5803**        | ~710           | 3.1 MB  | 666/711 = 94%   | **FAST 停止位编码的紧凑流，大量股票代码直出——最像逐笔**           |
| **50, 5001**       | ~625           | 394 KB  | 323/625 = 52%   | M201 标签，MD201 债券 L2 快照                                     |
| **49, 4901**       | ~2450          | 1.7 MB  | 80%             | M201 标签，MD301 期权 L2 快照                                     |
| **38, 3802**       | ~550           | 448 KB  | 30%             | 指数状态流                                                        |
| **4, 2301**        | 509            | 285 KB  | 全明文          | FIX 文本 35=W/h（L1）                                             |
| **23, 7301**       | 1324           | 676 KB  | 全明文          | FIX 文本（L2 快照文本版）                                         |
| **39, 3901**       | 116            | 487 KB  | 110/116 = 95%   | FAST-like + 债券代码（债券逐笔？）                                |
| 48, 4801           | 21             | 5.7 KB  | 部分 ZIP        | 杂项心跳                                                          |
| 18, 2201           | 8              | 7 KB    | 全明文          | FIX 文本（少量）                                                  |
| 6, 3115 / 38, 3815 | 4              | ~240 B  | 全明文          | 超短状态                                                          |

`lost_bytes` 基本是 0–1510 字节，对于 8–11 MB 的流基本忽略不计——**切帧是干净的**。

想重点看哪个通道、打多少帧都直接加参数跑。比如你现在想验证 "M201 是不是 M102 内容"，就 `./build/split_frames data/output.pcap 5261 47,4701 1` 看一帧完整的 1856 字节 body 就很直观。

# 47-4701

- `src/47_4701_struct.hpp`（原 `SseStruct.hpp` 已按你要求改名）——所有 M101/M201/SecurityEntry/MDEntry 的 view 类 + BE 读取 helper + 语义查表函数，全部在 `namespace sse` 下。
- `src/decode_47_4701.cpp` —— 只处理 (47, 4701) 通道：魔数切帧 → ZIP 解压 → 按 body[4:8] label 分派到 M101 / M201 解码 → GBK→UTF-8 → 可读表格。
- `CMakeLists.txt` —— 新增 `decode_47_4701` 目标，并链接 `Iconv::Iconv`（conda env 里 iconv 是独立 libiconv，需显式链）。

运行结果验证：三一重工 22.49 最新价 / 5 买 5 卖 10 档齐全、T111 连续竞价期的快照流 + T100 开盘前阶段切换的 5 帧 M101 全部解出，GBK 汉字正确转 UTF-8。

用法：
```
./build/decode_47_4701 data/output.pcap 5261 <max_sec_per_frame> <max_m201_frames>
# 每帧 3 条证券、只打 1 个 M201 帧:
./build/decode_47_4701 data/output.pcap 5261 3 1
# 只看 M101 (每流 1 帧, M201 全略):
./build/decode_47_4701 data/output.pcap 5261 0 0  | grep -A6 '\[M101\]'
```

# 6-3113

搞定。三个文件交付：

- **`src/6_3113_struct.hpp`** — `sse63113::IndexSnapshotView`，FAST stop-bit 变长解码，13 字段（`header_a / template_id / update_time / security_id / last_px / px_b / total_volume / px_c / px_d / px_e / field_f / total_value / flag`）
- **`src/decode_6_3113.cpp`** — 复用 40B 外层切帧 + TcpReassembly，只保留 `(6,3113)` 帧，调用上述 view 打印
- **`CMakeLists.txt`** — 新增 `decode_6_3113` target

关键修正：body 实际 **40B~57B 变长**（值小的指数 FAST 编码就短），初版假定 57B 固定有错，现已改成「解析到 13 个字段为止，不强校验总长」。

验证数据（500 帧 0 解析失败，指数值全部合理）：

| SecurityID      | LastPx   |
| --------------- | -------- |
| 000001 上证综指 | 4138.76  |
| 000003 B股指数  | 257.77   |
| 000010 上证 180 | 10429.17 |
| 000012 国债指数 | 224.71   |

运行：`./build/decode_6_3113 data/output.pcap 5261 [max_frames_per_stream=0]`

# 9-5803

全部跑通。总结一下产出:

**新增文件**:
- `src/9_5803_struct.hpp` — 纯头文件, 含 `readFast`, `tryReadAsciiSecID`, `TickRecord`, `TickStreamParser`, `mapSemantic` 等
- `src/decode_9_5803.cpp` — 主程序, 带 ZIP 解压 + 帧切分 + TCP 重组
- CMakeLists.txt 已加入 `decode_9_5803` target

**关键设计点**:
1. **PMAP = 1 字节** (观测所有记录都符合, PMAP 字节 MSB=1 紧挨 TID)
2. **TID 扫描定界**: 用 `2d ab` 位置切记录, PMAP 在其前 1 字节
3. **ASCII SecID 宽容扫描**: 每帧首条记录有帧级前导字段 (3~4 个 FAST int), 允许跳过 0~3 个前导再找 SecID, 分离到 `prefix_ints`
4. **Action 宽容扫描**: SecID 和 Action 之间也允许 0~2 个前导字段
5. **继承状态机**: `TickStreamParser` 内部维护 `cur_sec_` / `cur_action_`, 缺字段时自动继承
6. **尾部探测**: 最后 2 字节若符合 `[FAST 'B'/'S'/'N', raw byte]` 则识别为 BSFlag+ExtCode, 否则只 1B 尾
7. **CSV 模式** (`--csv`): 输出和 `mdl_4_24_0.csv` 结构一致的列, `mapSemantic` 按 Action 规则填 BuyOrderNO/SellOrderNO/Price/Qty/TradeMoney

**验证输出**:
- rec#0 "601106" 'A': ApplSeq=6000458, Px=6331, Qty=1100001
- rec#1 "600748" 'D': DeletedRef=5850745, Px=6361
- rec#6 "688122" 'T': BidRef=3460556, TradeApplSeq=6000463, Px=95861, Qty=769001, Money=7371634001
- rec#10~13 继承链: 同一笔 'T' ApplSeq=6000465 带 3 条对手明细 (SecID/Action 均继承)

**用法**:
```
./build/decode_9_5803 data/output.pcap            # 全量, 可读格式
./build/decode_9_5803 data/output.pcap 5261 10    # 每流前 10 帧
./build/decode_9_5803 data/output.pcap 5261 0 --csv > out.csv
```