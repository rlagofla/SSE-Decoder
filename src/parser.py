"""
上交所 pcap 解析器（(47,4701) 通道定向解析）

分层：
  1) 外层 40B transport header（大端）
  2) body 可选 ZIP deflate（streaming mode，自己裸解）
  3) 解压后的 "M201-wrap" 应用载荷（外观上带 "M201" 标签，内部实际是 SSE
     BINARY 行情快照 M102 的变种）
"""
import struct
import zlib
from dataclasses import dataclass

MAGIC = b'\x00\x04\xc4\x53'


# ---------- 传输层 ----------

@dataclass
class Frame:
    offset: int
    length: int
    channel_hi: int      # offset 8-11  (type / service?)
    channel_lo: int      # offset 12-15 (sub-type / channel-id?)
    seq: int             # offset 16-19
    t24: int             # offset 24-27 (疑似行情时间戳)
    flag_28: int         # offset 28-31
    compressed: int      # offset 32-35  (0/1)
    flag_36: int         # offset 36-39
    body: bytes          # 解 ZIP 后的业务载荷


def iter_frames(blob: bytes):
    """按 MAGIC 切帧，ZIP 包一并解掉后返回 Frame。"""
    off = 0
    n = len(blob)
    while off < n:
        if blob[off:off+4] != MAGIC:
            raise ValueError(f'bad magic at {off}')
        length     = struct.unpack_from('>I', blob, off+4)[0]
        channel_hi = struct.unpack_from('>I', blob, off+8)[0]
        channel_lo = struct.unpack_from('>I', blob, off+12)[0]
        seq        = struct.unpack_from('>I', blob, off+16)[0]
        t24        = struct.unpack_from('>I', blob, off+24)[0]
        flag_28    = struct.unpack_from('>I', blob, off+28)[0]
        compr      = struct.unpack_from('>I', blob, off+32)[0]
        flag_36    = struct.unpack_from('>I', blob, off+36)[0]
        body = blob[off+40:off+length]
        if compr == 1 and body[:4] == b'PK\x03\x04':
            body = _raw_inflate_zip_lfh(body)
        yield Frame(off, length, channel_hi, channel_lo, seq,
                    t24, flag_28, compr, flag_36, body)
        off += length


def _raw_inflate_zip_lfh(body: bytes) -> bytes:
    """body 以 ZIP Local File Header 开头但无 Central Directory，
    跳过头 + filename + extra 后 raw-deflate 解压。"""
    n = struct.unpack_from('<H', body, 26)[0]   # filename_len
    m = struct.unpack_from('<H', body, 28)[0]   # extra_len
    start = 30 + n + m
    return zlib.decompressobj(-zlib.MAX_WBITS).decompress(body[start:])


# ---------- 应用层：(47, 4701) 的 M201-wrap 包 ----------
#
# body 总 layout（所有数值都是大端）：
#   0-3    : uint32  total_len（含自身 4B）
#   4-7    : ASCII   "M201" 固定标签（厂商伪装成 M201，实际内容是快照）
#   8-15   : uint64  SendingTime（SSE 时间戳，精度待定）
#   16-23  : uint64  MsgSeqNum
#   24-27  : uint32  常量 0x0000C73F
#   28-31  : uint32  类别码（低 2 字节是 SecurityType/SubCategory）
#   32-39  : 8B zero padding
#   40-43  : uint32  TradeDate = 20260114 (BE 十进制)
#   44-46  : 3B ASCII "000"
#   47-48  : uint16  NoEntries (包内快照条数)
#   49+    : 各条快照（变长，依 NoEntries 循环）
#
# 每条快照疑似 layout（正是要对拍的部分，先按 M102 规范+观测结构尝试）：
#   +0   : uint8   SecurityType
#   +1   : uint8   flag / TradSesMode-like（观测恒为 0x01）
#   +2   : uint8   record_tag       （观测恒为 0x75 'u' — 可能是厂商内部 tag）
#   +3   : char[5] MDStreamID       "MD002/MD004/..."
#   +8   : char[8] SecurityID       "600031  " 这种（6 位代码右补空格）
#   +16  : char[8] Symbol GBK       4 个汉字证券名
#   +24  : uint64  PreClosePx       ×10^5（或 ×10^3，按 MDStreamID 决定）
#   +32  : uint64  TotalVolumeTraded
#   +40  : uint64  NumTrades
#   +48  : uint64  TotalValueTraded
#   +56  : uint32  ?                （TotalValueTraded 末段 / 其他字段，待拍）
#   +60  : char[8] TradingPhaseCode "T111    " 这种
#   +68  : uint32  LastUpdateTime   HHMMSSsss 或厂商自己的时间戳
#   +72  : uint16  NoMDEntries      后续买卖盘条目数
#   +74+ : 档位循环体 ......
#
# 注：上面 "+0..+71" 里的字段顺序和精度都是当前猜测，第一版解析器先按此处理，
#    跑出第一批结果后根据 CSV 对拍再逐字段修正。

def parse_m201wrap_header(body: bytes):
    """拆 M201-wrap 包的外层头，返回 (hdr_dict, trade_date, no_entries, entry_payload)。"""
    if len(body) < 49 or body[4:8] != b'M201':
        return None
    total_len   = struct.unpack_from('>I', body, 0)[0]
    send_time   = struct.unpack_from('>Q', body, 8)[0]
    msg_seq     = struct.unpack_from('>Q', body, 16)[0]
    const_c73f  = struct.unpack_from('>I', body, 24)[0]
    category    = struct.unpack_from('>I', body, 28)[0]
    trade_date  = struct.unpack_from('>I', body, 40)[0]
    marker_000  = body[44:47]
    no_entries  = struct.unpack_from('>H', body, 47)[0]
    hdr = dict(
        total_len=total_len, send_time=send_time, msg_seq=msg_seq,
        const_c73f=const_c73f, category=category,
        trade_date=trade_date, marker_000=marker_000,
        no_entries=no_entries,
    )
    return hdr, body[49:]


def dump_m201wrap(body: bytes, max_entries: int = 3):
    """诊断用：打印一包 M201-wrap 的头部和前若干条快照原始字节。"""
    res = parse_m201wrap_header(body)
    if not res:
        print('  [not an M201-wrap]'); return
    hdr, rest = res
    print(f'  hdr: total_len={hdr["total_len"]} send_time=0x{hdr["send_time"]:016x}'
          f' msg_seq={hdr["msg_seq"]}')
    print(f'       const_c73f=0x{hdr["const_c73f"]:08x}  category=0x{hdr["category"]:08x}'
          f' trade_date={hdr["trade_date"]}  marker={hdr["marker_000"]!r}'
          f'  no_entries={hdr["no_entries"]}')
    # 按"每条 ~ 76 字节"的假设切条（临时）
    approx = 76
    for i in range(min(max_entries, hdr['no_entries'])):
        chunk = rest[i*approx:(i+1)*approx]
        print(f'  entry[{i}] ({len(chunk)}B): {chunk.hex()}')
        try:
            mdstream = chunk[3:8].decode('ascii', 'replace').rstrip()
            secid    = chunk[8:16].decode('ascii', 'replace').rstrip()
            symbol   = chunk[16:24].decode('gbk', 'replace').rstrip()
            print(f'         MDStreamID={mdstream!r}  SecurityID={secid!r}  Symbol={symbol!r}')
        except Exception as e:
            print(f'         (decode error: {e})')


# ---------- CLI ----------

def scan(paths, channel_hi=47, channel_lo=4701, show_samples=5):
    import os
    stats = dict(total=0, matched=0, zip_compressed=0, m201=0, other=0, other_head=set())
    samples = []
    for p in paths:
        blob = open(p, 'rb').read()
        for f in iter_frames(blob):
            stats['total'] += 1
            if (f.channel_hi, f.channel_lo) != (channel_hi, channel_lo):
                continue
            stats['matched'] += 1
            if f.compressed:
                stats['zip_compressed'] += 1
            body = f.body
            if body[4:8] == b'M201':
                stats['m201'] += 1
                if len(samples) < show_samples:
                    samples.append((p, f))
            else:
                stats['other'] += 1
                stats['other_head'].add(body[:8].hex())
    print(f'frames total={stats["total"]}  matched({channel_hi},{channel_lo})={stats["matched"]}')
    print(f'  zip={stats["zip_compressed"]}  m201-wrap={stats["m201"]}'
          f'  other={stats["other"]}  other_heads={stats["other_head"]}')
    print()
    for i, (path, f) in enumerate(samples):
        print(f'=== sample #{i}: file={os.path.basename(path)}  off={f.offset}'
              f'  seq={f.seq}  compressed={f.compressed}  body_len={len(f.body)}')
        dump_m201wrap(f.body, max_entries=3)


if __name__ == '__main__':
    import sys
    paths = sys.argv[1:] or [f'/tmp/sse/s{i}.bin' for i in range(5)]
    scan(paths)
