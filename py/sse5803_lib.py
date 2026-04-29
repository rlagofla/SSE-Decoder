"""上交所 (9, 5803) FAST 行情 —— 字节层解析库 (Python 端)

只做"读字节"的脏活：
  iter_pcap_tcp        —— scapy 读 pcap, 按 (sip,sp,dip,dp) 重组 TCP, 出 server->client 字节流
  iter_frames          —— 在字节流里按 SSE 40B 头切帧, ZIP 帧自动 inflate
  iter_records         —— 一帧 body 内按 FAST TID `2d ab` 切记录
  read_fast_uint       —— FAST stop-bit 变长无符号
  read_fast_ascii      —— FAST ASCII 字串 (末字节 MSB=1 终止)
  decode_pmap_bits     —— PMAP -> 置位 bit 索引列表

业务层(Price/Qty 等语义)不在这里, 留给上层 audit 脚本按 PMAP/字段位置自己组装。
"""

from __future__ import annotations
import struct
import zlib
from dataclasses import dataclass, field
from typing import Iterator

from scapy.all import rdpcap, TCP, IP, Raw  # type: ignore


# ---------- 1) pcap + TCP 重组 ----------

@dataclass
class TcpFlow:
    """单向 TCP 流的累计 buffer (服务端 -> 客户端)。"""
    key: tuple  # (sip, sport, dip, dport)
    first_seq: int | None = None
    chunks: dict = field(default_factory=dict)  # ofs -> payload

    def feed(self, seq: int, payload: bytes):
        if not payload:
            return
        if self.first_seq is None:
            self.first_seq = seq
        ofs = (seq - self.first_seq) & 0xffffffff
        # 重传段会 ofs 相同, 我们只保留第一次见到的 (内容应一致)
        self.chunks.setdefault(ofs, payload)

    def assemble(self) -> bytes:
        """按 ofs 排序拼接。如果中间有洞会被空字节填上(罕见, 用于诊断)。"""
        if not self.chunks:
            return b''
        items = sorted(self.chunks.items())
        out = bytearray()
        cursor = 0
        for ofs, payload in items:
            if ofs > cursor:
                out.extend(b'\x00' * (ofs - cursor))    # 洞
            elif ofs < cursor:
                # 重叠: 截掉重叠部分, 信任已写入的字节
                overlap = cursor - ofs
                if overlap >= len(payload):
                    continue
                payload = payload[overlap:]
                ofs = cursor
            out.extend(payload)
            cursor = ofs + len(payload)
        return bytes(out)


def iter_pcap_tcp(path: str, server_port: int = 5261) -> dict[tuple, bytes]:
    """读 pcap, 重组所有 sport==server_port 的下行流, 返回 {flow_key: 拼接好的字节}.

    flow_key = (server_ip, server_port, client_ip, client_port).
    """
    pkts = rdpcap(path)
    flows: dict[tuple, TcpFlow] = {}
    for pkt in pkts:
        if not pkt.haslayer(TCP):
            continue
        ip = pkt[IP]
        tcp = pkt[TCP]
        if tcp.sport != server_port:
            continue
        payload = bytes(tcp.payload) if tcp.payload else b''
        if not payload:
            continue
        key = (ip.src, tcp.sport, ip.dst, tcp.dport)
        flow = flows.get(key)
        if flow is None:
            flow = flows[key] = TcpFlow(key=key)
        flow.feed(tcp.seq, payload)
    return {k: f.assemble() for k, f in flows.items()}


# ---------- 2) 40B 帧 ----------

SSE_MAGIC = b'\x00\x04\xc4\x53'

@dataclass
class SseFrame:
    outer_seq: int
    type_hi: int          # 9 = (9,5803) 业务大类
    sub_lo: int           # 5803 等
    compressed: int
    raw_body: bytes       # 解压前的 body
    body: bytes           # 解压后的 body (compressed=0 时与 raw_body 相同)
    bad_inflate: bool = False

def _raw_inflate_zip_lfh(body: bytes) -> bytes:
    """body 以 ZIP Local File Header 起头, 跳头+filename+extra 后 raw-deflate 解。"""
    if len(body) < 30 or body[:2] != b'PK':
        raise ValueError('not ZIP LFH')
    name_len = struct.unpack('<H', body[26:28])[0]
    extra_len = struct.unpack('<H', body[28:30])[0]
    start = 30 + name_len + extra_len
    return zlib.decompressobj(-zlib.MAX_WBITS).decompress(body[start:])

def iter_frames(stream: bytes,
                want_hi: int | None = None,
                want_lo: int | None = None) -> Iterator[SseFrame]:
    """按 SSE_MAGIC 切 40B 头帧, 用 length 字段(含 40B 头自身)定边界。"""
    n = len(stream)
    off = 0
    while off + 40 <= n:
        if stream[off:off+4] != SSE_MAGIC:
            nxt = stream.find(SSE_MAGIC, off + 1)
            if nxt < 0:
                return
            off = nxt
            continue
        length     = struct.unpack('>I', stream[off+4:off+8])[0]
        type_hi    = struct.unpack('>I', stream[off+8:off+12])[0]
        sub_lo     = struct.unpack('>I', stream[off+12:off+16])[0]
        outer_seq  = struct.unpack('>I', stream[off+16:off+20])[0]
        compressed = struct.unpack('>I', stream[off+32:off+36])[0]
        if length < 40 or off + length > n:
            return
        if (want_hi is not None and type_hi != want_hi) or \
           (want_lo is not None and sub_lo != want_lo):
            off += length
            continue
        raw_body = bytes(stream[off+40:off+length])
        body = raw_body
        bad = False
        if compressed == 1:
            try:
                body = _raw_inflate_zip_lfh(raw_body)
            except Exception:
                bad = True
        yield SseFrame(outer_seq=outer_seq, type_hi=type_hi, sub_lo=sub_lo,
                       compressed=compressed, raw_body=raw_body, body=body,
                       bad_inflate=bad)
        off += length


# ---------- 3) FAST stop-bit + PMAP ----------

def read_fast_uint(buf: bytes, off: int) -> tuple[int, int]:
    """FAST stop-bit 无符号变长。返回 (value, bytes_consumed); 没遇 stop 返回 (0, 0)."""
    v = 0
    i = off
    while i < len(buf):
        b = buf[i]
        v = (v << 7) | (b & 0x7F)
        i += 1
        if b & 0x80:
            return v, i - off
    return 0, 0

def read_fast_ascii(buf: bytes, off: int) -> tuple[str, int]:
    """FAST ASCII 字串: 末字符 MSB=1 终止. 返回 (str, bytes_consumed)."""
    i = off
    while i < len(buf):
        b = buf[i]
        i += 1
        if b & 0x80:
            return ((buf[off:i-1] + bytes([b & 0x7F])).decode('ascii', 'replace'),
                    i - off)
    return '', 0

def decode_pmap_bits(buf: bytes, off: int) -> tuple[list[int], int]:
    """读 PMAP, 返回 (bit_indices_set, bytes_consumed).

    PMAP: 每字节高位是 stop-bit (1=最后一字节), 低 7 位是数据。
    数据位 MSB-first 排列, byte0 数据位贡献 bit_index 0..6, byte1 贡献 7..13。
    """
    bits: list[int] = []
    i = off
    bit_base = 0
    while i < len(buf):
        b = buf[i]
        data = b & 0x7F
        for k in range(7):
            if data & (1 << (6 - k)):
                bits.append(bit_base + k)
        i += 1
        bit_base += 7
        if b & 0x80:
            return bits, i - off
    return bits, 0


# ---------- 4) 记录拆分 ----------

@dataclass
class RawRecord:
    rec_idx: int
    rec_offset: int           # 在 frame body 内的起始偏移
    pmap_bytes: bytes
    pmap_bits: list[int]
    tid: int                  # 期望 = 5803
    body: bytes               # PMAP+TID 之后到下条 PMAP 之前
    raw: bytes                # 完整记录字节 = pmap+tid+body

def iter_records(frame_body: bytes,
                 tid_word: bytes = b'\x2d\xab',
                 min_gap: int = 4) -> Iterator[RawRecord]:
    """按 TID 字节序列 `2d ab` 切记录。

    TID 命中条件:
      - body[i:i+2] == tid_word
      - body[i-1] MSB=1 (PMAP 末字节 stop-bit)
      - 与上一个 TID 至少间隔 min_gap+2 字节
    PMAP 起点反向扩展: 从 body[i-1] (一定是 stop-bit byte) 起, 向左把所有
    MSB=0 字节也吞进 PMAP, 直到上一条记录边界为止。
    """
    n = len(frame_body)
    tid_pos: list[int] = []
    i = 1
    while i + 1 < n:
        if frame_body[i] == tid_word[0] and frame_body[i+1] == tid_word[1]:
            if (frame_body[i-1] & 0x80) and \
               (not tid_pos or i - tid_pos[-1] >= min_gap + 2):
                tid_pos.append(i)
                i += 2
                continue
        i += 1

    starts: list[int] = []
    for k, ti in enumerate(tid_pos):
        start = ti - 1
        prev_end = tid_pos[k-1] + 1 if k > 0 else -1
        while start - 1 > prev_end and not (frame_body[start - 1] & 0x80):
            start -= 1
        starts.append(start)

    for k, ti in enumerate(tid_pos):
        s = starts[k]
        e = starts[k+1] if k + 1 < len(tid_pos) else n
        if e <= ti + 1:
            continue
        pmap_bytes = frame_body[s:ti]
        bits, w = decode_pmap_bits(pmap_bytes, 0)
        if w != len(pmap_bytes):
            continue
        tid_val, tw = read_fast_uint(frame_body, ti)
        if tw == 0:
            continue
        body_start = ti + tw
        yield RawRecord(
            rec_idx=k,
            rec_offset=s,
            pmap_bytes=bytes(pmap_bytes),
            pmap_bits=bits,
            tid=tid_val,
            body=bytes(frame_body[body_start:e]),
            raw=bytes(frame_body[s:e]),
        )


# ---------- 5) Token 化(诊断用) ----------

@dataclass
class Token:
    kind: str        # 'int' | 'ascii6' | 'ascii_var' | 'raw'
    value: object    # int / str / int (raw byte)
    span: tuple[int, int]
    raw: bytes

def tokenize(body: bytes) -> list[Token]:
    """启发式切 token (字节层, 不做语义判定):
      a) 6B SecID:  前 5 字节 0..9 (MSB=0), 第 6 字节 MSB=1 且低 7bit 为 0..9
      b) ASCII 变长串: 全 0x20..0x7E, 末位 MSB=1 终止 (例如 "SUSP")
      c) FAST stop-bit 整数
      d) 残字节 (没有 stop-bit, 单独标 'raw')
    """
    out: list[Token] = []
    n = len(body)
    off = 0
    while off < n:
        # a) SecID
        if off + 6 <= n and all(0x30 <= body[off+j] <= 0x39 for j in range(5)):
            last = body[off + 5]
            if (last & 0x80) and (0x30 <= (last & 0x7F) <= 0x39):
                s = body[off:off+5].decode('ascii') + chr(last & 0x7F)
                out.append(Token('ascii6', s, (off, off+6), body[off:off+6]))
                off += 6
                continue
        # b) ASCII 变长
        b0 = body[off]
        if b0 != 0 and (b0 < 0x80) and (0x20 <= b0 <= 0x7E):
            i = off
            while i < n and not (body[i] & 0x80) and 0x20 <= body[i] <= 0x7E:
                i += 1
            if i < n and (body[i] & 0x80) and 0x20 <= (body[i] & 0x7F) <= 0x7E:
                s = body[off:i].decode('ascii', 'replace') + chr(body[i] & 0x7F)
                out.append(Token('ascii_var', s, (off, i+1), body[off:i+1]))
                off = i + 1
                continue
        # c) FAST 整数
        v, w = read_fast_uint(body, off)
        if w > 0:
            out.append(Token('int', v, (off, off+w), body[off:off+w]))
            off += w
            continue
        # d) 残字节
        out.append(Token('raw', b0, (off, off+1), body[off:off+1]))
        off += 1
    return out


def hex_brief(b: bytes, max_bytes: int = 16) -> str:
    if len(b) <= max_bytes:
        return b.hex(' ')
    return b[:max_bytes].hex(' ') + f' ... ({len(b)}B)'


# ---------- 6) 高层助手: 一遍遍历整个 pcap 的 (9,5803) 记录 ----------

def iter_pcap_records(pcap_path: str, server_port: int = 5261,
                      type_hi: int = 9, sub_lo: int = 5803):
    """对一个 pcap, yield (flow_key, frame_idx, outer_seq, RawRecord)."""
    flows = iter_pcap_tcp(pcap_path, server_port=server_port)
    for fkey, stream in flows.items():
        for fi, frame in enumerate(iter_frames(stream, want_hi=type_hi, want_lo=sub_lo)):
            if frame.bad_inflate:
                continue
            for rec in iter_records(frame.body):
                yield fkey, fi, frame.outer_seq, rec
