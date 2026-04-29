"""按观察到的字节结构直接解 head5.pcap

观察到的结构(每条记录, 由 `2d ab` TID 切分):
    PMAP(1~2B) TID(2B) [前导 FAST 整数...] SecID(6B FAST ASCII)
    [中间 FAST 整数...] StatusStr(变长 FAST ASCII, 例如 "SUSP"/"OCALL")
    [Trailer 1B raw, 例如 'H', 末条可能省略]

不靠 CSV 反推, 直接按字节读出来。
用法:  python decode_head5.py data/head5.pcap [max_records]
"""
from __future__ import annotations
import sys
from collections import Counter
from sse5803_lib import (iter_pcap_records, read_fast_uint, read_fast_ascii,
                         tokenize, hex_brief)


def parse_head5_record(rec_body: bytes):
    """按 head5 字节风格解一条记录的 body (PMAP+TID 之后的部分):

      [前导 FAST int...] SecID(6B) [中间 FAST int...] StatusStr(变长 ASCII) [Trailer 1B]

    解析顺序: 先从前往后定位 SecID, 再从后往前定位 Status / Trailer,
    剩下的中间字节按 FAST int 全部读出来当 mid_ints。这样避免 `d3`(=单字符 'S')
    被误认为 Status 字串而把真正的 "SUSP" 漏掉。
    """
    n = len(rec_body)
    if n == 0:
        return dict(prefix_ints=[], sec_id=None, mid_ints=[],
                    status=None, trailer=None, leftover=b'')

    # ---- 1) 从前面定位 SecID (跳过 0~3 个前导 FAST int) ----
    def is_secid_at(p: int) -> bool:
        if p + 6 > n:
            return False
        for j in range(5):
            if not (0x30 <= rec_body[p + j] <= 0x39):
                return False
        last = rec_body[p + 5]
        return bool(last & 0x80) and (0x30 <= (last & 0x7F) <= 0x39)

    prefix_ints: list[int] = []
    sec_id = None
    sec_end = None
    scan = 0
    for _ in range(4):
        if scan >= n:
            break
        if is_secid_at(scan):
            cur = 0
            while cur < scan:
                v, w = read_fast_uint(rec_body, cur)
                if w == 0:
                    break
                prefix_ints.append(v)
                cur += w
            sec_id = (rec_body[scan:scan+5].decode('ascii') +
                      chr(rec_body[scan+5] & 0x7F))
            sec_end = scan + 6
            break
        _v, w = read_fast_uint(rec_body, scan)
        if w == 0:
            break
        scan += w
    if sec_end is None:
        return dict(prefix_ints=prefix_ints, sec_id=None, mid_ints=[],
                    status=None, trailer=None, leftover=rec_body)

    # ---- 2) 从尾巴定位 Trailer + Status ----
    end = n
    trailer = None
    # 末字节没有 stop-bit -> 是 raw trailer
    if end > sec_end and not (rec_body[end - 1] & 0x80):
        trailer = rec_body[end - 1]
        end -= 1
    # 此时 rec_body[end-1] 应该是 stop-bit 字节, 是 Status 字串的末字符
    status = None
    status_start = None
    if end > sec_end and (rec_body[end - 1] & 0x80):
        last_c = rec_body[end - 1] & 0x7F
        if 0x20 <= last_c <= 0x7E:  # ASCII 可见
            # 向前扩: 连续的 MSB=0 ASCII 字符
            i = end - 2
            while i >= sec_end and not (rec_body[i] & 0x80) and 0x20 <= rec_body[i] <= 0x7E:
                i -= 1
            status_start = i + 1
            status = (rec_body[status_start:end - 1].decode('ascii', 'replace')
                      + chr(last_c))

    # ---- 3) 中间 FAST int (SecID 之后, Status 之前) ----
    mid_ints: list[int] = []
    cur = sec_end
    mid_end = status_start if status_start is not None else end
    while cur < mid_end:
        v, w = read_fast_uint(rec_body, cur)
        if w == 0:
            break
        mid_ints.append(v)
        cur += w
    leftover = rec_body[cur:mid_end] if cur < mid_end else b''

    return dict(prefix_ints=prefix_ints, sec_id=sec_id, mid_ints=mid_ints,
                status=status, trailer=trailer, leftover=leftover)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    path = sys.argv[1]
    max_records = int(sys.argv[2]) if len(sys.argv) >= 3 else 0

    status_cnt: Counter = Counter()
    trailer_cnt: Counter = Counter()
    pmap_cnt: Counter = Counter()
    rec_total = 0
    no_secid = 0
    no_status = 0

    print(f"# 读 {path}")
    print("# 列: flow_seq frame# PMAP_hex bits SecID Status Trailer  prefix_ints | mid_ints | leftover_hex")
    for fkey, fi, oseq, rec in iter_pcap_records(path):
        rec_total += 1
        info = parse_head5_record(rec.body)

        status_cnt[info['status']] += 1
        trailer_cnt[info['trailer']] += 1
        pmap_cnt[rec.pmap_bytes.hex()] += 1
        if info['sec_id'] is None: no_secid += 1
        if info['status']  is None: no_status += 1

        if max_records and rec_total <= max_records:
            tr = ('0x%02x' % info['trailer']) if info['trailer'] is not None else '-'
            tr_ch = (chr(info['trailer']) if info['trailer'] is not None
                     and 0x20 <= info['trailer'] < 0x7f else '.')
            sec = info['sec_id'] or '?'
            st = info['status'] if info['status'] is not None else '?'
            pre = ','.join(str(x) for x in info['prefix_ints']) or '-'
            mid = ','.join(str(x) for x in info['mid_ints']) or '-'
            lo = info['leftover'].hex(' ') if info['leftover'] else '-'
            print(f"  oseq={oseq:>7d} f#{fi:<3d}  PMAP={rec.pmap_bytes.hex()} "
                  f"bits={rec.pmap_bits}  SecID={sec}  Status={st!r}  "
                  f"Trailer={tr} '{tr_ch}'  | {pre} | {mid} | {lo}")

    print()
    print(f"# 共解析 {rec_total} 条记录 (TID=5803)")
    print(f"#   找不到 SecID: {no_secid}    找不到 Status: {no_status}")
    print()
    print("# Status 字串分布 (top 20):")
    for k, v in status_cnt.most_common(20):
        print(f"   {v:>8d}  {k!r}")
    print()
    print("# Trailer 字节分布 (top 20):")
    for k, v in trailer_cnt.most_common(20):
        ch = (chr(k) if k is not None and 0x20 <= k < 0x7f else '.')
        kk = ('0x%02x' % k) if k is not None else '-'
        print(f"   {v:>8d}  {kk} '{ch}'")
    print()
    print("# PMAP 字节分布 (top 20):")
    for k, v in pmap_cnt.most_common(20):
        print(f"   {v:>8d}  {k}")


if __name__ == '__main__':
    main()
