"""head5.pcap 解码结果与 mdl_4_24_0.csv 前段 (Type='S') 交叉验证

用法:  python validate_head5.py data/head5.pcap data/mdl_4_24_0.csv [max_show]
"""
from __future__ import annotations
import sys
import csv
from sse5803_lib import iter_pcap_records
from decode_head5 import parse_head5_record


def load_csv_status(csv_path: str) -> list[dict]:
    """读 CSV 开头的 Type='S' 行，遇到非 S 即停。"""
    rows = []
    with open(csv_path, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['Type'] != 'S':
                break
            rows.append(row)
    return rows


def load_pcap_status(pcap_path: str) -> list[dict]:
    """从第一条 TCP 流解出所有记录，去重后返回。"""
    first_key = None
    rows = []
    for fkey, fi, oseq, rec in iter_pcap_records(pcap_path):
        if first_key is None:
            first_key = fkey
        if fkey != first_key:
            continue   # 只取第一条流（其余流是同一份广播的复制）
        info = parse_head5_record(rec.body)
        t = info['mid_ints'][0] if info['mid_ints'] else None
        if t is not None:
            hh = t // 1_000_000
            mm = (t % 1_000_000) // 10_000
            ss = (t % 10_000) // 100
            cc = t % 100
            tick_time = f'{hh:02d}:{mm:02d}:{ss:02d}.{cc:03d}'
        else:
            tick_time = ''
        rows.append({
            'sec_id':    info['sec_id'] or '?',
            'status':    info['status'] or '?',
            'tick_time': tick_time,
            'pmap':      rec.pmap_bytes.hex(),
        })
    return rows


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    pcap_path = sys.argv[1]
    csv_path  = sys.argv[2]
    max_show  = int(sys.argv[3]) if len(sys.argv) >= 4 else 20

    print(f'# 读 pcap: {pcap_path}')
    pcap_rows = load_pcap_status(pcap_path)
    print(f'# 读 CSV:  {csv_path}')
    csv_rows  = load_csv_status(csv_path)

    n_pcap = len(pcap_rows)
    n_csv  = len(csv_rows)
    n_cmp  = min(n_pcap, n_csv)
    print(f'# pcap 记录数: {n_pcap},  CSV Type=S 行数: {n_csv},  对比行数: {n_cmp}')
    print()

    # ---- 集合对比 (不受顺序影响) ----
    from collections import Counter
    pcap_set = Counter((r['sec_id'], r['status']) for r in pcap_rows)
    csv_set  = Counter((r['SecurityID'], r['TickBSFlag']) for r in csv_rows)

    only_pcap = {k: v for k, v in pcap_set.items() if k not in csv_set}
    only_csv  = {k: v for k, v in csv_set.items()  if k not in pcap_set}

    print(f'# (SecID, Status) 集合对比:')
    print(f'#   只在 pcap 中: {len(only_pcap)} 条')
    print(f'#   只在 CSV  中: {len(only_csv)}  条')
    if not only_pcap and not only_csv:
        print('#   → 完全一致 ✓')
    else:
        if only_pcap:
            print('#   pcap 独有:', list(only_pcap.items())[:max_show])
        if only_csv:
            print('#   CSV 独有: ', list(only_csv.items())[:max_show])

    # ---- 逐行 Status 匹配率 ----
    print()
    status_ok = sum(1 for pr, cr in zip(pcap_rows, csv_rows)
                    if pr['status'] == cr['TickBSFlag'])
    print(f'# 逐行 Status 匹配: {status_ok}/{n_cmp}  ({100*status_ok/n_cmp:.2f}%)')
    status_mismatch = [(i+1, pr, cr) for i, (pr, cr) in enumerate(zip(pcap_rows, csv_rows))
                       if pr['status'] != cr['TickBSFlag']]
    if status_mismatch:
        print(f'# Status 不匹配 (共 {len(status_mismatch)} 条, 前 {max_show}):')
        for idx, pr, cr in status_mismatch[:max_show]:
            print(f'  [{idx}] pcap={pr["status"]}  csv={cr["TickBSFlag"]}')

    # ---- TickTime 对比 (pcap 百分秒 vs CSV 毫秒) ----
    print()
    print('# TickTime 对比 (pcap TransactTime 百分秒 vs CSV TickTime 毫秒):')
    # 建 SecID → CSV TickTime 的查找表
    csv_tick = {r['SecurityID']: r['TickTime'] for r in csv_rows}
    diffs = []
    sample = []
    for pr in pcap_rows:
        if not pr['tick_time']:
            continue
        csv_t = csv_tick.get(pr['sec_id'])
        if csv_t is None:
            continue
        pcap_cc = int(pr['tick_time'][-2:])   # 末两位百分秒
        csv_ms  = int(csv_t[-3:])              # CSV 末三位毫秒
        diff = pcap_cc * 10 - csv_ms           # pcap(ms) - csv(ms)
        diffs.append(diff)
        if len(sample) < 5:
            sample.append((pr['sec_id'], pr['tick_time'], csv_t, diff))
    if diffs:
        from statistics import mean
        cnt = Counter(diffs)
        print(f'#   有 TransactTime 的记录: {len(diffs)} 条')
        print(f'#   pcap_cs×10 - csv_ms 分布: {cnt.most_common(5)}')
        print(f'#   说明: pcap 百分秒精度 = CSV 毫秒 / 10 (截断), 固定差 +10ms 为正常精度损失')
        print(f'#   样例:')
        for sid, pt, ct, d in sample:
            print(f'     SecID={sid}  pcap={pt}  csv={ct}  Δ={d:+d}ms')


if __name__ == '__main__':
    main()
