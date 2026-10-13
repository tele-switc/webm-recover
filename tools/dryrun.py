# -*- coding: utf-8 -*-
"""只读体检：数 Cluster / 顺解全链 / 采集轨道事实 / 判断头部损毁类型。不写任何文件。
用法: python tools/dryrun.py <file1> [file2 ...]
"""
import mmap, os, sys, collections

try:                       # Windows GBK 控制台下打印中文不炸
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# EBML 的规则只留一份：CID 与 vint 从 recover.py 导入。改主脚本时体检工具跟着一起变，
# 不会出现"主脚本修好了、dryrun 还在用旧规则"的漂移（那正是 README 里写的第一号坑）。
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from recover import CID, vint  # noqa: E402


def read_vint(b, p, n):
    """带边界的 vint：损坏文件里长度标记可能非法（0x00-0x0F）或字段越过文件尾，
    这时返回 (None, 0)，让上层按「链断了」处理，而不是拿 None 去算偏移崩栈。"""
    if p >= n:
        return None, 0
    x = b[p]
    for k in range(8):
        if x & (0x80 >> k):
            L = k + 1
            if p + L > n:
                return None, 0
            v = x & (0xFF >> L)
            for q in range(1, L):
                v = (v << 8) | b[p + q]
            return v, L
    return None, 0


def probe(path):
    print("=" * 78)
    print(path)
    # 体检是新手的第一步：路径问题要用中文说清楚，别抛 ValueError: cannot mmap an empty file
    if not os.path.exists(path):
        print("!! 文件不存在（检查路径有没有打错，注意用真实文件名）")
        return
    if os.path.isdir(path):
        print("!! 这是目录，要给具体的 .webm 文件名")
        return
    if os.path.getsize(path) == 0:
        print("!! 文件是空的（0 字节），没有任何数据可救")
        return
    f = open(path, "rb")
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    n = len(mm)
    print("size %d (%.2f GB)  EBML magic %s %s" %
          (n, n / 1024 ** 3, mm[:4].hex(),
           "OK(未损坏)" if mm[:4] == bytes.fromhex("1a45dfa3") else "MISSING"))

    cands, i = [], 0
    while True:
        j = mm.find(CID, i)
        if j < 0:
            break
        cands.append(j)
        i = j + 1
    print("Cluster ID 候选 %d 个（随机期望 %.2f）" % (len(cands), n / 2 ** 32))

    def verify(o):
        if o + 13 > n or mm[o + 4] != 0x01:
            return None
        sv, ssz = read_vint(mm, o + 4, n)
        p = o + 4 + ssz
        if p >= n or mm[p] != 0xE7:
            return None
        tv, tsz = read_vint(mm, p + 1, n)
        if tv is None or p + 1 + tsz + tv > n:
            return None
        return p + 1 + tsz + tv, int.from_bytes(mm[p + 1 + tsz:p + 1 + tsz + tv], "big")

    start = None
    for o in cands:
        if verify(o):
            start = o
            break
    if start is None:
        print("!! 找不到可验证 Cluster")
        mm.close(); f.close(); return
    print("首个可验证 Cluster @ %d（前面 %d 字节 = 头部损毁区）" % (start, start))

    # 头部损毁区是什么：随机垃圾 or 同流错位碎片？
    pre = bytes(mm[:start]) if start < 4_000_000 else bytes(mm[:4_000_000])
    print("  损毁区(前 %d 字节)内: A3块ID %d 次 / 43C382 %d 次 / ff03 %d 次 / Cluster %d 个 / VP8关键帧 %d 个"
          % (len(pre), pre.count(b"\xa3"), pre.count(bytes.fromhex("43c382")),
             pre.count(bytes.fromhex("ff03")), pre.count(CID),
             pre.count(bytes.fromhex("9d012a"))))
    # 熵粗判
    cnt = collections.Counter(pre)
    import math
    H = -sum(c / len(pre) * math.log2(c / len(pre)) for c in cnt.values())
    print("  损毁区字节熵 %.2f bits/byte（>7.5≈随机或已压缩负载）" % H)

    chains, gaps, tblocks, tfirst, kf_dims, keyframes = [], [], collections.Counter(), {}, collections.Counter(), []
    tlens, bad_elem = collections.Counter(), collections.Counter()
    p, cur = start, None
    while p < n - 8:
        if mm[p:p + 4] == CID:
            v = verify(p)
            if not v:
                gaps.append(p)
                nxt = min((c for c in cands if c > p), default=n)
                if nxt <= p:
                    break
                p = nxt
                continue
            cur = dict(off=p, ts=v[1], blocks=0, end=p)
            chains.append(cur)
            p = v[0]
            continue
        b = mm[p]
        if b == 0xE7:
            tv, tsz = read_vint(mm, p + 1, n)
            if tv is None or p + 1 + tsz + tv > n:
                gaps.append(p)
                nxt = min((c for c in cands if c > p), default=n)
                if nxt <= p:
                    break
                p = nxt
                continue
            if cur is not None:
                cur["ts"] = int.from_bytes(mm[p + 1 + tsz:p + 1 + tsz + tv], "big")
            p = p + 1 + tsz + tv
            continue
        if b == 0xA3:
            sv, ssz = read_vint(mm, p + 1, n)
            body = p + 1 + ssz
            tk, tks = read_vint(mm, body, n) if sv is not None else (None, 0)
            if (sv is None or tk is None or tks == 0 or tk < 1 or sv < tks + 3
                    or body + sv > n):      # 块头自洽性检查：不满足就当断点跳过，不再拿 None 运算
                gaps.append(p)
                nxt = min((c for c in cands if c > p), default=n)
                if nxt <= p:
                    break
                p = nxt
                continue
            rts = int.from_bytes(mm[body + tks:body + tks + 2], "big")
            flags = mm[body + tks + 2]
            fo, flen = body + tks + 3, body + sv - (body + tks + 3)
            tblocks[tk] += 1
            tlens[(tk, flen)] += 1
            if tk not in tfirst:
                tfirst[tk] = dict(flags=flags, len=flen, head=bytes(mm[fo:fo + 10]))
            if cur is not None:
                cur["blocks"] += 1
                cur["end"] = body + sv
            if mm[fo + 3:fo + 6] == bytes.fromhex("9d012a"):
                w16 = int.from_bytes(mm[fo + 6:fo + 8], "little")
                h16 = int.from_bytes(mm[fo + 8:fo + 10], "little")
                kf_dims[(w16 & 0x3FFF, (w16 >> 14) & 3, h16 & 0x3FFF, (h16 >> 14) & 3)] += 1
                keyframes.append((fo, flen, cur["ts"] if cur else 0, rts))
            p = body + sv
            continue
        bad_elem[hex(b)] += 1
        gaps.append(p)
        nxt = min((c for c in cands if c > p), default=n)
        if nxt <= p:
            break
        p = nxt

    if not chains:
        print("!! 找到 Cluster 起点但没能顺出任何完整链（负载写法可能与本工具假设不符）")
        mm.close(); f.close(); return
    tsl = [c["ts"] for c in chains]
    base, top = min(tsl), max(tsl)
    print("存活链: cluster %d | 块 %s | 关键帧 %d | 断点 %d | 异常元素 %s"
          % (len(chains), dict(tblocks), len(keyframes), len(gaps), dict(bad_elem.most_common(5))))
    for t in sorted(tfirst):
        d = tfirst[t]
        print("   track %d: flags %02x 首包 %d 字节 head %s" % (t, d["flags"], d["len"], d["head"].hex()))
    print("   块长分布:", sorted(tlens.items(), key=lambda kv: -kv[1])[:4])
    print("分辨率分布:", kf_dims.most_common(3))
    print("时间码 %d -> %d ms（跨度 %.1f s = %.2f h）" % (base, top, (top - base) / 1000, (top - base) / 3.6e6))
    print("覆盖字节 %d .. %d / %d（存活尾部 %d 字节 = 全文件 %.1f%%）"
          % (start, chains[-1]["end"], n, n - start, 100 * (n - start) / n))
    # 时间码是否单调（判断有没有丢簇/断流）
    mono = sum(1 for a, b in zip(tsl, tsl[1:]) if b < a)
    dts = [b - a for a, b in zip(tsl, tsl[1:])]
    print("   簇时间码逆序 %d 次；簇间隔 min %s / max %s ms" % (mono, min(dts) if dts else "-", max(dts) if dts else "-"))
    mm.close(); f.close()


if len(sys.argv) < 2:                 # 和 tools/dump_ebml.py 一致：不给参数就说用法，别默默退出
    print("用法: python tools/dryrun.py <file1> [file2 ...]")
    raise SystemExit(2)

for pth in sys.argv[1:]:
    try:
        probe(pth)
    except Exception as e:
        print("ERROR", pth, type(e).__name__, e)
