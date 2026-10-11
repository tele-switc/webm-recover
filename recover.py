#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
webm_recover —— 浏览器 MediaRecorder 录像的 WebM/Matroska 头部丢失恢复器。

适用场景：网页端录制（网课、会议、屏幕共享）用 Chrome/Firefox 的 MediaRecorder 写盘时
被强杀、断电或崩溃，导致文件开头的 EBML Header / Segment / Info / Tracks 全部丢失，
但后半段的 Cluster 链完好。此时文件看似损坏，其实所有音视频数据都还在，缺的只是目录。

做法：扫 Cluster 链 -> 采集轨道事实（块数/关键帧/分辨率/时间码范围）->
      重建 EBML/Info/Tracks -> 时间码归零 -> 交给 ffmpeg 规范化输出。

用法:
    python recover.py <损坏的源文件> <输出文件> [--ffmpeg PATH] [--keep-raw]

ffmpeg 解析顺序：--ffmpeg 参数 > 环境变量 WEBM_RECOVER_FFMPEG > PATH 中的 ffmpeg。
退出码：0 成功；2 找不到可验证的 Cluster；3 ffmpeg 规范化失败（此时 .raw.webm 保留可查）。
"""
import argparse
import collections
import json
import mmap
import os
import shutil
import struct
import subprocess
import sys

CID = bytes.fromhex("1f43b675")          # Cluster
UNKNOWN_SEGMENT = bytes.fromhex("01ffffffffffffff")


def find_ffmpeg(cli=None):
    """按 --ffmpeg > 环境变量 > PATH 的顺序定位 ffmpeg，绝不回退到某个人的绝对路径。"""
    for cand in (cli, os.environ.get("WEBM_RECOVER_FFMPEG"), shutil.which("ffmpeg")):
        if not cand:
            continue
        if os.path.isabs(cand):
            if os.path.exists(cand):
                return cand
        else:
            found = shutil.which(cand)
            if found:
                return found
    raise SystemExit("找不到 ffmpeg：用 --ffmpeg <路径> 指定，或设环境变量 WEBM_RECOVER_FFMPEG，"
                     "或把 ffmpeg 放进 PATH。")


# Windows 下不弹黑窗（CREATE_NO_WINDOW）；非 Windows 不传该参数
NO_WINDOW = {} if os.name != "nt" else {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}


# ---------- EBML 基础编解码 ----------

def vint(b, p):
    """读 EBML 变长整数，返回 (值, 占用字节数)。"""
    x = b[p]
    for k in range(8):
        if x & (0x80 >> k):
            L = k + 1
            v = x & (0xFF >> L)
            for q in range(1, L):
                v = (v << 8) | b[p + q]
            return v, L
    return None, 0


def enc_size(v):
    """把长度写成 EBML 变长元素大小。"""
    for L in range(1, 9):
        if v < (1 << (7 * L)) - 1:
            return bytes([(1 << (8 - L)) | (v >> (8 * (L - 1)))]) + \
                   (v & ((1 << (8 * (L - 1))) - 1)).to_bytes(L - 1, "big")
    raise ValueError("size 超出 8 字节 vint 表示范围: %d" % v)


def el(i, b):
    return bytes.fromhex(i) + enc_size(len(b)) + b


def u(i, v):
    return el(i, v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big"))


def f64(i, v):
    return el(i, struct.pack(">d", v))


def s_(i, x):
    return el(i, x.encode())


def main():
    ap = argparse.ArgumentParser(description="恢复头部丢失的 WebM 录像")
    ap.add_argument("src", help="损坏的源文件（只剩 Cluster 链）")
    ap.add_argument("out", help="输出文件（.webm）")
    ap.add_argument("--ffmpeg", help="ffmpeg 可执行文件路径，默认自动查找")
    ap.add_argument("--keep-raw", action="store_true",
                    help="保留中间产物 .raw.webm（默认规范化成功后删除）")
    ap.add_argument("--quiet", action="store_true", help="只打印最后一行结论")
    a = ap.parse_args()

    # Windows 控制台（GBK）下打印中文会炸，stdout/stderr 统一按 UTF-8 输出
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    if not os.path.exists(a.src):
        raise SystemExit("源文件不存在: %s" % a.src)
    n = os.path.getsize(a.src)
    if n == 0:
        raise SystemExit("源文件为空")

    f = open(a.src, "rb")
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

    def say(*args):
        if not a.quiet:
            print(*args)

    say("size %d (%.2f GB)  EBML magic %s %s" %
        (n, n / 1024 ** 3, mm[:4].hex(), "OK" if mm[:4] == bytes.fromhex("1a45dfa3") else "MISSING"))

    cands = []
    i = 0
    while True:
        j = mm.find(CID, i)
        if j < 0:
            break
        cands.append(j)
        i = j + 1
    say("Cluster ID 候选 %d 个（纯随机数据的期望约 %.2f 个）" % (len(cands), n / 2 ** 32))

    def verify(o):
        """真 Cluster：unknown-size 头 + 紧跟 E7 Timestamp -> (块起点, 时间码)"""
        if o + 13 > n or mm[o + 4] != 0x01:
            return None
        sv, ssz = vint(mm, o + 4)
        p = o + 4 + ssz
        if p >= n or mm[p] != 0xE7:
            return None
        tv, tsz = vint(mm, p + 1)
        return p + 1 + tsz + tv, int.from_bytes(mm[p + 1 + tsz:p + 1 + tsz + tv], "big")

    start = None
    for o in cands:
        if verify(o):
            start = o
            break
    if start is None:
        mm.close()
        f.close()
        print("找不到可验证的 Cluster 起点：这个文件的 Cluster 可能不是 unknown-size 写法"
              "（例如 ffmpeg 直接封装的产物），或损坏程度超出本工具假设。")
        raise SystemExit(2)
    say("首个可验证 Cluster:", start, "（前面 %d 字节是被毁/错位的头）" % start)

    chains, gaps, track_blocks, track_first = [], [], collections.Counter(), {}
    kf_dims, keyframes = collections.Counter(), []
    p, cur = start, None
    while p < n - 8:
        if mm[p:p + 4] == CID:
            v = verify(p)
            if not v:
                gaps.append(p)
                p = min((c for c in cands if c > p), default=n)
                continue
            cur = dict(off=p, ts=v[1], blocks=0, end=p)
            chains.append(cur)
            p = v[0]
            continue
        b = mm[p]
        if b == 0xE7:
            tv, tsz = vint(mm, p + 1)
            if cur is not None:
                cur["ts"] = int.from_bytes(mm[p + 1 + tsz:p + 1 + tsz + tv], "big")
            p = p + 1 + tsz + tv
            continue
        if b == 0xA3:
            sv, ssz = vint(mm, p + 1)
            body = p + 1 + ssz
            tk, tks = vint(mm, body)
            rts = int.from_bytes(mm[body + tks:body + tks + 2], "big")
            flags = mm[body + tks + 2]
            fo, flen = body + tks + 3, body + sv - (body + tks + 3)
            track_blocks[tk] += 1
            if tk not in track_first:
                track_first[tk] = dict(flags=flags, len=flen, head=bytes(mm[fo:fo + 12]))
            if cur is not None:
                cur["blocks"] += 1
                cur["end"] = body + sv
            # VP8 关键帧帧头里带宽高
            if mm[fo + 3:fo + 6] == bytes.fromhex("9d012a"):
                w16 = int.from_bytes(mm[fo + 6:fo + 8], "little")
                h16 = int.from_bytes(mm[fo + 8:fo + 10], "little")
                kf_dims[(w16 & 0x3FFF, (w16 >> 14) & 3, h16 & 0x3FFF, (h16 >> 14) & 3)] += 1
                keyframes.append((fo, flen, cur["ts"], rts))
            p = body + sv
            continue
        gaps.append(p)
        nxt = min((c for c in cands if c > p), default=n)
        if nxt <= p:
            break
        p = nxt

    if not chains:
        mm.close()
        f.close()
        print("Cluster 链为空，无法重建。")
        raise SystemExit(2)

    tsl = [c["ts"] for c in chains]
    base, top = min(tsl), max(tsl)
    say("cluster %d | 块 %s | 关键帧 %d | 断点 %d" %
        (len(chains), dict(track_blocks), len(keyframes), len(gaps)))
    for t in sorted(track_first):
        d = track_first[t]
        say("   track %d: flags %02x 首包 %d 字节 head %s" % (t, d["flags"], d["len"], d["head"].hex()))
    say("分辨率分布:", kf_dims.most_common(3))
    say("时间码 %d -> %d ms（跨度 %.1f s = %.2f h）" % (base, top, (top - base) / 1000, (top - base) / 3.6e6))
    say("覆盖字节 %d .. %d / %d（尾部 %d 字节 = 全文件 %.1f%%）" %
        (start, chains[-1]["end"], n, n - start, 100 * (n - start) / n))

    if kf_dims:
        W = kf_dims.most_common(1)[0][0][0]
        H = kf_dims.most_common(1)[0][0][2]
    else:
        W, H = 0, 0
    # MediaRecorder 的典型写法：轨道 1 = 视频，轨道 2 = 音频（Opus 48kHz 立体声）
    vtk = [t for t in track_blocks if t != 2]
    vidtk = max(vtk, key=lambda t: track_blocks[t]) if vtk else 1
    dur = top - base
    say("判定：视频轨=%d 音频轨=2 分辨率=%dx%d base=%d 时长=%.1fs" % (vidtk, W, H, base, dur / 1000))

    ebml = el("1a45dfa3", u("4286", 1) + u("42f7", 1) + u("42f2", 4) + u("42f3", 8) +
              s_("4282", "webm") + u("4287", 2) + u("4285", 1))
    info = el("1549a966", u("2ad7b1", 1000000) + f64("4489", float(dur)) +
              s_("4d80", "recover") + s_("4744", "recover.py") + s_("7ba9", "recovered"))
    vte = el("ae", u("d7", vidtk) + el("73c5", (1).to_bytes(8, "big")) + u("83", 1) + u("9c", 0) +
             s_("22b59c", "und") + s_("86", "V_VP8") + el("e0", u("b0", W or 1) + u("ba", H or 1)))
    oph = b"OpusHead" + bytes([1, 2]) + struct.pack("<H", 312) + struct.pack("<I", 48000) + \
        struct.pack("<h", 0) + bytes([0])
    ate = el("ae", u("d7", 2) + el("73c5", (2).to_bytes(8, "big")) + u("83", 2) + u("9c", 0) +
             s_("22b59c", "und") + s_("86", "A_OPUS") + u("23e383", 60000000) +
             el("e1", f64("b5", 48000.0) + u("9f", 2)) + el("63a2", oph))
    head = ebml + bytes.fromhex("18538067") + UNKNOWN_SEGMENT + info + \
        el("1654ae6b", vte + (ate if 2 in track_blocks else b""))

    tmp = a.out + ".raw.webm"
    skipped = 0
    with open(tmp, "wb") as o:
        o.write(head)
        p = start
        ncl = 0
        while p < n - 8:
            if mm[p:p + 4] == CID:
                if not verify(p):
                    nxt = min((c for c in cands if c > p), default=n)
                    skipped += nxt - p
                    p = nxt
                    continue
                sv, ssz = vint(mm, p + 4)
                o.write(CID + (UNKNOWN_SEGMENT if mm[p + 4] == 0x01 else enc_size(sv)))
                p += 4 + ssz
                ncl += 1
                continue
            b = mm[p]
            if b == 0xE7:
                tv, tsz = vint(mm, p + 1)
                ts = max(0, int.from_bytes(mm[p + 1 + tsz:p + 1 + tsz + tv], "big") - base)
                o.write(el("e7", ts.to_bytes(tv, "big")))
                p = p + 1 + tsz + tv
                continue
            if b == 0xA3:
                sv, ssz = vint(mm, p + 1)
                o.write(mm[p:p + 1 + ssz + sv])
                p = p + 1 + ssz + sv
                continue
            nxt = min((c for c in cands if c > p), default=n)
            if nxt <= p:
                break
            skipped += nxt - p
            p = nxt
        tail = o.tell()
    mm.close()
    f.close()
    say("重建：cluster %d 个，写出 %d 字节，跳过 %d 字节" % (ncl, tail, skipped))

    ff = find_ffmpeg(a.ffmpeg)
    r = subprocess.run([ff, "-hide_banner", "-v", "error", "-y", "-i", tmp, "-map", "0",
                        "-c", "copy", "-f", "webm", a.out], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", **NO_WINDOW)
    say("规范化 rc=%d %s" % (r.returncode, (r.stderr or "").strip()[:300]))
    if r.returncode != 0:
        print("ffmpeg 规范化失败，中间产物保留在 %s 供排查" % tmp)
        raise SystemExit(3)
    if not a.keep_raw:
        os.remove(tmp)

    # 报告里只留文件名，不留调用者的绝对路径
    report = dict(src=os.path.basename(a.src), size=n, head_lost=start, clusters=len(chains),
                  blocks=dict((str(k), v) for k, v in track_blocks.items()),
                  keyframes=len(keyframes), W=W, H=H, ts_base=base, ts_top=top,
                  span_s=(top - base) / 1000, gaps=len(gaps))
    with open(a.out + ".report.json", "w", encoding="utf-8") as jf:
        json.dump(report, jf, ensure_ascii=False, indent=1)
    print("输出 %s = %d 字节（报告 %s）" % (a.out, os.path.getsize(a.out), a.out + ".report.json"))


if __name__ == "__main__":
    main()
