#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
make_sample.py —— 造一个「头部丢失但 Cluster 链完好」的 WebM 样本，用来验证恢复器。

为什么需要它：真实的浏览器 MediaRecorder 崩溃产物带隐私（录音录像本身），不能进仓库。
本脚本把一个**合成**视频（ffmpeg 生成的 testsrc + sine）重新封装成 MediaRecorder 的
流式写法——unknown-size Cluster + SimpleBlock——然后剥掉容器头并在前面塞垃圾字节，
产出一个与真实事故同构、但内容完全人造的样本文件。

编码要点（踩过坑，别再错）：
  * EBML 的整数元素值带长度 marker：track 1 是 0x81，track 2 是 0x82，**不是 0x01/0x02**。
    写成 0x01 会被当作 8 字节长度标记，后续 7 字节被吞，解析全乱。
  * SimpleBlock(0xA3) = track vint + int16 相对时间码 + 1 字节 flags + 帧数据。
  * Block(0xA1) / BlockGroup(0xA5) 里的 Block **没有 flags 字节**，
    Keyframe 标志位要按 VP8 帧头自己判（帧首字节 bit0==0 即关键帧 → flags=0x80）。

用法:
    python tools/make_sample.py <输出路径> [--seconds 2] [--src 已有的webm]

不带 --src 时自动用 ffmpeg 现场生成合成内容（需要 ffmpeg 在 PATH）。
"""
import argparse
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile

CID = bytes.fromhex("1f43b675")           # Cluster
UNKNOWN = bytes.fromhex("01ffffffffffffff")


def find_ffmpeg():
    c = os.environ.get("WEBM_RECOVER_FFMPEG")
    if c and os.path.exists(c):
        return c
    w = shutil.which("ffmpeg")
    if w:
        return w
    raise SystemExit("需要 ffmpeg：装好后放进 PATH，或设 WEBM_RECOVER_FFMPEG")


# ---------- EBML 基础 ----------

def vint(b, p):
    """读 EBML 变长整数（长度标记 + 低位值），返回 (值, 占用字节数)。"""
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
    """把整数写成 EBML 变长表示（长度字段与无符号整数元素通用）。"""
    for L in range(1, 9):
        if v < (1 << (7 * L)) - 1:
            return bytes([(1 << (8 - L)) | (v >> (8 * (L - 1)))]) + \
                   (v & ((1 << (8 * (L - 1))) - 1)).to_bytes(L - 1, "big")
    raise ValueError(v)


def rid(b, p):
    """读元素 ID（含 marker 位，不做掩码）。返回 (id值, 字节数)。"""
    x = b[p]
    for k in range(8):
        if x & (0x80 >> k):
            return int.from_bytes(b[p:p + k + 1], "big"), k + 1
    return None, 0


def parse_block(bb, cts):
    """Block/SimpleBlock 的公共头部 -> (绝对ts, track, rts, frame)。flags 由调用方决定。"""
    tk, tks = vint(bb, 0)
    if tk is None or tks == 0:
        return None
    rts = int.from_bytes(bb[tks:tks + 2], "big", signed=True)
    frame = bb[tks + 2:]
    return (cts + rts, tk, rts, frame)


def vp8_is_keyframe(frame):
    """VP8 裸帧：首字节最低位 0 = 关键帧（show_frame|partition 结构）。"""
    return bool(frame) and (frame[0] & 0x01) == 0


def extract_blocks(buf):
    """从任意合法 webm 取出所有帧 -> (绝对时间码ms, track, rts, flags, 帧字节)。"""
    out = []
    pos = 0
    while True:
        c = buf.find(CID, pos)
        if c < 0:
            break
        pos = c + 4
        sv, ssz = vint(buf, c + 4)
        if sv is None:
            continue
        # cluster 体范围：未知大小时到下一个 cluster 或文件尾
        nxt = buf.find(CID, c + 4)
        end = len(buf) if sv >= 2 ** (7 * ssz) - 1 or c + 4 + ssz + sv > len(buf) \
            else c + 4 + ssz + sv
        if nxt > 0 and nxt < end:
            end = nxt
        cts = 0
        p = c + 4 + ssz
        while p < end:
            idv, idlen = rid(buf, p)
            if idv is None:
                break
            bv, bsz = vint(buf, p + idlen)
            if bv is None or p + idlen + bsz + bv > len(buf):
                break
            body = buf[p + idlen + bsz:p + idlen + bsz + bv]
            if idv == 0xE7:                       # Timestamp
                cts = int.from_bytes(body, "big")
            elif idv == 0xA3:                     # SimpleBlock（带 flags）
                tk, tks = vint(body, 0)
                rts = int.from_bytes(body[tks:tks + 2], "big", signed=True)
                out.append((cts + rts, tk, rts, body[tks + 2], body[tks + 3:]))
            elif idv == 0xA1:                     # 裸 Block（无 flags 字节）
                r = parse_block(body, cts)
                if r:
                    abs_ts, tk, rts, frame = r
                    out.append((abs_ts, tk, rts, 0x80 if vp8_is_keyframe(frame) else 0x00, frame))
            elif idv == 0xA5:                     # BlockGroup：进去找 Block
                q = 0
                while q < len(body):
                    id2, l2 = rid(body, q)
                    if id2 is None:
                        break
                    v2, s2 = vint(body, q + l2)
                    if v2 is None or q + l2 + s2 + v2 > len(body):
                        break
                    if id2 == 0xA1:
                        r = parse_block(body[q + l2 + s2:q + l2 + s2 + v2], cts)
                        if r:
                            abs_ts, tk, rts, frame = r
                            out.append((abs_ts, tk, rts,
                                        0x80 if vp8_is_keyframe(frame) else 0x00, frame))
                    q = q + l2 + s2 + v2
            p = p + idlen + bsz + bv
    return out


def build_streaming(blocks, ms_per_cluster=250):
    """把帧重写成 MediaRecorder 流式结构：unknown-size Cluster + E7 + SimpleBlock。"""
    if not blocks:
        raise SystemExit("源里没解析出任何 block，无法造样本")
    base = min(b[0] for b in blocks)
    groups = {}
    for ts, tk, rts, flags, frame in blocks:
        groups.setdefault((ts - base) // ms_per_cluster, []).append((ts - base, tk, flags, frame))
    buf = bytearray()
    for key in sorted(groups):
        cts = key * ms_per_cluster
        buf += CID + UNKNOWN                        # cluster：unknown size
        tv = max(1, (cts.bit_length() + 7) // 8)
        buf += bytes.fromhex("e7") + enc_size(tv) + cts.to_bytes(tv, "big")
        for abs_ts, tk, flags, frame in sorted(groups[key], key=lambda x: (x[0], x[1])):
            rts = abs_ts - cts
            payload = enc_size(tk) + struct.pack(">h", rts) + bytes([flags]) + frame
            buf += bytes.fromhex("a3") + enc_size(len(payload)) + payload
    return bytes(buf)


def synth_src(seconds, workdir):
    ff = find_ffmpeg()
    out = os.path.join(workdir, "clean.webm")
    cmd = [ff, "-hide_banner", "-v", "error", "-y",
           "-f", "lavfi", "-i", "testsrc=size=320x240:rate=25:duration=%d" % seconds,
           "-f", "lavfi", "-i", "sine=frequency=440:sample_rate=48000:duration=%d" % seconds,
           "-c:v", "libvpx", "-crf", "10", "-b:v", "300k", "-g", "5", "-auto-alt-ref", "0",
           "-c:a", "libopus", "-b:a", "32k", "-shortest", out]
    kw = {} if os.name != "nt" else {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                       errors="replace", **kw)
    if r.returncode != 0 or not os.path.exists(out):
        raise SystemExit("ffmpeg 合成失败: %s" % (r.stderr or "")[:400])
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out", help="输出：头部被毁的 .webm")
    ap.add_argument("--seconds", type=int, default=2)
    ap.add_argument("--src", help="用已有的合法 webm 作内容源（默认自动合成）")
    ap.add_argument("--junk", type=int, default=4096, help="头部损毁区填多少字节垃圾")
    ap.add_argument("--print-blocks", action="store_true", help="打印取到的帧统计")
    a = ap.parse_args()

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    tmp = tempfile.mkdtemp(prefix="webm-sample-")
    try:
        src = a.src or synth_src(a.seconds, tmp)
        with open(src, "rb") as fh:
            raw = fh.read()
        blocks = extract_blocks(raw)
        per_track = {}
        for b in blocks:
            per_track[b[1]] = per_track.get(b[1], 0) + 1
        keys = sum(1 for b in blocks if b[3] & 0x80)
        print("源 %s：%d 帧，按轨道 %s，关键帧 %d" %
              (os.path.basename(src), len(blocks), per_track, keys))
        if a.print_blocks:
            for b in blocks[:6]:
                print("   ts=%s track=%s rts=%s flags=%02x len=%d head=%s" %
                      (b[0], b[1], b[2], b[3], len(b[4]), b[4][:6].hex()))
        stream = build_streaming(blocks)

        # 头部损毁区：随机字节冒充"被毁/错位的头"，recover.py 会跳过它找首个 Cluster
        rng = random.Random(2026)
        junk = bytes(rng.randrange(256) for _ in range(a.junk))
        with open(a.out, "wb") as f:
            f.write(junk)
            f.write(stream)
        print("样本已写出 %s = %d 字节（前 %d 字节是垃圾头，其后 unknown-size Cluster 链）"
              % (a.out, os.path.getsize(a.out), a.junk))
        print("验证：python recover.py %s recovered.webm" % a.out)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
