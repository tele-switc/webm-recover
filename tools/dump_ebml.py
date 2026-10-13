# -*- coding: utf-8 -*-
# 把参照 webm 的 EBML 结构完整打印，作为重建时的真实依据（不凭记忆断言 ID/取值）
import os, sys

try:                       # Windows GBK 控制台下打印中文不炸
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# vint 从 recover.py 导入：EBML 变长整数这条规则全仓库只留一份
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from recover import vint  # noqa: E402

if len(sys.argv) < 2:
    print("用法: python tools/dump_ebml.py <webm文件> [最多扫描字节]")
    raise SystemExit(2)

NAMES = {
    0x1A45DFA3: "EBML", 0x4286: "EBMLVersion", 0x42F7: "EBMLReadVersion",
    0x42F2: "EBMLMaxIDLength", 0x42F3: "EBMLMaxSizeLength", 0x4282: "DocType",
    0x4287: "DocTypeVersion", 0x4285: "DocTypeReadVersion",
    0x18538067: "Segment", 0x114D9B74: "SeekHead", 0x4DBB: "Seek", 0x53AB: "SeekID",
    0x53AC: "SeekPosition", 0x1549A966: "Info", 0x2AD7B1: "TimestampScale",
    0x4489: "Duration", 0x4461: "MuxingApp", 0x4744: "WritingApp", 0x7BA9: "Title",
    0x44B8: "Delay", 0x1654AE6B: "Tracks", 0xAE: "TrackEntry", 0xD7: "TrackNumber",
    0x73C5: "TrackUID", 0x83: "TrackType", 0x9C: "FlagLacing", 0x86: "CodecID",
    0x25A03C5: "CodecPrivate", 0x63A2: "CodecDelay", 0x1055EE: "CodecDecodePrivate",
    0x23E383: "DefaultDuration", 0x55B0: "FlagInterlaced", 0x23314E: "Language",
    0x22B59C: "Language", 0xB0: "PixelWidth", 0xBA: "PixelHeight", 0xE0: "Video",
    0xE1: "Audio", 0x9F: "Channels", 0xB5: "SamplingFrequency", 0x78B5: "OutputSamplingFrequency",
    0x9A: "DecodingBlock", 0xA3: "SimpleBlock", 0xA1: "Block", 0xAF: "BlockGroup",
    0x1F43B675: "Cluster", 0xE7: "Timestamp", 0x1C53BB6B: "Cues", 0xBB: " CuePoint",
    0xB3: " CueTime", 0x1B: " CueTrackPositions", 0xF7: " CueTrack", 0xF1: " CueClusterPosition",
    0x1254C367: "Tags", 0x73A4: "Tag", 0x1023C2: "TagName", 0x1754B9B9: "TagString",
    0x8E: "Pause", 0x61A7: "CodecName", 0x98: "DefaultInvisible", 0x3B6016: "CodecSettings",
    0x25A1C2: "", 0x55EE: "CodecDelay", 0x56B2: "CodecDecodeAll", 0x4DE6: "MaxBlockAdditionID",
    0x22CD5: "", 0x536E: "MaxBlockAdditionID", 0x55BA: "FlagHeatmap?",
}
CONTAINER = {0x1A45DFA3, 0x18538067, 0x1549A966, 0x1654AE6B, 0xAE, 0xE0, 0xE1, 0x1F43B675,
             0xAF, 0x114D9B74, 0x1C53BB6B, 0xBB, 0x1B, 0x73A4, 0x47B5, 0x1254C367}


def walk(b, lo, hi, depth=0, limit=600):
    p = lo
    while p < hi and limit > 0:
        x = b[p]
        if not (0x80 <= x <= 0xFF) and not (0x40 <= x <= 0x7F) and not (0x20 <= x <= 0x3F) \
           and not (0x10 <= x <= 0x1F):
            print("  " * depth + "!! 非法 ID 0x%02x @%d" % (x, p))
            break
        for k in range(8):
            if x & (0x80 >> k):
                idlen = k + 1
                break
        idv = int.from_bytes(b[p:p + idlen], "big")
        sv, ssz = vint(b, p + idlen)
        if p + idlen + ssz + sv > len(b):
            break
        body = b[p + idlen + ssz:p + idlen + ssz + sv]
        unknown = (sv == 2 ** (7 * ssz) - 1)
        name = NAMES.get(idv, "?0x%X" % idv)
        if idv in (0xA3, 0xA1) or (idv == 0xE7 and depth >= 2):
            tk, tks = vint(body, 0)
            print("  " * depth + "%s @%d len=%d  track=%d rts=%d flags=%02x  head=%s" %
                  (name, p, sv, tk, int.from_bytes(body[tks:tks + 2], "big"),
                   body[tks + 2], body[tks + 3:min(tks + 11, len(body))].hex()))
        elif idv in CONTAINER and not unknown:
            print("  " * depth + "%s @%d len=%d" % (name, p, sv))
            limit -= 1
            limit = walk(body, 0, len(body), depth + 1, limit) or limit
        elif idv == 0x1F43B675:
            print("  " * depth + "Cluster @%d unknown=%s" % (p, unknown))
        else:
            show = body[:12].hex()
            txt = ""
            try:
                if body and all(32 <= c < 127 for c in body):
                    txt = " ='" + body.decode() + "'"
                elif len(body) == 1:
                    txt = " =%d" % body[0]
                elif len(body) in (2, 3, 4, 8) and int.from_bytes(body, "big") < 2**40:
                    txt = " =%d" % int.from_bytes(body, "big")
            except Exception:
                pass
            print("  " * depth + "%s [%s] @%d len=%d %s%s" % (name, hex(idv), p, sv, show, txt))
        p = p + idlen + ssz + (sv if not unknown else 0)
        limit -= 1
        if unknown and idv == 0x18538067:
            walk(b, p, len(b), depth + 1, limit)
            break
    return limit


b = open(sys.argv[1], "rb").read()
print(sys.argv[1], len(b), "bytes")
walk(b, 0, min(len(b), int(sys.argv[2]) if len(sys.argv) > 2 else 2000000), 0, 3000)
