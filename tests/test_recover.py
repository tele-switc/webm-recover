# -*- coding: utf-8 -*-
"""
端到端回归测试（标准库 unittest，无需 pytest）。

跑法：
    python -m unittest discover -s tests -v
或    python tests/test_recover.py

没有 ffmpeg 时端到端用例自动 skip（不会假装通过）。
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

import recover as R            # noqa: E402
import make_sample as M        # noqa: E402

FFMPEG = M.find_ffmpeg() if (os.environ.get("WEBM_RECOVER_FFMPEG") or shutil.which("ffmpeg")) else None
# ffprobe 跟着 ffmpeg 走：PATH 里有就直接用，没有就取同级目录的那个
FFPROBE = "ffprobe" if shutil.which("ffprobe") else (FFMPEG.replace("ffmpeg", "ffprobe") if FFMPEG else None)

CID = bytes.fromhex("1f43b675")
UNKNOWN = bytes.fromhex("01ffffffffffffff")


def run(cmd):
    kw = {} if os.name != "nt" else {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", **kw)


def crafted(tail, junk=2048):
    """垃圾头 + 一个合法 unknown-size Cluster（带 E7 时间码）+ 指定尾巴。
    用来喂各种坏块头：真实损坏文件的特征就是链上随时冒出非法长度标记。"""
    import random
    rng = random.Random(7)
    head = bytes(rng.randrange(256) for _ in range(junk))
    head = head.replace(CID, b"\x00" * 4)          # 垃圾头里不许有簇 ID，保证起点唯一
    cluster = CID + UNKNOWN + bytes.fromhex("e7") + b"\x82" + (500).to_bytes(2, "big")
    return head + cluster + tail


class TestEbmlCodec(unittest.TestCase):
    """容器重建全靠这两个函数，先单独钉住。"""

    def test_vint_roundtrip(self):
        # EBML 长度编码：值必须带长度 marker，1 -> 0x81 而不是 0x01
        for v in (0, 1, 2, 126, 127, 128, 16383, 16384, 2 ** 21 - 2, 2 ** 21):
            enc = R.enc_size(v)
            got, size = R.vint(enc, 0)
            self.assertEqual(size, len(enc), "vint 长度不匹配 %d" % v)
            self.assertEqual(got, v, "往返失败: %d -> %s -> %s" % (v, enc.hex(), got))

    def test_track_number_is_not_plain_byte(self):
        """回归防线：track 号写成 0x01 会让解析器当它是 8 字节长度标记，吞掉后续字节。"""
        self.assertEqual(R.enc_size(1).hex(), "81")
        self.assertEqual(R.enc_size(2).hex(), "82")

    def test_enc_size_rejects_too_large(self):
        with self.assertRaises(ValueError):
            R.enc_size(2 ** 56)

    def test_element_helpers(self):
        self.assertEqual(R.u("d7", 1).hex(), "d78101")
        self.assertEqual(R.s_("4282", "webm").hex(), "4282847765626d")
        # f64: ID(2B) + size(1B, 0x88=长度8) + 8B double
        self.assertEqual(R.f64("4489", 1000.0)[:3].hex(), "448988")
        self.assertEqual(len(R.f64("4489", 1000.0)), 11)

    def test_read_vint_is_bounded(self):
        """read_vint 必须对坏长度标记和越界字段返回 (None, 0)，绝不能抛异常。"""
        self.assertEqual(R.read_vint(b"\x81\x01", 0, 2), (1, 1))          # 正常
        self.assertEqual(R.read_vint(b"\x00\x00", 0, 2), (None, 0))       # 非法标记 0x00
        self.assertEqual(R.read_vint(b"\x0f\x00", 0, 2), (None, 0))       # 非法标记 0x0F
        self.assertEqual(R.read_vint(b"\x81", 1, 1), (None, 0))           # 起点就是文件尾
        self.assertEqual(R.read_vint(b"\x01\xff", 0, 2), (None, 0))       # 8 字节长度写到界外
        self.assertEqual(R.read_vint(b"\x40", 0, 1), (None, 0))           # 2 字节长度只剩 1 字节
        self.assertEqual(R.read_vint(b"\xc0\x00", 0, 2), (64, 1))         # 1 字节长度（marker 在 bit7）


class TestSampleBuilder(unittest.TestCase):
    def test_streaming_layout_is_recoverable(self):
        """make_sample 产出的结构必须满足 recover.verify() 的三条判据。"""
        if not FFMPEG:
            self.skipTest("没有 ffmpeg")
        tmp = tempfile.mkdtemp(prefix="webm-test-")
        try:
            src = M.synth_src(1, tmp)
            with open(src, "rb") as fh:
                blocks = M.extract_blocks(fh.read())
            self.assertGreater(len(blocks), 10, "帧太少")
            stream = M.build_streaming(blocks)
            # build_streaming 故意不写容器头：第一个 Cluster 就在偏移 0
            off = stream.find(M.CID)
            self.assertEqual(off, 0, "样本应当以裸 Cluster 开头（模拟头已丢失）")
            v = R.vint(stream, off + 4)
            self.assertEqual(stream[off + 4], 0x01, "cluster 应写成 unknown size")
            first_inner = off + 4 + v[1]
            self.assertEqual(stream[first_inner], 0xE7, "cluster 头后应紧跟 Timestamp")
            # 轨道号必须是 1/2 这种小值（曾经因为编码错变成 10^14 量级）
            tracks = sorted(set(b[1] for b in blocks))
            self.assertTrue(all(1 <= t <= 250 for t in tracks), "轨道号异常: %s" % tracks)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


@unittest.skipUnless(FFMPEG, "需要 ffmpeg 才能跑端到端")
class TestEndToEnd(unittest.TestCase):
    """完整链路：合成内容 -> 毁头 -> 恢复 -> ffprobe 读回轨道与时长 -> 真解一帧。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="webm-e2e-")
        self.broken = os.path.join(self.tmp, "broken.webm")
        self.out = os.path.join(self.tmp, "recovered.webm")
        run([FFMPEG, "-hide_banner", "-v", "error", "-y",
             "-f", "lavfi", "-i", "testsrc=size=320x240:rate=25:duration=2",
             "-f", "lavfi", "-i", "sine=frequency=440:sample_rate=48000:duration=2",
             "-c:v", "libvpx", "-crf", "10", "-b:v", "300k", "-g", "5", "-auto-alt-ref", "0",
             "-c:a", "libopus", "-b:a", "32k", "-shortest",
             os.path.join(self.tmp, "clean.webm")])
        rc = run([sys.executable, os.path.join(ROOT, "tools", "make_sample.py"),
                  self.broken, "--seconds", "2"])
        self.assertEqual(rc.returncode, 0, rc.stdout + rc.stderr)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_recover_produces_playable_file(self):
        rc = run([sys.executable, os.path.join(ROOT, "recover.py"), self.broken, self.out])
        self.assertEqual(rc.returncode, 0, rc.stdout + rc.stderr)
        self.assertTrue(os.path.exists(self.out))
        self.assertGreater(os.path.getsize(self.out), 10000, "恢复文件过小，八成是空壳")
        self.assertFalse(os.path.exists(self.out + ".raw.webm"), "中间产物应被清理")

        probe = run([FFMPEG.replace("ffmpeg", "ffprobe") if shutil.which("ffprobe") is None
                     else "ffprobe", "-v", "error", "-show_entries",
                     "stream=codec_type:format=duration", "-of", "json", self.out])
        self.assertEqual(probe.returncode, 0, probe.stdout + probe.stderr)
        data = json.loads(probe.stdout)
        kinds = sorted(s.get("codec_type") for s in data.get("streams", []))
        self.assertEqual(kinds, ["audio", "video"], "轨道不对: %s" % kinds)
        dur = float(data.get("format", {}).get("duration", "0") or 0)
        self.assertGreater(dur, 1.0, "时长异常: %s" % dur)

    def test_recovered_stream_actually_decodes(self):
        """只保证容器能打开不够——必须真解出一帧非纯色图像才算恢复成功。"""
        rc = run([sys.executable, os.path.join(ROOT, "recover.py"), self.broken, self.out])
        self.assertEqual(rc.returncode, 0)
        png = os.path.join(self.tmp, "f.png")
        d = run([FFMPEG, "-hide_banner", "-v", "error", "-y", "-i", self.out,
                 "-frames:v", "1", png])
        self.assertEqual(d.returncode, 0, d.stdout + d.stderr)
        self.assertTrue(os.path.exists(png))
        self.assertGreater(os.path.getsize(png), 2000, "解出来的帧太小")

    def test_audio_only_input_recovers_as_audio_only(self):
        """回归防线：只开麦的网课/会议录音只有音频轨。旧逻辑死守「轨 1 = 视频」，
        给这种文件凭空造一条 1x1 的 VP8 轨，真实 Opus 数据整条丢掉。"""
        clean = os.path.join(self.tmp, "clean.webm")
        self.assertTrue(os.path.exists(clean), "setUp 没有合成出 clean.webm")
        with open(clean, "rb") as fh:
            blocks = M.extract_blocks(fh.read())
        audio = [(ts, 1, rts, flags, frame)
                 for ts, tk, rts, flags, frame in blocks if tk == 2]
        self.assertGreater(len(audio), 10, "样本里没有解析出音频块")
        broken = os.path.join(self.tmp, "aonly.webm")
        with open(broken, "wb") as f:
            f.write(os.urandom(2048))               # 被毁的头部
            f.write(M.build_streaming(audio))
        out = os.path.join(self.tmp, "aonly_out.webm")
        rc = run([sys.executable, os.path.join(ROOT, "recover.py"), broken, out])
        self.assertEqual(rc.returncode, 0, rc.stdout + rc.stderr)

        probe = run([FFPROBE, "-v", "error", "-show_entries", "stream=codec_type",
                     "-of", "csv=p=0", out])
        kinds = sorted({ln.strip() for ln in probe.stdout.splitlines() if ln.strip()})
        self.assertEqual(kinds, ["audio"], "纯音频输入被造出了视频轨: %s" % probe.stdout)

        wav = os.path.join(self.tmp, "aonly.wav")
        d = run([FFMPEG, "-hide_banner", "-v", "error", "-y", "-i", out, wav])
        self.assertEqual(d.returncode, 0, d.stdout + d.stderr)
        self.assertGreater(os.path.getsize(wav), 20000, "解出的 PCM 太小，音频其实是空的")

        with open(out + ".report.json", encoding="utf-8") as fh:
            rep = json.load(fh)
        self.assertIsNone(rep["video_track"])
        self.assertEqual(rep["audio_track"], 1)

    def test_report_contains_no_absolute_source_path(self):
        """隐私：报告里只留文件名，不留调用者的绝对路径。"""
        rc = run([sys.executable, os.path.join(ROOT, "recover.py"), self.broken, self.out])
        self.assertEqual(rc.returncode, 0)
        with open(self.out + ".report.json", encoding="utf-8") as fh:
            raw = fh.read()
        rep = json.loads(raw)
        self.assertEqual(rep["src"], "broken.webm")
        for field in ("size", "head_lost", "clusters", "ts_base", "ts_top"):
            self.assertIn(field, rep)
        self.assertNotIn(self.tmp.replace("\\", "/"), raw, "报告泄露了绝对路径")
        self.assertNotIn("\\\\", raw)


class TestCli(unittest.TestCase):
    def test_missing_source_is_clean_error(self):
        rc = run([sys.executable, os.path.join(ROOT, "recover.py"),
                  os.path.join(ROOT, "nope.webm"), os.path.join(ROOT, "out.webm")])
        self.assertNotEqual(rc.returncode, 0)
        self.assertIn("源文件不存在", rc.stderr + rc.stdout)

    def test_directory_source_is_clean_error(self):
        """传了目录应当说人话，不该抛 IsADirectoryError。"""
        rc = run([sys.executable, os.path.join(ROOT, "recover.py"),
                  os.path.join(ROOT, "fixtures"), os.path.join(ROOT, "out.webm")])
        self.assertNotEqual(rc.returncode, 0)
        self.assertNotIn("Traceback", rc.stderr)
        self.assertIn("源路径是目录", rc.stderr + rc.stdout)

    def test_missing_output_dir_is_clean_error(self):
        rc = run([sys.executable, os.path.join(ROOT, "recover.py"),
                  os.path.join(ROOT, "README.md"),
                  os.path.join(tempfile.gettempdir(), "webm-no-such-dir", "out.webm")])
        self.assertNotEqual(rc.returncode, 0)
        self.assertNotIn("Traceback", rc.stderr)
        self.assertIn("输出文件的目录不存在", rc.stderr + rc.stdout)

    def test_bad_explicit_ffmpeg_path_is_not_silently_ignored(self):
        """--ffmpeg 指了个不存在的 exe 必须报错；原先会悄悄改用 PATH 里的另一个 ffmpeg，
        用户以为自己用的是指定那个。"""
        with self.assertRaises(SystemExit) as cm:
            R.find_ffmpeg(os.path.join(tempfile.gettempdir(), "webm-definitely-not-here.exe"))
        self.assertIn("--ffmpeg", str(cm.exception))

    def test_rejects_non_cluster_file(self):
        """不是 MediaRecorder 产物的文件应当以退出码 2 明确拒绝，而不是硬造一个坏文件。"""
        tmp = tempfile.mkdtemp(prefix="webm-cli-")
        try:
            junk = os.path.join(tmp, "junk.webm")
            with open(junk, "wb") as f:
                f.write(os.urandom(50000))
            rc = run([sys.executable, os.path.join(ROOT, "recover.py"), junk,
                      os.path.join(tmp, "o.webm")])
            self.assertEqual(rc.returncode, 2, rc.stdout + rc.stderr)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_illegal_vint_and_truncated_tail_do_not_crash(self):
        """回归防线：链上出现非法长度标记（0x00）或元素正好截断在文件尾时，
        必须按断点跳过并以退出码 2 收场，不能抛 TypeError / IndexError 崩栈。"""
        cases = {
            "A3 后跟非法长度": b"\xa3\x00" + b"\x00" * 7,
            "E7 后跟非法长度": b"\xe7\x00" + b"\x11" * 40,
            "块头正好贴着文件尾": b"\xa3\x01" + b"\x00" * 7,
            "簇头后只剩 E7": b"\xe7",
        }
        tmp = tempfile.mkdtemp(prefix="webm-vint-")
        try:
            for name, tail in cases.items():
                src = os.path.join(tmp, "in.webm")
                with open(src, "wb") as f:
                    f.write(crafted(tail))
                rc = run([sys.executable, os.path.join(ROOT, "recover.py"), src,
                          os.path.join(tmp, "o.webm")])
                self.assertNotIn("Traceback", rc.stderr, "%s 崩栈" % name)
                self.assertNotIn("Error", rc.stderr, "%s 有异常: %s" % (name, rc.stderr[-300:]))
                self.assertEqual(rc.returncode, 2, "%s 退出码应为 2: %s" % (name, rc.stdout))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestDryrun(unittest.TestCase):
    def test_dryrun_survives_illegal_vint(self):
        """README 的第一步就是跑 dryrun 体检，坏块头不能让它只吐一句 ERROR。"""
        tmp = tempfile.mkdtemp(prefix="webm-dry-")
        try:
            src = os.path.join(tmp, "in.webm")
            with open(src, "wb") as f:
                f.write(crafted(b"\xa3\x00" + b"\x00" * 7 + b"\xe7\x00" + b"\x00" * 20))
            rc = run([sys.executable, os.path.join(ROOT, "tools", "dryrun.py"), src])
            out = rc.stdout + rc.stderr
            self.assertNotIn("Traceback", out)
            self.assertNotIn("ERROR", out, out[-300:])
            self.assertEqual(rc.returncode, 0)
            self.assertIn("存活链", out)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_dryrun_reports_bad_paths_in_words(self):
        """体检工具对空文件/目录/不存在的路径要给中文结论，不能只剩一句异常文本。"""
        tmp = tempfile.mkdtemp(prefix="webm-dry2-")
        try:
            empty = os.path.join(tmp, "empty.webm")
            open(empty, "wb").close()
            rc = run([sys.executable, os.path.join(ROOT, "tools", "dryrun.py"),
                      empty, os.path.join(tmp, "nope.webm"), tmp])
            out = rc.stdout + rc.stderr
            self.assertNotIn("Traceback", out)
            self.assertNotIn("ERROR", out, out[-300:])
            for msg in ("文件是空的", "文件不存在", "这是目录"):
                self.assertIn(msg, out)
            # 不给参数时必须喊用法，而不是默默退 0
            rc2 = run([sys.executable, os.path.join(ROOT, "tools", "dryrun.py")])
            self.assertIn("用法", rc2.stdout + rc2.stderr)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
