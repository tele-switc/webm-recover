# webm-recover

救回**头部丢失但数据还在**的 WebM 录像。

浏览器用 MediaRecorder 录屏/录课时，数据是边录边写的。如果录制进程被强杀、页面崩溃或断电，
文件开头那几百字节的 `EBML Header / Segment / Info / Tracks` 往往没写全或写歪了，
但后面的音视频 Cluster 链是完整的。这种文件在播放器里显示"损坏"，其实内容一条没丢，
缺的只是目录。本工具把目录重新造出来。

**只读你的文件，不上传任何东西**；恢复结果落在你指定的路径。

## 先判断能不能救

```bash
python tools/dryrun.py 你的录像.webm
```

看两件事：

| 输出 | 判据 |
|---|---|
| `EBML magic ... MISSING` | 头确实没了（如果显示 OK，说明头部完好，问题在别处） |
| `首个可验证 Cluster @ N` | **能找到**才有救。N 就是被毁头部的字节数 |
| `存活链: cluster X \| 块 {1: n, 2: m}` | 簇链连贯、两个轨道都有块，说明音视频都在 |
| `簇时间码逆序 0 次` | 逆序很多说明中间丢过簇 |

如果打印 `!! 找不到可验证 Cluster`，这个文件不是本工具针对的那种损坏
（可能是簇大小写法不同，或数据本身被覆盖），别硬试。

顺带一句判据：`Cluster ID 候选` 数量要跟文件大小对得上。1 GB 的文件在纯随机数据下
大约只会撞到 0.25 个假候选，所以候选数明显大于 1 基本就是真簇。

## 恢复

```bash
python recover.py 损坏.webm 恢复.webm
# 可选：--ffmpeg /path/to/ffmpeg   --keep-raw   --quiet
```

ffmpeg 按 `--ffmpeg` > 环境变量 `WEBM_RECOVER_FFMPEG` > `PATH` 的顺序找，没有内置任何人的绝对路径。
`--ffmpeg` 指定的路径不存在会直接报错退出，不会悄悄改用 PATH 里的另一个 ffmpeg。

流程：扫 Cluster 链 → 从 VP8 关键帧头里读出真实宽高 → 重建 EBML/Info/Tracks →
时间码整体归零 → 让 `ffmpeg -c copy` 规范化容器（不重编码，画质无损）。

跑完会得到 `恢复.webm.report.json`，里面是本次恢复的实测数字（簇数、块数、判定的视频轨/音频轨、
时长、跨度）。
报告里的 `src` 只写文件名，不写你的绝对路径。

验证是否真的可用：

```bash
ffprobe -v error -show_entries stream=codec_type:format=duration 恢复.webm
```

（写成 `stream=codec_type,duration` 也行，但每条流的 duration 会显示 `N/A`，
时长只在 `format=duration` 这一项里。）

## 它假设了什么（不对上就别指望）

这些是 MediaRecorder 的写法，不是所有 WebM 都长这样：

1. **簇是 unknown-size**（`1F43B675` 后跟 `01 FF FF FF FF FF FF FF`，1 字节长度标记 + 7 个 `FF`）
   + 紧跟 `E7` Timestamp。
   ffmpeg 直接封装的文件用的是已知大小簇，本工具会拒绝（退出码 2）而不是硬造一个坏文件。
2. **块是 SimpleBlock（`A3`）**，不是 `BlockGroup > Block`。
3. **轨道 1 = 视频（VP8），轨道 2 = 音频（Opus 48kHz 立体声）**——但轨道角色现在按证据认：
   有 VP8 关键帧魔数的轨算视频轨；只开麦的纯音频录像（只有 Opus 一轨）会被建成纯音频容器，
   不再凭空造一条空的 VP8 视频轨。Tracks 里的 `CodecPrivate` 仍是按 48kHz 立体声写死的
   `OpusHead`；如果你录的是 H.264、或者音频不是 48k 立体声，恢复出来的容器会跟真实负载不符——
   这时先跑 `tools/dump_ebml.py` 看原文件到底怎么写的，再决定要不要改 `recover.py` 里的 `vte`/`ate`。
4. **不重建 Cues / SeekHead / Chapters**。播放器按顺序读没问题，但拖动进度条可能定位不准。
5. 一次录制对应一个文件。多段课堂录制的时间码是连续递增的，需要自己按段拼接。

## 自检

仓库自带一个与真实事故同构、但内容完全人造的验证链路：

```bash
python tests/test_recover.py
```

`tools/make_sample.py` 会用 ffmpeg 现合成一段 testsrc + 440Hz 正弦，重写成
MediaRecorder 的流式结构，再剥掉容器头、前面塞垃圾字节，然后交给 `recover.py`，
最后用 ffprobe 核对轨道/时长，并**真的解出一帧 PNG** 确认不是空壳。
没有 ffmpeg 时端到端用例自动 skip，不会假装通过。

当前本机实测（Python 3.14 + ffmpeg 9）：18 项全过（EBML 编码往返、带边界的 vint 读取、
轨道号回归、样本结构、端到端恢复、解码出真实帧、纯音频输入不被造出视频轨、
报告不含绝对路径、CLI 错误路径、非法长度标记与截断尾不崩栈、体检工具的坏路径提示）。
没有 ffmpeg 时其中 5 项 skip，其余 13 项照跑。

`fixtures/` 里两个参考文件是 ffmpeg 生成的约 1 秒合成片段，只作 EBML 结构参照，
不含任何真实录音录像。

## EBML 的几个坑（本工具踩过，写在这里省你时间）

- 整数元素值带**长度 marker**：track 1 编码成 `0x81`，不是 `0x01`。
  写成 `0x01` 会被解析成"后面还有 8 字节长度"，于是吞掉真实数据，轨道号变成
  `220456113668253` 这种荒谬值，整条链边界全错。
- `SimpleBlock` 的帧头有 flags 字节，`Block`（`BlockGroup` 里那个）**没有**。
  两者偏移不同，Keyframe 位得自己按 VP8 帧首字节 bit0 判断。
- 损坏文件上 `0x00`-`0x0F` 这类**非法长度标记**和**正好截断在文件尾的元素**很常见，
  读变长整数必须带边界（`read_vint`）：拿到 `None` 就当链断了、跳到下一个簇候选重新对齐。
  直接拿 `None` 去算偏移会变成 `TypeError` / `IndexError` 崩栈，用户只看到一屏英文堆栈。

## 依赖

Python 3.8+（只用标准库）+ ffmpeg。不需要 pip install 任何东西。

## 许可

MIT，见 `LICENSE`。
