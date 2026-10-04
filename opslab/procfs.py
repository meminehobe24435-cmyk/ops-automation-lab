# -*- coding: utf-8 -*-
"""解析 /proc 拿指标 —— **读哪个目录是可注入的**。

为什么不用 psutil：本项目的卖点之一是**运行时零第三方依赖**（CI 里有 AST 依赖检查会拦），
而 /proc 的文本格式几十年没变、完全可以自己解析，解析过程还能逐字段对账。

为什么把 root 做成参数：Windows / macOS 上没有 /proc，如果直接写死路径，
这个模块就**只能在没有测试的 Linux 上跑**。把 root 注入之后，
单元测试喂固定样本（`tests/fixtures/proc/`），Linux 上读真实 /proc，同一套解析代码两条路都覆盖。

═══ 解析 /proc 时最容易错的四件事（都写在这里，别再踩） ═══

1. **总 CPU 时间不能把 guest / guest_nice 加进去**：内核文档写明 guest 时间
   **已经包含在 user / nice 里**了，再单独加一遍就重复计算，CPU% 会偏低。
2. **"可用内存"要用 MemAvailable，不能用 MemFree**：MemFree 只是完全没被碰过的页，
   内核可回收的 page cache / slab 才算大头。用 MemFree 算"内存使用率"会得出 80%+ 的假警报。
3. **/proc/diskstats 的扇区数恒按 512 字节折算**，与设备真实扇区大小（4K 盘）无关 ——
   乘 512 才是字节数，不要用 `blockdev --getss` 的结果去乘。
4. **load average 包含不可中断睡眠（D 状态）的进程**：一块慢盘就能把 load 推到很高，
   而 CPU 其实很闲。所以"load 高"≠"CPU 忙"，必须和 cpu.busy 一起看。
"""

import os
import time
from typing import Dict, Iterable, List, Optional, Tuple


def _sysconf(name: str, default: int) -> int:
    fn = getattr(os, "sysconf", None)
    if fn is None:  # Windows 没有 os.sysconf
        return default
    try:
        return int(fn(name))
    except (ValueError, OSError, KeyError):
        return default


CLOCK_TICKS = _sysconf("SC_CLK_TCK", 100)      # 每秒多少个 jiffy，常见 100
PAGE_SIZE = _sysconf("SC_PAGE_SIZE", 4096)     # 字节
SECTOR_SIZE = 512                              # diskstats 恒为 512（见上文第 3 条）

CPU_FIELDS = ("user", "nice", "system", "idle", "iowait",
              "irq", "softirq", "steal", "guest", "guest_nice")
# 参与"总时间"的字段：故意不含 guest / guest_nice（见上文第 1 条）
CPU_TOTAL_FIELDS = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")

_SKIP_DEVICE_PREFIXES = ("loop", "ram", "dm-", "sr", "fd")


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


# --------------------------------------------------------------------------- 解析

def parse_cpu_stat(text: str) -> Dict[str, Dict[str, int]]:
    """`/proc/stat` → {"cpu": {field: jiffies}, "cpu0": {...}, ...}"""
    out: Dict[str, Dict[str, int]] = {}
    for line in text.splitlines():
        parts = line.split()
        if not parts or not parts[0].startswith("cpu"):
            continue
        name = parts[0]
        values = []
        for raw in parts[1:]:
            try:
                values.append(int(raw))
            except ValueError:
                break  # 老内核字段少，遇到非数字就停
        if not values:
            continue
        row = {}
        for idx, field in enumerate(CPU_FIELDS):
            row[field] = values[idx] if idx < len(values) else 0
        out[name] = row
    return out


def parse_meminfo(text: str) -> Dict[str, int]:
    """`/proc/meminfo` → {MemTotal: kB, ...}（单位统一是 kB，除了几个无单位计数）"""
    out: Dict[str, int] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, rest = line.partition(":")
        parts = rest.split()
        if not parts:
            continue
        try:
            out[key.strip()] = int(parts[0])
        except ValueError:
            continue
    return out


def parse_loadavg(text: str) -> Dict[str, float]:
    """`/proc/loadavg` → load1/load5/load15 + runnable/total + last_pid"""
    parts = text.split()
    out = {"load1": 0.0, "load5": 0.0, "load15": 0.0, "runnable": 0.0, "procs": 0.0}
    if len(parts) >= 3:
        try:
            out["load1"], out["load5"], out["load15"] = (float(x) for x in parts[:3])
        except ValueError:
            pass
    if len(parts) >= 4 and "/" in parts[3]:
        runnable, _, total = parts[3].partition("/")
        try:
            out["runnable"], out["procs"] = float(runnable), float(total)
        except ValueError:
            pass
    return out


def parse_uptime(text: str) -> float:
    """`/proc/uptime` → 秒"""
    parts = text.split()
    try:
        return float(parts[0])
    except (IndexError, ValueError):
        return 0.0


def parse_diskstats(text: str, skip_virtual: bool = True) -> Dict[str, Dict[str, float]]:
    """`/proc/diskstats` → {dev: {reads, sectors_read, io_ms, writes, sectors_written, ...}}

    域顺序（内核 Documentation/admin-guide/iostats.rst）：
      major minor name reads_completed reads_merged sectors_read ms_reading
      writes_completed writes_merged sectors_written ms_writing
      ios_in_progress ms_doing_io weighted_ms_doing_io [discards...]
    """
    out: Dict[str, Dict[str, float]] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 14:
            continue
        name = parts[2]
        if skip_virtual and name.startswith(_SKIP_DEVICE_PREFIXES):
            continue
        try:
            nums = [float(x) for x in parts[3:14]]
        except ValueError:
            continue
        out[name] = {
            "reads": nums[0],
            "sectors_read": nums[2],
            "ms_reading": nums[3],
            "writes": nums[4],
            "sectors_written": nums[6],
            "ms_writing": nums[7],
            "in_progress": nums[8],
            "ms_doing_io": nums[9],
            "weighted_ms": nums[10],
        }
    return out


def parse_netdev(text: str) -> Dict[str, Dict[str, float]]:
    """`/proc/net/dev` → {iface: {rx_bytes, rx_packets, rx_errs, rx_drop, tx_bytes, ...}}

    前两行是表头（含接收/发送列说明），要跳过；接口名后面跟着冒号。
    """
    out: Dict[str, Dict[str, float]] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        name, _, rest = line.partition(":")
        name = name.strip()
        if not name or name in ("Inter-|", "face"):
            continue
        parts = rest.split()
        if len(parts) < 16:
            continue
        try:
            nums = [float(x) for x in parts[:16]]
        except ValueError:
            continue
        keys = ("rx_bytes", "rx_packets", "rx_errs", "rx_drop", "rx_fifo", "rx_frame",
                "rx_compressed", "rx_multicast",
                "tx_bytes", "tx_packets", "tx_errs", "tx_drop", "tx_fifo", "tx_colls",
                "tx_carrier", "tx_compressed")
        out[name] = dict(zip(keys, nums))
    return out


# --------------------------------------------------------------------------- 差分

def cpu_times(row: Dict[str, int]) -> Dict[str, int]:
    """从一行 cpu 数据里取参与统计的字段"""
    return {k: int(row.get(k, 0)) for k in CPU_TOTAL_FIELDS}


def cpu_busy_percent(prev: Dict[str, int], cur: Dict[str, int]) -> float:
    """两次采样之间的 CPU 忙碌率（0~100）。

    busy = 总时间增量 - (idle + iowait) 增量。把 iowait 算空闲是通用做法
    （CPU 在等 IO 时确实没干活），但要注意此时 load 会很高 —— 见模块开头的第 4 条。
    """
    prev_t, cur_t = cpu_times(prev), cpu_times(cur)
    deltas = {k: cur_t[k] - prev_t[k] for k in CPU_TOTAL_FIELDS}
    total = sum(deltas.values())
    if total <= 0:
        return 0.0
    idle = deltas["idle"] + deltas["iowait"]
    busy = total - idle
    return max(0.0, min(100.0, busy * 100.0 / total))


def _counter_delta(prev: float, cur: float) -> float:
    """计数器差分；处理回绕/重置（cur < prev 时按重置处理，返回 cur）"""
    if cur >= prev:
        return cur - prev
    return cur


class Collector(object):
    """按 root 目录采集一次快照；Linux 上传 root='/proc'。"""

    def __init__(self, root: str = "/proc", clock=None):
        self.root = root
        self.clock = clock or time.time

    # -- 单个文件读取（缺文件时静默跳过：容器里经常没有 diskstats） -------
    def _read(self, name: str) -> Optional[str]:
        path = os.path.join(self.root, name)
        try:
            return read_text(path)
        except (IOError, OSError):
            return None

    def snapshot(self) -> Dict[str, float]:
        """返回扁平化的 {metric: value}，便于直接灌进时序库"""
        ts = float(self.clock())
        m: Dict[str, float] = {"ts": ts}

        text = self._read("stat")
        if text:
            cpus = parse_cpu_stat(text)
            for field, value in cpus.get("cpu", {}).items():
                m["cpu.jiffies." + field] = float(value)
            for key, row in cpus.items():
                if key == "cpu":
                    continue
                m["cpu." + key + ".jiffies.total"] = float(sum(cpu_times(row).values()))

        text = self._read("meminfo")
        if text:
            info = parse_meminfo(text)
            total = float(info.get("MemTotal", 0))
            available = float(info.get("MemAvailable", 0))
            m["mem.total_kb"] = total
            m["mem.available_kb"] = available
            m["mem.free_kb"] = float(info.get("MemFree", 0))
            m["mem.cached_kb"] = float(info.get("Cached", 0))
            m["swap.total_kb"] = float(info.get("SwapTotal", 0))
            m["swap.free_kb"] = float(info.get("SwapFree", 0))
            if total > 0:
                # 用 MemAvailable（见开头第 2 条）；MemFree 只作为对照指标留下
                m["mem.used_percent"] = round((total - available) * 100.0 / total, 3)
                m["mem.free_percent_naive"] = round(
                    float(info.get("MemFree", 0)) * 100.0 / total, 3)

        text = self._read("loadavg")
        if text:
            load = parse_loadavg(text)
            for key, value in load.items():
                m["load." + key] = float(value)

        text = self._read("uptime")
        if text:
            m["uptime_seconds"] = parse_uptime(text)

        text = self._read("diskstats")
        if text:
            for dev, row in parse_diskstats(text).items():
                m["disk." + dev + ".read_bytes"] = row["sectors_read"] * SECTOR_SIZE
                m["disk." + dev + ".write_bytes"] = row["sectors_written"] * SECTOR_SIZE
                m["disk." + dev + ".io_ms"] = row["ms_doing_io"]
                m["disk." + dev + ".ios_in_progress"] = row["in_progress"]

        text = self._read("net/dev")
        if text:
            for iface, row in parse_netdev(text).items():
                if iface == "lo":
                    continue
                for key in ("rx_bytes", "tx_bytes", "rx_errs", "rx_drop", "tx_errs", "tx_drop"):
                    m["net." + iface + "." + key] = row[key]
        return m

    def derive(self, prev: Dict[str, float], cur: Dict[str, float]) -> Dict[str, float]:
        """把两次快照变成速率/百分比指标（计数器类指标必须差分才有意义）"""
        out: Dict[str, float] = {"ts": cur.get("ts", 0.0)}
        dt = cur.get("ts", 0.0) - prev.get("ts", 0.0)
        if dt <= 0:
            return out

        prev_cpu = {k: prev.get("cpu.jiffies." + k, 0.0) for k in CPU_TOTAL_FIELDS}
        cur_cpu = {k: cur.get("cpu.jiffies." + k, 0.0) for k in CPU_TOTAL_FIELDS}
        if sum(cur_cpu.values()) > 0 and sum(prev_cpu.values()) > 0:
            out["cpu.busy_percent"] = cpu_busy_percent(
                {k: int(v) for k, v in prev_cpu.items()},
                {k: int(v) for k, v in cur_cpu.items()},
            )

        for key, value in cur.items():
            if key.endswith((".read_bytes", ".write_bytes", ".rx_bytes", ".tx_bytes",
                             ".rx_errs", ".tx_errs", ".rx_drop", ".tx_drop")):
                # ⚠️ 派生的名字要**保留原计数器名**：net.eth0.rx_bytes → net.eth0.rx_bytes.rate
                #    早期版本写成 base + ".rate"（丢掉 rx_bytes），结果 rx 和 tx 会互相覆盖，
                #    而且名字对不上（测试里直接 KeyError）。
                out[key + ".rate"] = _counter_delta(prev.get(key, 0.0), value) / dt
            elif key.endswith(".io_ms"):
                base = key[:-len(".io_ms")]
                # 磁盘利用率：IO 时间增量 / 墙钟时间，跨多盘时会 >100%，单盘上限 100%
                util = _counter_delta(prev.get(key, 0.0), value) / (dt * 1000.0) * 100.0
                out[base + ".util_percent"] = min(100.0, util)
            elif key.startswith(("mem.", "load.", "swap.", "uptime")):
                out[key] = value
        return out


def summarize(snapshot: Dict[str, float]) -> str:
    """一行人类可读摘要（CLI 用）"""
    bits = []
    if "cpu.busy_percent" in snapshot:
        bits.append("cpu=%.1f%%" % snapshot["cpu.busy_percent"])
    if "mem.used_percent" in snapshot:
        bits.append("mem=%.1f%%" % snapshot["mem.used_percent"])
    if "load.load1" in snapshot:
        bits.append("load1=%.2f" % snapshot["load.load1"])
    if not bits:
        bits.append("(no metrics)")
    return " ".join(bits)


class ProcessCpuSampler(object):
    """**跨平台**的"本进程 CPU 使用率"采样器。

    为什么不用 /proc：Windows / macOS 上没有 /proc，而"监控进程自己吃多少 CPU"
    是最基础的一条自监控指标。`time.process_time()` 是**进程 CPU 时间**（所有线程之和、
    不含睡眠），两个采样点一减就是这段时间里真正占用的 CPU 时间：

        cpu_percent = Δcpu_time / Δwall_time × 100

    注意两个易错点：
      - 除以**墙钟**时间，不是除以核数；多线程跑满 4 核时这个值会到 ~400%，这是对的。
      - `time.process_time()` 不含 sleep，所以"进程在等待"不会被算成 CPU 忙。
    """

    def __init__(self, clock=None, cpu_clock=None):
        self.clock = clock or time.time
        self.cpu_clock = cpu_clock or time.process_time
        self._last_wall = self.clock()
        self._last_cpu = self.cpu_clock()

    def sample(self) -> float:
        wall = self.clock()
        cpu = self.cpu_clock()
        dt = wall - self._last_wall
        dc = cpu - self._last_cpu
        self._last_wall, self._last_cpu = wall, cpu
        if dt <= 0:
            return 0.0
        return max(0.0, dc / dt * 100.0)
