# -*- coding: utf-8 -*-
"""时序存储与窗口聚合。

一个告警系统里最容易被忽略、又最容易算错的地方就是**聚合**：
"最近 5 分钟 CPU 的 p95" —— 5 分钟是滑动窗口、p95 是分位数，
两个定义只要有一个含糊，告警就会忽真忽假。所以这里把定义写死并逐条对账：

  - **窗口**：左闭右开 `[now - window, now]`（含右端点，方便"刚写入的点"立刻可见）
  - **p95**：线性插值法（等价 numpy.percentile 默认 'linear'）：
        idx = q/100 * (n-1);  lo=floor(idx); hi=ceil(idx)
        p = v[lo] + (v[hi] - v[lo]) * (idx - lo)
    n=1 时 p 就等于那个值；这样手算可以对账，nearest-rank 会让 3 个点的 p95 直接等于最大值。
  - **rate**：计数器差分 / 秒，且**回绕或进程重启导致计数器变小**时按重置处理（返回 cur），
    否则会出现一个巨大的负尖峰。

环形缓冲的作用：常驻进程连续采几周，序列不能无限长。RingBuffer 是**定容**的，
写满后覆盖最旧的点 —— 所以 `window()` 一定要按**时间**过滤，而不是按位置取，
否则窗口长度会随着容量变化而漂移（这是我自己踩过的坑）。
"""

import math
from typing import Dict, List, Optional, Sequence, Tuple


class RingBuffer(object):
    """定容环形缓冲：append O(1)，满了覆盖最旧。"""

    __slots__ = ("_buf", "_cap", "_start", "_size")

    def __init__(self, capacity: int):
        if capacity <= 0:
            raise ValueError("capacity 必须为正")
        self._cap = int(capacity)
        self._buf: List[Tuple[float, float]] = [None] * self._cap  # type: ignore
        self._start = 0
        self._size = 0

    def append(self, item: Tuple[float, float]) -> None:
        idx = (self._start + self._size) % self._cap
        self._buf[idx] = item
        if self._size < self._cap:
            self._size += 1
        else:
            self._start = (self._start + 1) % self._cap

    def __len__(self) -> int:
        return self._size

    @property
    def capacity(self) -> int:
        return self._cap

    def to_list(self) -> List[Tuple[float, float]]:
        """最旧 → 最新"""
        return [self._buf[(self._start + i) % self._cap] for i in range(self._size)]

    def latest(self, n: int) -> List[Tuple[float, float]]:
        items = self.to_list()
        return items[-n:] if n < len(items) else items


class Series(object):
    """一条时间序列：时间戳必须非递减，否则直接报错而不是悄悄排序。

    为什么不容忍乱序：真实系统里时间倒退只有两种原因 —— 时钟被 NTP 调回去，
    或者采集线程有 bug。两种都该炸出来，而不是让窗口聚合给出一个看起来合理的错答案。
    """

    def __init__(self, name: str, capacity: int = 4096):
        self.name = name
        self.buf = RingBuffer(capacity)
        self._last_ts: Optional[float] = None
        self.total_appended = 0
        self.total_dropped = 0   # 因乱序被拒

    def append(self, ts: float, value: float) -> None:
        if self._last_ts is not None and ts < self._last_ts:
            self.total_dropped += 1
            raise ValueError("时间戳乱序：%r < 上一个 %r（序列 %s）" % (ts, self._last_ts, self.name))
        self.buf.append((float(ts), float(value)))
        self._last_ts = float(ts)
        self.total_appended += 1

    def __len__(self) -> int:
        return len(self.buf)

    def window(self, now: float, seconds: float) -> List[Tuple[float, float]]:
        lo = now - seconds
        return [(t, v) for t, v in self.buf.to_list() if t >= lo and t <= now]

    def values(self, now: float, seconds: float) -> List[float]:
        return [v for _, v in self.window(now, seconds)]

    def last(self) -> Optional[Tuple[float, float]]:
        items = self.buf.to_list()
        return items[-1] if items else None


def percentile(sorted_values: Sequence[float], q: float) -> float:
    """线性插值分位数（q 取 0~100）。空序列返回 nan。"""
    if not sorted_values:
        return float("nan")
    if q <= 0:
        return float(sorted_values[0])
    if q >= 100:
        return float(sorted_values[-1])
    idx = q / 100.0 * (len(sorted_values) - 1)
    lo = int(math.floor(idx))
    hi = int(math.ceil(idx))
    if lo == hi:
        return float(sorted_values[lo])
    frac = idx - lo
    return float(sorted_values[lo]) + (float(sorted_values[hi]) - float(sorted_values[lo])) * frac


def aggregate_values(values: Sequence[float]) -> Dict[str, float]:
    """一组数的常用聚合量。空序列返回 count=0，其余为 nan。"""
    n = len(values)
    if n == 0:
        return {"count": 0.0, "avg": float("nan"), "min": float("nan"), "max": float("nan"),
                "sum": 0.0, "stddev": float("nan"), "p50": float("nan"),
                "p90": float("nan"), "p95": float("nan"), "p99": float("nan")}
    ordered = sorted(float(v) for v in values)
    total = sum(ordered)
    avg = total / n
    var = sum((v - avg) ** 2 for v in ordered) / n   # 总体方差（不除 n-1）
    return {
        "count": float(n),
        "avg": avg,
        "min": ordered[0],
        "max": ordered[-1],
        "sum": total,
        "stddev": math.sqrt(var),
        "p50": percentile(ordered, 50),
        "p90": percentile(ordered, 90),
        "p95": percentile(ordered, 95),
        "p99": percentile(ordered, 99),
    }


class Store(object):
    """多序列存储 + 窗口聚合。默认容量按「1 秒一个点存 1 小时」估算。"""

    def __init__(self, capacity: int = 3600):
        self.capacity = capacity
        self._series: Dict[str, Series] = {}

    def series(self, name: str) -> Series:
        s = self._series.get(name)
        if s is None:
            s = Series(name, self.capacity)
            self._series[name] = s
        return s

    def metric_names(self) -> List[str]:
        return sorted(self._series)

    def append(self, name: str, ts: float, value: float) -> None:
        self.series(name).append(ts, value)

    def append_many(self, ts: float, metrics: Dict[str, float]) -> int:
        """一次写入一批指标；跳过非有限值（NaN 会把聚合全污染掉）"""
        written = 0
        for name, value in metrics.items():
            if name == "ts":
                continue
            try:
                fv = float(value)
            except (TypeError, ValueError):
                continue
            if math.isnan(fv) or math.isinf(fv):
                continue
            self.append(name, ts, fv)
            written += 1
        return written

    def latest(self, name: str) -> Optional[float]:
        item = self.series(name).last()
        return None if item is None else item[1]

    def window(self, name: str, now: float, seconds: float) -> List[Tuple[float, float]]:
        return self.series(name).window(now, seconds)

    def aggregate(self, name: str, now: float, seconds: float) -> Dict[str, float]:
        return aggregate_values(self.series(name).values(now, seconds))

    def rate(self, name: str, now: float, seconds: float) -> float:
        """计数器速率（每秒增量），**对计数器重置做累加处理**。

        算法（与 Prometheus 的 rate 同口径）：沿窗口内的相邻点求增量，
        增量为正就累加；**增量为负说明计数器被重置**（进程重启 / 32 位回绕），
        此时把"当前值"当作这一段的新增量累加进去。最后除以窗口时间跨度。

        为什么不能简单写 `(末值 - 首值) / dt`：只要窗口里发生过一次重启，
        这个减法就会把重启前的量全丢掉，得到一个明显偏小的速率 —— 属于
        "指标看起来正常、其实含义错了"的那类坑。
        """
        points = self.series(name).window(now, seconds)
        if len(points) < 2:
            return 0.0
        (t0, _v0), (t1, _v1) = points[0], points[-1]
        dt = t1 - t0
        if dt <= 0:
            return 0.0
        increase = 0.0
        prev = points[0][1]
        for _t, value in points[1:]:
            delta = value - prev
            if delta >= 0:
                increase += delta
            else:
                increase += value        # 重置：把当前值算作这一段的增量
            prev = value
        return increase / dt

    def to_dict(self) -> Dict[str, List[List[float]]]:
        """导出（给报告/调试用），点少时才好读。"""
        return {name: [[t, v] for t, v in s.buf.to_list()] for name, s in sorted(self._series.items())}

    def stats(self) -> Dict[str, int]:
        return {
            "series": len(self._series),
            "points": sum(len(s) for s in self._series.values()),
            "capacity_per_series": self.capacity,
        }
