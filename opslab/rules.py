# -*- coding: utf-8 -*-
"""告警规则与状态机。

═══ 为什么"抖动抑制"必须写进状态机，而不是靠人肉忽略 ═══
最朴素的告警实现是 `if cpu > 85: 报警`。它的问题不是不准，而是**吵**：
一次 3 秒的毛刺会推一条通知出去，值班的人被训练成不看告警。
所以真实告警系统都要有 `for`（持续多久才算数）和状态机：

       条件为真                 持续 >= for_seconds
  INACTIVE ──────► PENDING ──────────────────────► FIRING
      ▲               │                              │
      │  条件变假      │ 条件变假（抖动，不通知）        │ 条件变假
      └───────────────┘                              ▼
                                                  RESOLVED（通知一次）

  - `for_seconds=0` 时直接 INACTIVE → FIRING（等价于立即告警）
  - **PENDING 阶段条件变假 → 回 INACTIVE，一条通知都不发** ← 这就是抖动抑制
  - FIRING 后条件变假 → RESOLVED 并通知一次（否则值班的人永远不知道恢复了）
  - 缺数据（采集挂了）用 `op="absent"` 单独表达：**指标不来了本身就该告警**，
    不能因为"没有值可以比较"就静默 —— 这是监控系统最经典的自杀方式。
"""

import math
from typing import Callable, Dict, List, Optional, Sequence, Tuple

OPERATORS = (">", ">=", "<", "<=", "==", "!=", "absent")

# 状态
INACTIVE = "INACTIVE"
PENDING = "PENDING"
FIRING = "FIRING"
RESOLVED = "RESOLVED"


def compare(value: float, op: str, threshold: float, missing: bool = False) -> bool:
    """按操作符比较；`missing=True` 表示该指标这一轮没有数据。"""
    if op == "absent":
        return missing
    if missing:
        return False          # 没有值就不触发阈值类告警（由 absent 规则负责）
    if op == ">":
        return value > threshold
    if op == ">=":
        return value >= threshold
    if op == "<":
        return value < threshold
    if op == "<=":
        return value <= threshold
    if op == "==":
        return value == threshold
    if op == "!=":
        return value != threshold
    raise ValueError("未知操作符：%r（可用：%s）" % (op, "/".join(OPERATORS)))


class Rule(object):
    """一条告警规则。

    两种形态：
      - 指标规则：`metric` + 可选 `agg`（avg/min/max/last/p95/...），`window` 秒窗口
      - 探针规则：`probe`（健康检查名），条件 = 该探针 down
    以及一条通用能力：`op="absent"` —— 指标/探针**没有数据**时触发。
    """

    def __init__(self, name, metric=None, op=">", threshold=0.0, for_seconds=0.0,
                 severity="warning", window=60.0, agg=None, probe=None,
                 labels=None, annotations=None, enabled=True):
        if op not in OPERATORS:
            raise ValueError("未知操作符：%r" % (op,))
        if not metric and not probe:
            raise ValueError("规则 %s 必须指定 metric 或 probe" % name)
        if for_seconds < 0:
            raise ValueError("for_seconds 不能为负")
        self.name = name
        self.metric = metric
        self.probe = probe
        self.op = op
        self.threshold = float(threshold)
        self.for_seconds = float(for_seconds)
        self.severity = severity
        self.window = float(window)
        self.agg = agg or ("last" if not metric else "avg")
        self.labels = dict(labels or {})
        self.annotations = dict(annotations or {})
        self.enabled = bool(enabled)

    # 标量键：把 (metric, agg) 压成一个字符串，供 daemon 预计算后直接查表
    @property
    def scalar_key(self) -> str:
        if self.probe:
            return "probe.%s.up" % self.probe
        return "%s|%s" % (self.metric, self.agg)

    def describe(self) -> str:
        subject = self.metric or ("probe " + str(self.probe))
        return "%s %s %g for %gs" % (subject, self.op, self.threshold, self.for_seconds)

    @classmethod
    def from_dict(cls, data: Dict) -> "Rule":
        return cls(
            name=data["name"],
            metric=data.get("metric"),
            probe=data.get("probe"),
            op=data.get("op", ">"),
            threshold=data.get("threshold", 0.0),
            for_seconds=data.get("for_seconds", 0.0),
            severity=data.get("severity", "warning"),
            window=data.get("window", 60.0),
            agg=data.get("agg"),
            labels=data.get("labels"),
            annotations=data.get("annotations"),
            enabled=data.get("enabled", True),
        )


class Alert(object):
    """规则的一次状态跃迁结果"""

    def __init__(self, rule: Rule, state: str, ts: float, value=None,
                 transition: str = "", fingerprint: str = ""):
        self.rule = rule
        self.state = state
        self.ts = float(ts)
        self.value = value
        self.transition = transition      # "->FIRING" / "->RESOLVED" / ...
        self.fingerprint = fingerprint or rule.name
        self.labels: Dict[str, str] = dict(rule.labels)
        self.labels.setdefault("alertname", rule.name)
        self.labels.setdefault("severity", rule.severity)
        self.annotations: Dict[str, str] = dict(rule.annotations)

    def __repr__(self) -> str:
        return "<Alert %s %s value=%s>" % (self.rule.name, self.state, self.value)


class RuleState(object):
    """单条规则（单个指纹）的运行时状态"""

    __slots__ = ("state", "pending_since", "firing_since", "resolved_at",
                 "last_value", "last_eval", "true_count", "eval_count")

    def __init__(self):
        self.state = INACTIVE
        self.pending_since: Optional[float] = None
        self.firing_since: Optional[float] = None
        self.resolved_at: Optional[float] = None
        self.last_value: Optional[float] = None
        self.last_eval: Optional[float] = None
        self.true_count = 0
        self.eval_count = 0


class RuleEngine(object):
    """按时间推进规则状态机。**时间由调用方传入，不读系统时钟** —— 这样测试可以秒推进 30 秒。"""

    def __init__(self, rules: Sequence[Rule]):
        self.rules = list(rules)
        self._states: Dict[str, RuleState] = {r.name: RuleState() for r in self.rules}
        self.history: List[Alert] = []

    def state_of(self, name: str) -> RuleState:
        return self._states[name]

    def snapshot(self) -> Dict[str, str]:
        return {name: st.state for name, st in self._states.items()}

    def active(self) -> List[str]:
        return sorted(n for n, st in self._states.items() if st.state == FIRING)

    def observe(self, ts: float, scalars: Dict[str, float]) -> List[Alert]:
        """推进一轮：scalars 里没有的键视为「缺数据」。返回本轮的跃迁事件。"""
        ts = float(ts)
        events: List[Alert] = []
        for rule in self.rules:
            if not rule.enabled:
                continue
            st = self._states[rule.name]
            if st.last_eval is not None and ts < st.last_eval:
                raise ValueError("时间倒退：%r < %r（规则 %s）" % (ts, st.last_eval, rule.name))
            st.last_eval = ts
            st.eval_count += 1

            key = rule.scalar_key
            raw = scalars.get(key)
            missing = raw is None or (isinstance(raw, float) and math.isnan(raw))
            value = None if missing else float(raw)   # type: ignore
            st.last_value = value

            truth = compare(0.0 if missing else value, rule.op, rule.threshold, missing)  # type: ignore

            if truth:
                st.true_count += 1
                if st.state in (INACTIVE, RESOLVED):
                    if rule.for_seconds <= 0:
                        st.state = FIRING
                        st.firing_since = ts
                        st.resolved_at = None
                        events.append(self._emit(rule, ts, value, "->FIRING", st))
                    else:
                        st.state = PENDING
                        st.pending_since = ts
                        events.append(self._emit(rule, ts, value, "->PENDING", st))
                elif st.state == PENDING:
                    # ⚠️ 这里不能写 `st.pending_since or ts`：pending_since 可能是 **0.0**，
                    #    而 `0.0 or ts` 会取 ts（0.0 是假值），于是"持续够不够"永远算成 0，
                    #    PENDING 就永远升不到 FIRING。这一条是被测试当场抓出来的。
                    since = st.pending_since if st.pending_since is not None else ts
                    if ts - since >= rule.for_seconds:
                        st.state = FIRING
                        st.firing_since = ts
                        events.append(self._emit(rule, ts, value, "->FIRING", st))
            else:
                if st.state == PENDING:
                    # 抖动：还没持续够就恢复 → 一条都不发
                    st.state = INACTIVE
                    st.pending_since = None
                    events.append(self._emit(rule, ts, value, "->INACTIVE", st))
                elif st.state == FIRING:
                    st.state = RESOLVED
                    st.resolved_at = ts
                    events.append(self._emit(rule, ts, value, "->RESOLVED", st))
        self.history.extend(events)
        return events

    def _emit(self, rule: Rule, ts: float, value, transition: str, st: RuleState) -> Alert:
        alert = Alert(rule, st.state, ts, value, transition)
        if transition == "->FIRING":
            alert.annotations.setdefault("summary", "%s 触发：%s" % (rule.name, rule.describe()))
        elif transition == "->RESOLVED":
            alert.annotations.setdefault("summary", "%s 已恢复" % rule.name)
        return alert


def expand_scalars(store, now: float, rules: Sequence[Rule],
                   override: Optional[Dict[str, float]] = None) -> Dict[str, float]:
    """把时序库按规则需求预聚合成标量表（规则只认标量，不认识时序库）。

    override 用来直接塞外部事实（比如探针 up/down、进程存在与否），优先级最高。
    """
    scalars: Dict[str, float] = {}
    for rule in rules:
        if rule.probe:
            continue
        key = rule.scalar_key
        if rule.op == "absent":
            # absent 规则关心的是「有没有点」，而不是聚合值
            points = store.window(rule.metric, now, rule.window)
            if points:
                scalars[key] = points[-1][1]
            continue
        if rule.agg == "last":
            item = store.series(rule.metric).last()
            if item is not None:
                scalars[key] = item[1]
        else:
            agg = store.aggregate(rule.metric, now, rule.window)
            value = agg.get(rule.agg)
            if value is not None and not (isinstance(value, float) and math.isnan(value)):
                scalars[key] = value
    if override:
        scalars.update(override)
    return scalars
