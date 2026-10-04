# -*- coding: utf-8 -*-
"""告警治理：去重 / 分组 / 抑制 / 静默 —— 也就是"别把人吵死"的那一层。

职责链（顺序很重要，写在下面）：
    RuleEngine 产出跃迁事件
        → ① 去重（同一指纹在 FIRING 期间只通知一次；repeat_interval 到了才重复提醒）
        → ② 静默（silence 时间窗 + 标签匹配 → 记录但不通知）
        → ③ 抑制（inhibit：源头在响，就别再响下游 —— 例如整机掉线时不必再报它上面的 12 个服务）
        → ④ 分组（group_by 相同标签的通知合并成一条，附带数量）
        → ⑤ 发送（Notifier，带超时/重试）

为什么抑制（inhibit）不是"可选功能"：一次机架掉电会产生几百条告警，
其中真正有信息量的是最上面那条"节点不可达"。抑制规则就是把人从"300 条通知"里
捞回到"1 条通知 + 299 条已抑制"。
"""

import hashlib
import json
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from . import rules as R


def fingerprint(labels: Dict[str, str], extra: str = "") -> str:
    """指纹 = 标签集的稳定哈希。同一组标签 → 同一指纹 → 可以被去重。"""
    payload = json.dumps(labels, sort_keys=True, ensure_ascii=False) + "|" + extra
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


class Silence(object):
    """静默窗口：在 [starts_at, ends_at] 内、且标签全部匹配的告警不发送（但仍记录状态）。"""

    def __init__(self, matchers: Dict[str, str], starts_at: float, ends_at: float,
                 comment: str = "", created_by: str = "ops"):
        self.matchers = dict(matchers)
        self.starts_at = float(starts_at)
        self.ends_at = float(ends_at)
        self.comment = comment
        self.created_by = created_by

    def matches(self, labels: Dict[str, str], ts: float) -> bool:
        if not (self.starts_at <= ts <= self.ends_at):
            return False
        return all(labels.get(k) == v for k, v in self.matchers.items())


class InhibitRule(object):
    """抑制规则：`source` 正在 FIRING 且标签匹配 → `target` 不发送。"""

    def __init__(self, source: Dict[str, str], target: Dict[str, str],
                 equal: Sequence[str] = (), name: str = ""):
        self.source = dict(source)
        self.target = dict(target)
        self.equal = tuple(equal)
        self.name = name or ("inhibit %s -> %s" % (self.source, self.target))

    def matches(self, labels: Dict[str, str], equal_values: Dict[str, str]) -> bool:
        for k, v in self.target.items():
            if labels.get(k) != v:
                return False
        for key in self.equal:
            if equal_values.get(key) != labels.get(key):
                return False
        return True


class Notification(object):
    def __init__(self, status: str, alert: R.Alert, ts: float, group: str = "",
                 count: int = 1, fingerprint_value: str = "", suppressed: str = ""):
        self.status = status          # FIRING / RESOLVED
        self.alert = alert
        self.ts = float(ts)
        self.group = group
        self.count = int(count)
        self.fingerprint = fingerprint_value
        self.suppressed = suppressed  # "" / "dedupe" / "silence" / "inhibit"

    @property
    def severity(self) -> str:
        return self.alert.rule.severity

    def as_dict(self) -> Dict:
        return {
            "status": self.status,
            "ts": self.ts,
            "alertname": self.alert.rule.name,
            "severity": self.severity,
            "group": self.group,
            "count": self.count,
            "fingerprint": self.fingerprint,
            "value": self.alert.value,
            "labels": self.alert.labels,
            "summary": self.alert.annotations.get("summary", ""),
        }

    def text(self) -> str:
        head = "[%s] %s" % (self.status, self.alert.rule.name)
        if self.count > 1:
            head += " x%d" % self.count
        value = "" if self.alert.value is None else " value=%g" % self.alert.value
        return "%s%s | %s" % (head, value, self.alert.annotations.get("summary", ""))


class AlertManager(object):
    """把规则跃迁事件治理成"人真的该看的通知"。"""

    def __init__(self, notifier=None, group_by: Sequence[str] = (), group_wait: float = 0.0,
                 repeat_interval: float = 0.0, silences: Sequence[Silence] = (),
                 inhibits: Sequence[InhibitRule] = ()):
        self.notifier = notifier
        self.group_by = tuple(group_by)
        self.group_wait = float(group_wait)
        self.repeat_interval = float(repeat_interval)
        self.silences = list(silences)
        self.inhibits = list(inhibits)
        self.notifications: List[Notification] = []
        self.sent: List[Notification] = []
        # 指纹 → 状态
        self._firing: Dict[str, float] = {}       # 指纹 → 首次 FIRING 时间
        self._last_notified: Dict[str, float] = {}
        self._pending_group: Dict[str, List[R.Alert]] = {}
        # 指纹 → 标签，供抑制规则比对。
        # ⚠️ 必须建在实例上：写成类属性会变成**所有实例共享同一个 dict**，
        #    一个 AlertManager 的告警会抑制另一个（多实例并存时几乎必然出问题）。
        self._firing_labels: Dict[str, Dict[str, str]] = {}
        self.stats = {
            "events": 0,
            "firing": 0,
            "resolved": 0,
            "sent": 0,
            "deduped": 0,
            "silenced": 0,
            "inhibited": 0,
            "grouped": 0,
        }

    # ---------------------------------------------------------------- 匹配
    def _group_key(self, alert: R.Alert) -> str:
        if not self.group_by:
            return alert.rule.name
        return ",".join("%s=%s" % (k, alert.labels.get(k, "")) for k in self.group_by)

    def _silenced(self, alert: R.Alert, ts: float) -> bool:
        return any(s.matches(alert.labels, ts) for s in self.silences)

    def _inhibited(self, alert: R.Alert, ts: float) -> bool:
        for rule in self.inhibits:
            for other_fp, since in self._firing.items():
                labels = self._firing_labels.get(other_fp)
                if labels is None or since > ts:
                    continue
                if not all(labels.get(k) == v for k, v in rule.source.items()):
                    continue
                if rule.matches(alert.labels, labels):
                    return True
        return False

    # ---------------------------------------------------------------- 主入口
    def handle(self, events: Sequence[R.Alert], ts: Optional[float] = None) -> List[Notification]:
        """处理一批跃迁事件，返回**实际发出**的通知。"""
        out: List[Notification] = []
        for alert in events:
            if alert.state == R.PENDING or alert.transition == "->INACTIVE":
                continue  # 抖动，不产生通知
            when = float(ts if ts is not None else alert.ts)
            self.stats["events"] += 1
            fp = fingerprint(alert.labels)
            group = self._group_key(alert)

            if alert.state == R.FIRING:
                self.stats["firing"] += 1
                self._firing[fp] = when
                self._firing_labels[fp] = dict(alert.labels)
                # ① 去重：同一指纹已在 FIRING 且还没到 repeat_interval → 不再通知
                if fp in self._last_notified:
                    last = self._last_notified[fp]
                    if self.repeat_interval <= 0 or (when - last) < self.repeat_interval:
                        note = Notification("FIRING", alert, when, group, 1, fp, "dedupe")
                        self.notifications.append(note)
                        self.stats["deduped"] += 1
                        continue
            elif alert.state == R.RESOLVED:
                self.stats["resolved"] += 1
                self._firing.pop(fp, None)
                self._firing_labels.pop(fp, None)

            note = Notification("FIRING" if alert.state == R.FIRING else "RESOLVED",
                                alert, when, group, 1, fp)
            self.notifications.append(note)

            # ② 静默
            if self._silenced(alert, when):
                note.suppressed = "silence"
                self.stats["silenced"] += 1
                continue
            # ③ 抑制（只抑制 FIRING；恢复通知要放出去，否则值班的人不知道恢复了）
            if note.status == "FIRING" and self._inhibited(alert, when):
                note.suppressed = "inhibit"
                self.stats["inhibited"] += 1
                continue
            # ④ 分组聚合
            if self.group_wait > 0 and note.status == "FIRING":
                bucket = self._pending_group.setdefault(group, [])
                bucket.append(alert)
                continue

            self._last_notified[fp] = when
            if alert.state == R.RESOLVED:
                self._last_notified.pop(fp, None)
            out.append(note)
            self.sent.append(note)
            self.stats["sent"] += 1
        return out

    def flush(self, ts: float) -> List[Notification]:
        """把攒着的分组发出去（分组窗口结束时调用）。"""
        out: List[Notification] = []
        for group, alerts in sorted(self._pending_group.items()):
            if not alerts:
                continue
            head = alerts[0]
            count = len(alerts)
            note = Notification("FIRING", head, ts, group, count,
                                fingerprint(head.labels))
            if count > 1:
                self.stats["grouped"] += count - 1
            self.notifications.append(note)
            self.sent.append(note)
            self.stats["sent"] += 1
            out.append(note)
        self._pending_group = {}
        return out

    def send_all(self, notifications: Sequence[Notification]) -> int:
        """真正投递（Notifier 可替换成录制器，测试里不碰网络）。"""
        if self.notifier is None:
            return 0
        delivered = 0
        for note in notifications:
            if self.notifier.send(note):
                delivered += 1
        return delivered

    # 指纹 → 标签，供抑制规则比对（实例属性，见 __init__）

    def compression_ratio(self) -> float:
        """噪声压缩比 = 1 - 发出的通知数 / 原始告警数。"""
        raw = self.stats["firing"] + self.stats["resolved"]
        if raw <= 0:
            return 0.0
        return 1.0 - float(self.stats["sent"]) / raw

    def report(self) -> Dict:
        data = dict(self.stats)
        data["compression_ratio"] = round(self.compression_ratio(), 4)
        return data
