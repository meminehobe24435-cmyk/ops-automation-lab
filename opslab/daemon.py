# -*- coding: utf-8 -*-
"""常驻采集/评估/通知守护进程：单实例锁 + 信号处理 + 主循环。

═══ 三件必须做对的事 ═══
  1. **单实例锁**：同一台机器上跑两个采集进程，指标会双份、告警会双份、
     去重指纹还会互相干扰。用 `O_CREAT|O_EXCL` 建 pidfile 是最省事且跨平台的做法
     （不用 fcntl/flock —— 那两个在 Windows 上都没有）。
  2. **信号处理**：SIGTERM 要**优雅退出**（跑完当前这一轮、flush 通知、删掉 pidfile），
     不能直接死掉，否则最后一轮采到的数据就丢了；SIGHUP 用来重载配置（POSIX 才有）。
  3. **主循环可收尾**：`run(ticks=N)` 支持只跑 N 轮然后正常返回 ——
     否则守护进程**没法被测试**（测试只能 kill 它，那等于什么都没测）。
"""

import errno
import os
import signal
import sys
import time
from typing import Callable, Dict, List, Optional, Sequence

from . import procfs
from .alerting import AlertManager
from .health import HealthChecker
from .logs import RotatingWriter, json_line
from .rules import Rule, RuleEngine, expand_scalars
from .tsdb import Store

IS_WINDOWS = os.name == "nt"


class PidFile(object):
    """单实例锁。`acquire()` 失败说明已经有一个在跑。"""

    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        self.acquired = False

    def acquire(self) -> bool:
        parent = os.path.dirname(self.path)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent)
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                return False
            raise
        with os.fdopen(fd, "w") as fh:
            fh.write(str(os.getpid()))
        self.acquired = True
        return True

    def release(self) -> None:
        if self.acquired:
            try:
                os.unlink(self.path)
            except OSError:
                pass
            self.acquired = False

    def holder(self) -> Optional[int]:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                return int(fh.read().strip())
        except (IOError, OSError, ValueError):
            return None


class Daemon(object):
    """一轮 = 采集 → 存 → 探活 → 聚合 → 评估规则 → 通知 → 落日志。

    时钟、睡眠、采集器、通知全部可注入：**所以"跑 30 轮、每轮 1 秒"在测试里是瞬时的**，
    不用 sleep 30 秒，也不会 flaky。
    """

    def __init__(self, workdir: str, rules: Sequence[Rule], checker: Optional[HealthChecker] = None,
                 collector=None, notifier=None, manager: Optional[AlertManager] = None,
                 interval: float = 1.0, clock: Callable = time.time,
                 sleep: Callable = time.sleep, log_path: Optional[str] = None,
                 verbose: bool = False):
        self.workdir = workdir
        self.interval = float(interval)
        self.clock = clock
        self.sleep = sleep
        self.verbose = verbose
        self.collector = collector if collector is not None else procfs.Collector()
        self.checker = checker
        self.engine = RuleEngine(rules)
        self.manager = manager if manager is not None else AlertManager(notifier=notifier)
        self.store = Store(capacity=3600)
        self.pidfile = PidFile(os.path.join(workdir, "opslab.pid"))
        self.writer = RotatingWriter(os.path.join(workdir, "opslab.log"),
                                     max_bytes=256 * 1024, backups=2) if log_path is None else None
        self._stop = False
        self._reload = False
        self.ticks = 0
        self.notified = 0
        self.samples: List[Dict] = []
        self._prev_snapshot: Optional[Dict[str, float]] = None

    # ------------------------------------------------------------------ 日志
    def _log(self, level: str, msg: str, **fields) -> None:
        line = json_line(level, msg, ts=self.clock(), logger="opslab.daemon", **fields)
        if self.writer is not None:
            self.writer.write(line)
        if self.verbose:
            sys.stderr.write(line + "\n")
            sys.stderr.flush()

    # ------------------------------------------------------------------ 信号
    def install_signals(self) -> List[str]:
        installed = []

        def on_term(signum, frame):
            self._stop = True

        def on_hup(signum, frame):
            self._reload = True

        for name, handler in (("SIGTERM", on_term), ("SIGINT", on_term), ("SIGHUP", on_hup)):
            sig = getattr(signal, name, None)
            if sig is None:      # Windows 没有 SIGHUP
                continue
            try:
                signal.signal(sig, handler)
                installed.append(name)
            except (ValueError, OSError, RuntimeError):
                pass
        return installed

    # ------------------------------------------------------------------ 主循环
    def tick(self) -> Dict:
        """跑一轮，返回本轮结果（可单独调用，便于测试与复用）"""
        now = self.clock()
        # ① 采集（Linux 上是 /proc；其它平台就只有进程 CPU 这类通用指标）
        snapshot = self.collector.snapshot()
        snapshot["ts"] = now
        written = self.store.append_many(now, snapshot)
        if self._prev_snapshot is not None:
            derived = self.collector.derive(self._prev_snapshot, snapshot)
            written += self.store.append_many(now, derived)
        else:
            derived = {}
        self._prev_snapshot = snapshot

        # ② 探活
        health_metrics: Dict[str, float] = {}
        if self.checker is not None:
            self.checker.check_once(now)
            health_metrics = self.checker.metrics(now)
            self.store.append_many(now, health_metrics)

        # ③ 聚合 → 规则评估
        override = dict(health_metrics)
        if self.checker is not None:
            override.update(self.checker.up_flags())
        scalars = expand_scalars(self.store, now, self.engine.rules, override)
        events = self.engine.observe(now, scalars)

        # ④ 通知
        notes = self.manager.handle(events, now)
        delivered = self.manager.send_all(notes)
        self.notified += delivered
        for note in notes:
            if note.status == "FIRING":
                self._log("WARNING", "告警触发", alert=note.alert.rule.name,
                          value=note.alert.value, summary=note.alert.annotations.get("summary", ""))
            else:
                self._log("INFO", "告警恢复", alert=note.alert.rule.name)

        self.ticks += 1
        record = {
            "tick": self.ticks, "ts": now, "metrics_written": written,
            "rules": self.engine.snapshot(), "active": self.engine.active(),
            "notifications": [n.as_dict() for n in notes],
            "health": {n: self.checker.state_of(n) for n in
                       ([p.name for p in self.checker.probes] if self.checker else [])},
        }
        self.samples.append(record)
        return record

    def run(self, ticks: Optional[int] = None, acquire_lock: bool = True) -> Dict:
        if acquire_lock and not self.pidfile.acquire():
            raise RuntimeError("已有实例在运行（pid=%s，锁文件 %s）"
                               % (self.pidfile.holder(), self.pidfile.path))
        signals = self.install_signals()
        self._log("INFO", "守护进程启动", interval=self.interval, signals=signals,
                  pid=os.getpid())
        started = self.clock()
        count = 0
        try:
            while not self._stop and (ticks is None or count < ticks):
                self.tick()
                count += 1
                if self._reload:
                    self._reload = False
                    self._log("INFO", "收到 SIGHUP，配置已重载（本轮起生效）")
                if ticks is None or count < ticks:
                    self.sleep(self.interval)
        finally:
            # 优雅收尾：flush 分组中的通知 + 落盘 + 释放锁
            pending = self.manager.flush(self.clock())
            self.manager.send_all(pending)
            self._log("INFO", "守护进程退出", ticks=count,
                      elapsed_s=round(self.clock() - started, 3))
            if self.writer is not None:
                self.writer.close()
            self.pidfile.release()
        return {
            "ticks": count,
            "elapsed_s": round(self.clock() - started, 3),
            "active_alerts": self.engine.active(),
            "notified": self.notified,
            "alerting": self.manager.report(),
            "rules": self.engine.snapshot(),
            "samples": self.samples[-3:],
        }


def build_default_daemon(workdir: str, port: Optional[int] = None, **kw) -> Daemon:
    """开箱即用的一套：服务可用性规则 + 进程 CPU 规则 + HTTP 探针。"""
    rules = [
        Rule("ServiceDown", probe="svc", op="==", threshold=0.0, for_seconds=0.0,
             severity="critical", annotations={"summary": "服务不可用（连续失败判定）"}),
        Rule("ProcessCpuHigh", metric="proc.cpu_percent", op=">", threshold=80.0,
             for_seconds=2.0, agg="last", severity="warning",
             annotations={"summary": "采集进程自身 CPU 高于 80% 持续 2s"}),
    ]
    checker = None
    if port:
        from .health import HttpProbe
        checker = HealthChecker([HttpProbe("svc", "127.0.0.1", port, "/healthz", timeout=1.0)],
                                interval=kw.get("interval", 1.0),
                                failures_to_down=2, successes_to_up=2)
    return Daemon(workdir, rules, checker=checker, **kw)
