# -*- coding: utf-8 -*-
"""应急预案剧本（playbook）：把"出事了该怎么办"写成可执行、可演练、可审计的步骤。

═══ 为什么应急预案必须可执行 ═══
写在 Word 里的预案有三个必然结局：没人看、看的人记不住、真出事时不敢照着做。
把它做成机器能跑的剧本，就多了三个性质：
  - **可演练**：平时就能在测试环境跑（`chaos.py` 就是干这个的），而不是等真出事
  - **可审计**：每一步的开始/结束/耗时/退出码都留痕，事后能复盘"为什么处置慢了 40 秒"
  - **有回滚**：任何一步失败都能沿回滚链退回去，不会把系统停在一个"半处置"状态

═══ 三条语义（写死，别含糊） ═══
  1. **超时**：每步有自己的 `timeout`，全局还有 `timeout`。超时 = 该步失败（不是"再等等"）。
  2. **幂等**：步骤可以用 `skip_if` 声明"如果满足这个条件就说明已经做过了"。
     例：重启服务前先探测口 —— 端口已经在监听就跳过重启。重复执行剧本是安全的。
  3. **dry_run**：只跑"读"操作（probe），跳过所有"写"操作（exec / kill / http_post），
     用来在上生产前先看一眼"这套剧本会做什么"。
"""

import time
from typing import Callable, Dict, List, Optional, Sequence

from . import procs
from .health import CommandProbe, FileProbe, HttpProbe, ProcessProbe, TcpProbe

OK = "OK"
FAILED = "FAILED"
SKIPPED = "SKIPPED"
TIMEOUT = "TIMEOUT"

READ_ONLY_TYPES = ("probe", "wait_probe", "note", "sleep")


def build_probe(spec: Dict):
    """按规格造一个探针（剧本 JSON 里就是这么写的）"""
    kind = spec.get("kind", "tcp")
    name = spec.get("name", kind)
    timeout = float(spec.get("timeout", 2.0))
    if kind == "tcp":
        return TcpProbe(name, spec.get("host", "127.0.0.1"), int(spec["port"]), timeout)
    if kind == "http":
        return HttpProbe(name, spec.get("host", "127.0.0.1"), int(spec["port"]),
                         spec.get("path", "/healthz"),
                         spec.get("expect_status", (200,)), spec.get("expect_body"), timeout)
    if kind == "process":
        return ProcessProbe(name, spec.get("pid"), spec.get("pidfile"))
    if kind == "file":
        return FileProbe(name, spec["path"], float(spec.get("max_age", 300)), int(spec.get("min_size", 0)))
    if kind == "command":
        return CommandProbe(name, spec["argv"], int(spec.get("expect_rc", 0)), timeout)
    raise ValueError("未知探针类型：%r" % (kind,))


class Step(object):
    def __init__(self, id, type, timeout=10.0, expect=True, argv=None, probe=None,
                 background=False, skip_if=None, on_failure="abort", sleep=0.0,
                 target=None, message="", interval=0.2, blocking=True, **extra):
        self.id = id
        self.type = type
        self.timeout = float(timeout)
        self.expect = bool(expect)
        self.argv = list(argv or [])
        self.spec = dict(probe or {})
        self.background = bool(background)
        self.skip_if = skip_if
        self.on_failure = on_failure      # abort / continue
        self.sleep = float(sleep)
        self.target = target              # kill 步骤指向某个 exec 步骤的 id
        self.message = message
        self.interval = float(interval)
        # blocking=False：这一步是**诊断/信息性**的，失败不让整个剧本算失败。
        # 典型例子：CPU 被打满时服务其实还活着，此时"确认服务已不可用"这一步本来就不该成立，
        # 但它失败并不代表处置没成功 —— 处置成功与否由后面的验证步骤说了算。
        self.blocking = bool(blocking)
        self.extra = extra

    def __repr__(self) -> str:
        return "<Step %s %s>" % (self.id, self.type)


class Playbook(object):
    def __init__(self, name: str, steps: Sequence[Step], rollback: Sequence[Step] = (),
                 timeout: float = 120.0, on_failure: str = "abort", description: str = ""):
        self.name = name
        self.steps = list(steps)
        self.rollback = list(rollback)
        self.timeout = float(timeout)
        self.on_failure = on_failure      # abort / rollback / continue
        self.description = description

    @classmethod
    def from_dict(cls, data: Dict) -> "Playbook":
        def mk(items):
            out = []
            for item in items or []:
                item = dict(item)
                out.append(Step(**item))
            return out
        return cls(name=data["name"], steps=mk(data.get("steps")),
                   rollback=mk(data.get("rollback")), timeout=data.get("timeout", 120.0),
                   on_failure=data.get("on_failure", "abort"),
                   description=data.get("description", ""))


class StepResult(object):
    def __init__(self, step_id, type, status, started, duration, detail=""):
        self.id = step_id
        self.type = type
        self.status = status
        self.started = started
        self.duration = duration
        self.detail = detail

    def as_dict(self) -> Dict:
        return {"id": self.id, "type": self.type, "status": self.status,
                "started": round(self.started, 4), "duration_ms": round(self.duration * 1000, 1),
                "detail": self.detail}


class Report(object):
    def __init__(self, playbook: str):
        self.playbook = playbook
        self.steps: List[StepResult] = []
        self.ok = True
        self.rolled_back = False
        self.dry_run = False
        self.started = 0.0
        self.duration = 0.0
        self.notes: List[str] = []

    def failed_steps(self) -> List[str]:
        return [s.id for s in self.steps if s.status in (FAILED, TIMEOUT)]

    def as_dict(self) -> Dict:
        return {"playbook": self.playbook, "ok": self.ok, "dry_run": self.dry_run,
                "rolled_back": self.rolled_back, "duration_ms": round(self.duration * 1000, 1),
                "failed_steps": self.failed_steps(),
                "steps": [s.as_dict() for s in self.steps], "notes": self.notes}


class Executor(object):
    """执行剧本。时钟/睡眠可注入 → 演练里能把"处置耗时"算准，测试里也不用真等。"""

    def __init__(self, clock: Callable = time.time, sleep: Callable = time.sleep,
                 log=None, background_registry: Optional[Dict[str, procs.ManagedProcess]] = None):
        self.clock = clock
        self.sleep = sleep
        self.log = log
        self.background: Dict[str, procs.ManagedProcess] = (
            background_registry if background_registry is not None else {})

    def _note(self, message: str) -> None:
        if self.log:
            self.log(message)

    def run(self, playbook: Playbook, dry_run: bool = False) -> Report:
        report = Report(playbook.name)
        report.dry_run = dry_run
        report.started = self.clock()
        started = self.clock()
        aborted = False

        for step in playbook.steps:
            if aborted:
                report.steps.append(StepResult(step.id, step.type, SKIPPED, started, 0.0, "前序步骤失败"))
                continue
            if self.clock() - started > playbook.timeout:
                report.ok = False
                report.steps.append(StepResult(step.id, step.type, TIMEOUT, started, 0.0, "剧本总超时"))
                aborted = True
                continue
            result = self._run_step(step, dry_run)
            report.steps.append(result)
            if result.status in (FAILED, TIMEOUT):
                # 非阻塞步骤（诊断类）失败只记录，不判定整个剧本失败
                if step.blocking:
                    report.ok = False
                    if step.on_failure == "abort" and playbook.on_failure != "continue":
                        aborted = True

        if not report.ok and playbook.rollback:
            report.rolled_back = True
            self._note("剧本 %s 失败，开始回滚" % playbook.name)
            for step in playbook.rollback:
                report.steps.append(self._run_step(step, dry_run))

        report.duration = self.clock() - started
        return report

    # ------------------------------------------------------------------ 单步
    def _run_step(self, step: Step, dry_run: bool) -> StepResult:
        started = self.clock()

        # 幂等：skip_if 命中说明这一步已经做过了
        if step.skip_if:
            probe = build_probe(step.skip_if)
            if probe.check(started).ok:
                return StepResult(step.id, step.type, SKIPPED, started,
                                  self.clock() - started, "skip_if 已满足，跳过")

        if dry_run and step.type not in READ_ONLY_TYPES:
            return StepResult(step.id, step.type, SKIPPED, started,
                              self.clock() - started, "dry-run：跳过写操作")

        deadline = started + step.timeout
        try:
            if step.type == "note":
                self._note(step.message)
                return StepResult(step.id, step.type, OK, started, self.clock() - started, step.message)
            if step.type == "sleep":
                self.sleep(step.sleep)
                return StepResult(step.id, step.type, OK, started, self.clock() - started,
                                  "等待 %.2fs" % step.sleep)
            if step.type == "probe":
                probe = build_probe(step.spec)
                result = probe.check(started)
                status = OK if result.ok == step.expect else FAILED
                return StepResult(step.id, step.type, status, started, self.clock() - started,
                                  "%s（期望 %s，实际 %s）" % (result.detail, step.expect, result.ok))
            if step.type == "wait_probe":
                return self._wait_probe(step, started, deadline)
            if step.type == "exec":
                return self._exec(step, started, deadline)
            if step.type == "kill":
                return self._kill(step, started)
            if step.type == "http_post":
                return self._http_post(step, started)
            return StepResult(step.id, step.type, FAILED, started, self.clock() - started,
                              "未知步骤类型 %r" % step.type)
        except Exception as exc:
            return StepResult(step.id, step.type, FAILED, started, self.clock() - started,
                              "%s: %s" % (type(exc).__name__, exc))

    def _wait_probe(self, step: Step, started: float, deadline: float) -> StepResult:
        probe = build_probe(step.spec)
        last = ""
        while self.clock() < deadline:
            result = probe.check(self.clock())
            last = result.detail
            if result.ok == step.expect:
                return StepResult(step.id, step.type, OK, started, self.clock() - started, last)
            self.sleep(step.interval)
        return StepResult(step.id, step.type, TIMEOUT, started, self.clock() - started,
                          "等待超时：%s" % last)

    def _exec(self, step: Step, started: float, deadline: float) -> StepResult:
        if step.background:
            managed = procs.ManagedProcess(
                step.id, step.argv, port=step.extra.get("port"),
                env=step.extra.get("env"))
            managed.start(wait=bool(step.extra.get("wait_port", False)),
                          timeout=max(0.1, deadline - self.clock()), clock=self.clock)
            self.background[step.id] = managed
            return StepResult(step.id, step.type, OK, started, self.clock() - started,
                              "后台启动 pid=%s" % managed.pid)
        import subprocess
        timeout = max(0.1, step.timeout)
        try:
            done = subprocess.run(step.argv, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, timeout=timeout)
        except subprocess.TimeoutExpired:
            return StepResult(step.id, step.type, TIMEOUT, started, self.clock() - started,
                              "命令超时 %.1fs" % timeout)
        out = (done.stdout or b"").decode("utf-8", "replace").strip().replace("\n", " ")[:120]
        status = OK if done.returncode == 0 else FAILED
        return StepResult(step.id, step.type, status, started, self.clock() - started,
                          "rc=%d %s" % (done.returncode, out))

    def _kill(self, step: Step, started: float) -> StepResult:
        target = self.background.get(step.target or "")
        if target is None:
            return StepResult(step.id, step.type, FAILED, started, self.clock() - started,
                              "找不到目标步骤 %r" % step.target)
        info = target.stop(graceful=not step.extra.get("force", False),
                           drain_timeout=step.timeout, clock=self.clock)
        return StepResult(step.id, step.type, OK, started, self.clock() - started,
                          str(info.get("stop_reason", "")))

    def _http_post(self, step: Step, started: float) -> StepResult:
        host = step.extra.get("host", "127.0.0.1")
        port = int(step.extra["port"])
        status, body = procs.http_post(host, port, step.extra.get("path", "/shutdown"),
                                       timeout=step.timeout)
        ok = status == int(step.extra.get("expect_status", 200))
        return StepResult(step.id, step.type, OK if ok else FAILED, started,
                          self.clock() - started, "HTTP %d %s" % (status, body[:60]))

    def cleanup(self) -> List[str]:
        """收尾：把还在跑的后台进程都收干净（演练必须不留残留进程）"""
        stopped = []
        for name, managed in list(self.background.items()):
            if managed.alive():
                managed.stop(graceful=True, drain_timeout=3.0, clock=self.clock)
                stopped.append(name)
        self.background.clear()
        return stopped
