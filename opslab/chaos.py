# -*- coding: utf-8 -*-
"""故障演练（chaos drill）：把故障注入进去，量出"多久发现、多久恢复"。

═══ 为什么必须做演练，而不是"写了预案就算有预案" ═══
预案不演练，就等于没有 —— 因为你不知道：
  - 探针配置能不能真的发现问题（`failures × interval` 到底是多少秒）
  - 告警会不会被去重/抑制吃掉（该响的时候没响，比乱响更危险）
  - 重启真的能把服务拉回来吗（有状态服务经常拉不回来）
  - 端到端 MTTR 到底是 5 秒还是 5 分钟
所以这里每个场景都产出**可对账的数字**：detect_ms（发现）、recover_ms（恢复）、mttr_ms（端到端）。

═══ 五种故障 + 两条检测路径 ═══
  service_killed   进程被杀死          → 探针 DOWN（连不上）
  service_hung     服务挂死（不回包）   → 探针 DOWN（超时）★ 只有带超时的探针才测得出来
  network_latency  网络延迟 800ms      → 探针 DOWN（响应超过探针超时）
  http_errors      接口持续 5xx        → 探针 DOWN（状态码不符）
  cpu_saturation   CPU 被占满          → **服务还活着**，只能靠指标规则发现（进程 CPU > 60%）
后一条特别重要：**不是所有故障都表现为"服务不可用"**。只做探针的监控会漏掉它。
"""

import json
import os
import socket
import threading
import time
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from . import procs
from .alerting import AlertManager
from .health import HealthChecker, HttpProbe
from .notify import RecordingNotifier
from .playbook import Executor, Playbook, Step, StepResult, OK as PB_OK, FAILED as PB_FAILED
from .procfs import ProcessCpuSampler
from .rules import Rule, RuleEngine
from .tsdb import Store


# --------------------------------------------------------------------------- 故障注入器

class Injector(object):
    kind = "injector"

    def __init__(self, name: str, target_port: int, listen_port: Optional[int] = None):
        self.name = name
        self.target_port = int(target_port)
        self.listen_port = int(listen_port or (target_port + 1))
        self.active = False

    def start(self) -> None:
        self.active = True

    def stop(self) -> None:
        self.active = False


class ProxyInjector(Injector):
    """TCP 代理式故障注入：在探针和服务之间插一层，按需注入延迟 / 错误 / 挂死。

    为什么用代理而不是改服务代码：**故障注入器不应该和被测服务耦合**。
    代理能注入的故障对服务是"外部世界变了"，这才贴近真实的网络问题。
    """

    kind = "proxy"

    def __init__(self, name, target_port, listen_port=None, latency_ms=0.0,
                 error_rate=0.0, hang=False, clock=None):
        Injector.__init__(self, name, target_port, listen_port)
        self.latency_ms = float(latency_ms)
        self.error_rate = float(error_rate)
        self.hang = bool(hang)
        self.clock = clock or time.time
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.connections = 0
        self.injected_errors = 0

    def start(self) -> None:
        if self.active:
            # 幂等保护：SO_REUSEADDR 在 **Linux 上不允许**两个 socket 绑同一个 addr:port
            # （那是 SO_REUSEPORT 的语义），第二次 bind 会抛 OSError；但在 Windows 上
            # SO_REUSEADDR 允许重复绑定、还会把端口"抢"过去 —— 于是同一个 bug
            # 在 Windows 上"看起来能用"、在 Linux CI 上直接挂。所以这里显式报错。
            raise RuntimeError("代理 %s 已在监听 %d，不要重复启动" % (self.name, self.listen_port))
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", self.listen_port))
        self._sock.listen(64)
        self._sock.settimeout(0.1)
        self._stop.clear()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        self.active = True
        self.started_at = self.clock()

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                client, _ = self._sock.accept()          # type: ignore[union-attr]
            except socket.timeout:
                continue
            except OSError:
                break
            self.connections += 1
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    def _handle(self, client: socket.socket):
        try:
            if self.hang:
                # 挂死：连接建起来了，但一个字节都不回 —— 客户端只能靠超时发现
                self._stop.wait(30.0)
                return
            if self.latency_ms > 0:
                time.sleep(self.latency_ms / 1000.0)
            if self.error_rate > 0.0:
                # 用连接序号的确定性哈希决定是否注错（不用随机数：演练要可复现）
                if (self.connections % max(1, int(round(1.0 / self.error_rate)))) == 0:
                    self.injected_errors += 1
                    client.sendall(b"HTTP/1.1 503 Service Unavailable\r\n"
                                   b"Content-Length: 0\r\nConnection: close\r\n\r\n")
                    return
            upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            upstream.settimeout(5.0)
            upstream.connect(("127.0.0.1", self.target_port))
            self._pump(client, upstream)
        except (OSError, socket.timeout):
            pass
        finally:
            try:
                client.close()
            except OSError:
                pass

    @staticmethod
    def _pump(client: socket.socket, upstream: socket.socket):
        done = threading.Event()

        def forward(src, dst):
            try:
                while not done.is_set():
                    chunk = src.recv(65536)
                    if not chunk:
                        break
                    dst.sendall(chunk)
            except (OSError, socket.timeout):
                pass
            finally:
                done.set()

        t = threading.Thread(target=forward, args=(client, upstream), daemon=True)
        t.start()
        forward(upstream, client)
        t.join(timeout=2.0)
        try:
            upstream.close()
        except OSError:
            pass

    def stop(self) -> None:
        self._stop.set()
        self.active = False
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        self._sock = None
        self._thread = None


class ProxyFault(Injector):
    """**在运行中的代理上就地改故障参数** —— 注入故障不该重启基础设施。

    `ProxyInjector` 是在每条新连接建立时才读 `latency_ms / error_rate / hang`，
    所以直接改这三个属性就立即对新连接生效，**不需要重启代理**。

    ⚠️ 第一版这里图省事，直接又调了一次 `proxy.start()`，结果在 Windows 上能跑
    （SO_REUSEADDR 允许重复绑定），在 Linux 上一次都跑不起来（bind 直接 OSError）。
    这种"只有某个平台才复现"的 bug 正是跨平台 CI 的价值所在。
    """

    kind = "proxy"

    def __init__(self, name: str, proxy: ProxyInjector, latency_ms: float = 0.0,
                 error_rate: float = 0.0, hang: bool = False):
        Injector.__init__(self, name, proxy.target_port, proxy.listen_port)
        self.proxy = proxy
        self.latency_ms = float(latency_ms)
        self.error_rate = float(error_rate)
        self.hang = bool(hang)

    def start(self) -> None:
        if not self.proxy.active:
            raise RuntimeError("代理还没起来，无法注入故障")
        self.proxy.latency_ms = self.latency_ms
        self.proxy.error_rate = self.error_rate
        self.proxy.hang = self.hang
        self.active = True

    def stop(self) -> None:
        self.proxy.latency_ms = 0.0
        self.proxy.error_rate = 0.0
        self.proxy.hang = False
        self.active = False


class KillInjector(Injector):
    kind = "kill"

    def __init__(self, name, managed: procs.ManagedProcess):
        Injector.__init__(self, name, managed.port or 0, managed.port or 0)
        self.managed = managed
        self.killed_pid = None

    def start(self) -> None:
        self.killed_pid = self.managed.pid
        self.managed.stop(graceful=False, drain_timeout=0.5)
        self.active = True

    def stop(self) -> None:
        self.active = False


class LoadInjector(Injector):
    """CPU 占满：在演练进程内起 N 个忙线程（跨平台、可观测量 = 本进程 CPU%）。"""

    kind = "load"

    def __init__(self, name, workers=4):
        Injector.__init__(self, name, 0, 0)
        self.workers = int(workers)
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []

    def start(self) -> None:
        self._stop.clear()
        for _ in range(self.workers):
            t = threading.Thread(target=self._burn, daemon=True)
            t.start()
            self._threads.append(t)
        self.active = True

    def _burn(self):
        while not self._stop.is_set():
            x = 0
            for i in range(20000):
                x += i * i
            if x < 0:      # 防止被优化掉
                break

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=1.0)
        self._threads = []
        self.active = False


# --------------------------------------------------------------------------- 场景与演练

class Scenario(object):
    def __init__(self, name, description, expect_down=True, expect_metric_rule=False,
                 detect_bound_ms=4000.0, recover_bound_ms=25000.0):
        self.name = name
        self.description = description
        self.expect_down = expect_down
        self.expect_metric_rule = expect_metric_rule
        self.detect_bound_ms = detect_bound_ms
        self.recover_bound_ms = recover_bound_ms


class DrillResult(object):
    def __init__(self, scenario: Scenario):
        self.scenario = scenario
        self.detected = False
        self.detect_ms: Optional[float] = None
        self.recover_ms: Optional[float] = None
        self.mttr_ms: Optional[float] = None
        self.detected_by = ""
        self.notification = ""
        self.playbook_ok = False
        self.playbook_steps = 0
        self.playbook_failed: List[str] = []
        self.assertions: List[Tuple[str, bool, str]] = []
        self.error = ""

    def check(self, label: str, ok: bool, detail: str = "") -> None:
        self.assertions.append((label, bool(ok), detail))

    @property
    def passed(self) -> bool:
        return bool(self.assertions) and all(a[1] for a in self.assertions) and not self.error

    def as_dict(self) -> Dict:
        return {
            "scenario": self.scenario.name,
            "description": self.scenario.description,
            "passed": self.passed,
            "detected": self.detected,
            "detected_by": self.detected_by,
            "detect_ms": None if self.detect_ms is None else round(self.detect_ms, 1),
            "recover_ms": None if self.recover_ms is None else round(self.recover_ms, 1),
            "mttr_ms": None if self.mttr_ms is None else round(self.mttr_ms, 1),
            "notification": self.notification,
            "playbook": {"ok": self.playbook_ok, "steps": self.playbook_steps,
                         "failed": self.playbook_failed},
            "assertions": [{"label": l, "ok": o, "detail": d} for l, o, d in self.assertions],
            "error": self.error,
        }


class Drill(object):
    """跑一个场景：起服务 → 注入故障 → 等检测 → 跑预案 → 等恢复 → 量 MTTR。"""

    def __init__(self, workdir: str, base_port: int = 18500, interval: float = 0.1,
                 failures_to_down: int = 2, probe_timeout: float = 0.6,
                 clock: Callable = time.time, sleep: Callable = time.sleep, verbose: bool = False):
        self.workdir = workdir
        self.base_port = int(base_port)
        self.interval = float(interval)
        self.failures_to_down = int(failures_to_down)
        self.probe_timeout = float(probe_timeout)
        self.clock = clock
        self.sleep = sleep
        self.verbose = verbose
        if not os.path.isdir(self.workdir):
            os.makedirs(self.workdir)

    def _log(self, message: str) -> None:
        if self.verbose:
            print("[drill] %s" % message, flush=True)

    # -------------------------------------------------------------- 场景实现
    def _make_injector(self, scenario: Scenario, managed: procs.ManagedProcess,
                       proxy: Optional[ProxyInjector]):
        if scenario.name == "service_killed":
            return KillInjector("kill", managed)
        if proxy is None:
            raise RuntimeError("该场景需要代理注入器")
        # 就地改参数，不重启代理（见 ProxyFault 的说明）
        if scenario.name == "service_hung":
            return ProxyFault("hang", proxy, hang=True)
        if scenario.name == "network_latency":
            return ProxyFault("latency", proxy, latency_ms=800.0)
        if scenario.name == "http_errors":
            return ProxyFault("errors", proxy, error_rate=1.0)
        raise RuntimeError("未知场景：%s" % scenario.name)

    def _remediation_steps(self, scenario: Scenario, managed: procs.ManagedProcess,
                           proxy: Optional[ProxyInjector], probe_port: int) -> Playbook:
        """预案：先确认故障，再处置，最后验证恢复（含幂等 skip_if）。"""
        steps = [
            # 诊断步骤：期望值随场景变化 —— 掉线类场景期望"探针已不可用"，
            # CPU 类场景服务其实还活着，期望就是"服务仍然可用"。
            # 它是**信息性**的（blocking=False）：诊断结论与预期不符不判定处置失败，
            # 处置成不成功由最后那个 verify 步骤说了算。
            Step("confirm", "probe", timeout=2.0, expect=not scenario.expect_down,
                 blocking=False,
                 probe={"kind": "http", "name": "confirm_state", "port": probe_port,
                        "path": "/healthz", "timeout": self.probe_timeout},
                 on_failure="continue"),
        ]
        if scenario.name == "cpu_saturation":
            # CPU 场景不重启服务（服务本来是好的），只处置"占用源"
            steps.append(Step("note", "note", message="CPU 饱和：停止压测负载"))
        else:
            if proxy is not None and scenario.name != "service_killed":
                steps.append(Step("fix_proxy", "kill", target="__proxy__",
                                  timeout=3.0, force=True))
                steps.append(Step("restart_proxy", "exec", timeout=10.0, background=True,
                                  skip_if={"kind": "tcp", "port": proxy.listen_port, "timeout": 0.3},
                                  argv=["__restart_proxy__"]))
            steps.append(Step("restart_service", "exec", timeout=15.0, background=True,
                              port=managed.port,
                              skip_if={"kind": "http", "port": managed.port, "path": "/healthz",
                                       "timeout": 0.4},
                              argv=["__restart_service__"], **{"wait_port": True}))
        steps.append(Step("verify", "wait_probe", timeout=20.0, expect=True, interval=0.2,
                          probe={"kind": "http", "name": "verify_up", "port": probe_port,
                                 "path": "/healthz", "timeout": self.probe_timeout}))
        return Playbook("remediate_" + scenario.name, steps, timeout=60.0)

    def run(self, scenario: Scenario) -> DrillResult:
        result = DrillResult(scenario)
        service_port = self.base_port + 1
        proxy_port = self.base_port + 2
        log_path = os.path.join(self.workdir, "svc-%s.log" % scenario.name)

        managed = procs.ManagedProcess(
            "svc", procs.python_module_argv("opslab.demo.service", "--port", str(service_port),
                                            "--version", "v1"),
            port=service_port, log_path=log_path)
        probe_port = proxy_port if scenario.name in ("service_hung", "network_latency",
                                                     "http_errors") else service_port
        proxy: Optional[ProxyInjector] = None
        if probe_port == proxy_port:
            proxy = ProxyInjector("proxy", service_port, proxy_port)

        checker = HealthChecker([HttpProbe("svc", "127.0.0.1", probe_port, "/healthz",
                                           timeout=self.probe_timeout)],
                                interval=self.interval,
                                failures_to_down=self.failures_to_down,
                                successes_to_up=2)
        notifier = RecordingNotifier()
        manager = AlertManager(notifier=notifier)
        rules = [Rule("ServiceDown", probe="svc", op="==", threshold=0.0, for_seconds=0.0,
                      severity="critical", annotations={"summary": "服务不可用"})]
        engine = RuleEngine(rules)
        store = Store(capacity=2048)
        cpu_sampler = ProcessCpuSampler(clock=self.clock)
        load = LoadInjector("load", workers=4) if scenario.name == "cpu_saturation" else None
        if load is not None:
            rules.append(Rule("ProcessCpuHigh", metric="proc.cpu_percent", op=">",
                              threshold=60.0, for_seconds=0.0, agg="last",
                              severity="warning",
                              annotations={"summary": "本进程 CPU 持续高于 60%"}))
            engine = RuleEngine(rules)

        stop_monitor = threading.Event()
        monitor_state: Dict[str, object] = {"ticks": 0, "down_at": None, "firing_at": None,
                                            "firing_rule": "", "notified": 0}

        def monitor():
            while not stop_monitor.is_set():
                now = self.clock()
                checker.check_once(now)
                metrics = checker.metrics(now)
                if load is not None:
                    metrics["proc.cpu_percent"] = cpu_sampler.sample()
                store.append_many(now, metrics)
                scalars = {}
                scalars.update(checker.up_flags())
                for rule in engine.rules:
                    if rule.metric == "proc.cpu_percent":
                        last = store.latest("proc.cpu_percent")
                        if last is not None:
                            scalars[rule.scalar_key] = last
                events = engine.observe(now, scalars)
                notes = manager.handle(events, now)
                if notes:
                    manager.send_all(notes)
                if monitor_state["down_at"] is None and checker.state_of("svc") == "DOWN":
                    monitor_state["down_at"] = now
                if monitor_state["firing_at"] is None:
                    for name in engine.active():
                        monitor_state["firing_at"] = now
                        monitor_state["firing_rule"] = name
                monitor_state["ticks"] = int(monitor_state["ticks"]) + 1
                self.sleep(self.interval)

        executor = _HookExecutor(clock=self.clock, sleep=self.sleep, log=self._log)

        # 让预案能重启服务/代理：把"重启动作"注册成执行器认得的回调
        def restart_service():
            managed.stop(graceful=False, drain_timeout=1.0, clock=self.clock)
            managed.start(wait=True, timeout=10.0, clock=self.clock)
            return "restarted pid=%s" % managed.pid

        monkey = executor
        monkey.set_callbacks(restart_service, proxy, managed)

        try:
            managed.start(wait=True, timeout=10.0, clock=self.clock)
            if proxy is not None:
                proxy.start()
                _ = procs.wait_port("127.0.0.1", proxy_port, timeout=5.0, clock=self.clock)
            # 先跑到健康（连续 successes_to_up 次成功），保证基线是 UP
            deadline = self.clock() + 10.0
            while self.clock() < deadline and checker.state_of("svc") != "UP":
                checker.check_once(self.clock())
                self.sleep(0.05)
            result.check("基线健康（UP）", checker.state_of("svc") == "UP",
                         "state=%s" % checker.state_of("svc"))

            thread = threading.Thread(target=monitor, daemon=True)
            thread.start()
            self.sleep(max(0.25, self.interval * 3))

            # ---- 注入故障
            if load is not None:
                injector = load
            else:
                injector = self._make_injector(scenario, managed, proxy)
            t0 = self.clock()
            injector.start()
            result.detected_by = injector.kind
            self._log("t0 注入故障：%s" % scenario.name)

            # ---- 等检测
            deadline = self.clock() + 15.0
            while self.clock() < deadline:
                if scenario.expect_metric_rule:
                    if monitor_state["firing_rule"] == "ProcessCpuHigh":
                        break
                elif monitor_state["down_at"] is not None and monitor_state["firing_at"] is not None:
                    break
                self.sleep(0.05)
            detected_at = self.clock()
            if monitor_state["firing_at"] is not None:
                result.detected = True
                result.detect_ms = (detected_at - t0) * 1000.0
                result.detected_by = str(monitor_state["firing_rule"])

            result.check("故障被检测到", result.detected,
                         "detected_by=%s" % result.detected_by)
            result.check("检测在 %d ms 内" % scenario.detect_bound_ms,
                         result.detect_ms is not None and result.detect_ms <= scenario.detect_bound_ms,
                         "detect_ms=%s" % result.detect_ms)
            for note in notifier.received:
                result.notification = note.text()
                break

            # ---- 执行预案
            book = self._remediation_steps(scenario, managed, proxy, probe_port)
            monkey.set_callbacks(restart_service, proxy, managed)
            report = monkey.run(book, dry_run=False)
            result.playbook_ok = report.ok
            result.playbook_steps = len(report.steps)
            result.playbook_failed = report.failed_steps()
            ready_at = self.clock()
            result.check("预案执行成功", report.ok, "failed=%s" % report.failed_steps())

            if load is not None:
                load.stop()

            # ---- 等恢复（探针回到 UP + 告警 RESOLVED）
            deadline = self.clock() + 30.0
            while self.clock() < deadline and checker.state_of("svc") != "UP":
                self.sleep(0.05)
            recovered_at = self.clock()
            result.recover_ms = (recovered_at - detected_at) * 1000.0
            result.mttr_ms = (recovered_at - t0) * 1000.0
            result.check("服务已恢复（探针 UP）", checker.state_of("svc") == "UP",
                         "state=%s" % checker.state_of("svc"))
            result.check("恢复在 %d ms 内" % scenario.recover_bound_ms,
                         result.mttr_ms <= scenario.recover_bound_ms,
                         "mttr_ms=%.1f（含预案执行 %.1f）" % (
                             result.mttr_ms, (ready_at - detected_at) * 1000.0))
            result.check("MTTR 已量化", result.mttr_ms is not None and result.mttr_ms > 0)
        except Exception as exc:
            result.error = "%s: %s" % (type(exc).__name__, exc)
        finally:
            stop_monitor.set()
            if load is not None:
                load.stop()
            if proxy is not None:
                proxy.stop()
            try:
                managed.stop(graceful=True, drain_timeout=3.0, clock=self.clock)
            except Exception:
                pass
            monkey.cleanup()
        return result


class _HookExecutor(Executor):
    """给 Executor 装上"真正的动作"：argv 是占位符时改调回调。

    为什么不直接在剧本里写命令行：重启"本进程管理的那个 ManagedProcess"和
    重启"命令行里的某个进程"不是一回事，前者要复用同一个端口和日志。
    所以剧本写意图（restart_service），执行器把意图映射到具体动作。
    """

    def __init__(self, clock=None, sleep=None, log=None):
        Executor.__init__(self, clock=clock or time.time,
                          sleep=sleep or time.sleep, log=log)
        self.restart_service_cb: Optional[Callable[[], str]] = None
        self.proxy: Optional[ProxyInjector] = None
        self.managed: Optional[procs.ManagedProcess] = None

    def set_callbacks(self, restart_service, proxy, managed) -> None:
        self.restart_service_cb = restart_service
        self.proxy = proxy
        self.managed = managed

    def _exec(self, step, started, deadline):
        argv = step.argv
        if argv and argv[0] == "__restart_service__":
            try:
                detail = self.restart_service_cb() if self.restart_service_cb else "no callback"
                return StepResult(step.id, step.type, PB_OK, started,
                                  self.clock() - started, detail)
            except Exception as exc:
                return StepResult(step.id, step.type, PB_FAILED, started, self.clock() - started,
                                  "%s: %s" % (type(exc).__name__, exc))
        if argv and argv[0] == "__restart_proxy__" and self.proxy is not None:
            try:
                self.proxy.stop()
                self.proxy.hang = False
                self.proxy.latency_ms = 0.0
                self.proxy.error_rate = 0.0
                self.proxy.start()
                ok = procs.wait_port("127.0.0.1", self.proxy.listen_port, timeout=5.0,
                                     clock=self.clock)
                return StepResult(step.id, step.type, PB_OK if ok else PB_FAILED, started,
                                  self.clock() - started,
                                  "代理已重建 port=%d" % self.proxy.listen_port)
            except Exception as exc:
                return StepResult(step.id, step.type, PB_FAILED, started, self.clock() - started,
                                  "%s: %s" % (type(exc).__name__, exc))
        return Executor._exec(self, step, started, deadline)

    def _kill(self, step, started):
        if step.target == "__proxy__" and self.proxy is not None:
            self.proxy.stop()
            return StepResult(step.id, step.type, PB_OK, started, self.clock() - started,
                              "代理已停止")
        return Executor._kill(self, step, started)


SCENARIOS = [
    Scenario("service_killed", "进程被杀死（端口不再监听）", detect_bound_ms=4000.0),
    Scenario("service_hung", "服务挂死：连接能建但永不回包（只能靠探针超时发现）",
             detect_bound_ms=6000.0),
    Scenario("network_latency", "网络延迟 800ms（超过探针超时）", detect_bound_ms=6000.0),
    Scenario("http_errors", "接口持续返回 503", detect_bound_ms=4000.0),
    Scenario("cpu_saturation", "CPU 被占满：**服务仍可用**，只能靠指标规则发现",
             expect_down=False, expect_metric_rule=True, detect_bound_ms=6000.0),
]


def run_all(workdir: str, base_port: int = 18500, verbose: bool = False,
            only: Optional[Sequence[str]] = None) -> Dict:
    """跑全部场景并汇总（MTTR 取所有场景的最大值与平均）"""
    picked = [s for s in SCENARIOS if not only or s.name in only]
    results = []
    for idx, scenario in enumerate(picked):
        drill = Drill(workdir, base_port=base_port + idx * 10, verbose=verbose)
        results.append(drill.run(scenario))
        if verbose:
            print("[drill] %s -> %s" % (scenario.name,
                                        "PASS" if results[-1].passed else "FAIL"), flush=True)
    mttrs = [r.mttr_ms for r in results if r.mttr_ms]
    detects = [r.detect_ms for r in results if r.detect_ms]
    return {
        "scenarios": [r.as_dict() for r in results],
        "total": len(results),
        "passed": sum(1 for r in results if r.passed),
        "detect_ms_avg": round(sum(detects) / len(detects), 1) if detects else None,
        "detect_ms_max": round(max(detects), 1) if detects else None,
        "mttr_ms_avg": round(sum(mttrs) / len(mttrs), 1) if mttrs else None,
        "mttr_ms_max": round(max(mttrs), 1) if mttrs else None,
    }
