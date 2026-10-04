# -*- coding: utf-8 -*-
"""发布编排：滚动重启 + 优雅停机 + 健康门禁 + 失败自动回滚。

═══ "零停机发布"到底靠什么 ═══
不是靠"重启得快"，而是靠三件事同时成立：
  1. **滚动**：一次只动一个实例，其余实例继续扛流量（所以至少要 2 个实例）
  2. **优雅停机**：实例退出前先从 LB 摘除、并等在途请求跑完（见 demo/service.py 的 drain）
  3. **健康门禁**：新实例必须真的通过健康检查才算发布成功，否则**立刻回滚**
     —— 而不是"进程起来了就算成功"（这是最常见的自欺：进程活着，接口 500）

本模块把这三件事都做成可量化的：
  - `availability`：发布全程用路由层真实发请求，成功率必须 100%
  - `gate`：新版本健康门禁的结论（passed / failed:reason）
  - `rollback`：坏版本被拦下后，回滚耗时与回滚后可用性

═══ 为什么要专门准备一个"坏版本" ═══
只演练成功路径的发布流程等于没有发布流程。**必须演练"新版本是坏的"这条路径**，
否则第一次遇到就是生产事故：门禁拦不拦得住、回滚要多久，都只能靠猜。
"""

import json
import os
import threading
import time
from typing import Callable, Dict, List, Optional, Sequence

from . import procs
from .health import HttpProbe


class Instance(object):
    def __init__(self, name: str, port: int, version: str = "v1", workdir: str = ".",
                 unhealthy: bool = False):
        self.name = name
        self.port = int(port)
        self.version = version
        self.workdir = workdir
        self.unhealthy = unhealthy
        self.managed: Optional[procs.ManagedProcess] = None

    def argv(self) -> List[str]:
        argv = procs.python_module_argv("opslab.demo.service", "--port", str(self.port),
                                        "--version", self.version)
        if self.unhealthy:
            argv.append("--unhealthy")
        return argv

    def start(self, timeout: float = 10.0, clock=None) -> int:
        if self.managed is not None and self.managed.alive():
            return self.managed.pid or 0
        log = os.path.join(self.workdir, "instance-%s.log" % self.name)
        self.managed = procs.ManagedProcess(self.name, self.argv(), port=self.port, log_path=log)
        return self.managed.start(wait=True, timeout=timeout, clock=clock)

    def stop(self, graceful: bool = True, drain_timeout: float = 5.0, clock=None) -> Dict:
        if self.managed is None:
            return {"stop_reason": "未启动"}
        return self.managed.stop(graceful=graceful, drain_timeout=drain_timeout, clock=clock)

    def alive(self) -> bool:
        return self.managed is not None and self.managed.alive()


class Router(object):
    """极简负载均衡：只在**健康**实例之间轮询。

    用它来量"发布期间用户是否受影响"，比"各实例自己探活"诚实得多 ——
    单个实例下线不等于服务不可用，只有**全部**实例都不可用时服务才真的挂了。

    ⚠️ 计数口径（第一版在这里搞错过）：`requests` 必须是**用户请求数**，
    不能把"在某台实例上的一次尝试"也算一次请求。否则发布时明明每次请求都
    被重试到健康实例上成功了（用户毫无感知），算出来的可用性却只有 70% ——
    数字看着很吓人，其实是把"重试"当成了"失败"。
    所以实例级的额外尝试单独记在 `retries` 里。
    """

    def __init__(self, instances: Sequence[Instance], timeout: float = 0.5):
        self.instances = list(instances)
        self.timeout = float(timeout)
        self._idx = 0
        self.requests = 0        # 用户请求数
        self.success = 0         # 用户视角的成功数
        self.failed = 0          # 用户视角的失败数（所有候选实例都不可用）
        self.retries = 0         # 实例级重试次数（对用户透明）
        self.failures_by_instance: Dict[str, int] = {}

    def _healthy(self) -> List[Instance]:
        return [i for i in self.instances if i.alive()]

    def request(self, path: str = "/healthz") -> Dict:
        self.requests += 1
        candidates = self._healthy()
        if not candidates:
            self.failed += 1
            self.failures_by_instance["<none>"] = self.failures_by_instance.get("<none>", 0) + 1
            return {"ok": False, "instance": None, "status": 0, "attempts": 0}
        attempts = 0
        for offset in range(len(candidates)):
            inst = candidates[(self._idx + offset) % len(candidates)]
            attempts += 1
            status, _ = procs.http_get("127.0.0.1", inst.port, path, timeout=self.timeout)
            if status == 200:
                self.success += 1
                self.retries += attempts - 1
                self._idx = (self._idx + offset + 1) % len(candidates)
                return {"ok": True, "instance": inst.name, "status": status,
                        "attempts": attempts}
            self.failures_by_instance[inst.name] = \
                self.failures_by_instance.get(inst.name, 0) + 1
        self.failed += 1
        self.retries += attempts - 1
        return {"ok": False, "instance": None, "status": 0, "attempts": attempts}

    @property
    def availability(self) -> float:
        if self.requests == 0:
            return 1.0
        return self.success / float(self.requests)


class DeployReport(object):
    def __init__(self, name: str):
        self.name = name
        self.ok = True
        self.gate_passed = True
        self.gate_reason = ""
        self.rolled_back = False
        self.rollback_ms: Optional[float] = None
        self.duration_ms = 0.0
        self.steps: List[Dict] = []
        self.availability = 1.0
        self.requests = 0
        self.failed_requests = 0
        self.retries = 0
        self.failures_by_instance: Dict[str, int] = {}
        self.drain_details: List[Dict] = []

    def as_dict(self) -> Dict:
        return {
            "deployment": self.name, "ok": self.ok,
            "gate": {"passed": self.gate_passed, "reason": self.gate_reason},
            "rolled_back": self.rolled_back,
            "rollback_ms": None if self.rollback_ms is None else round(self.rollback_ms, 1),
            "duration_ms": round(self.duration_ms, 1),
            "availability": round(self.availability, 4),
            "requests": self.requests,
            "failed_requests": self.failed_requests,
            "retries": self.retries,
            "failures_by_instance": self.failures_by_instance,
            "steps": self.steps,
            "drain": self.drain_details,
        }


class RollingDeployer(object):
    def __init__(self, instances: Sequence[Instance], workdir: str,
                 gate_timeout: float = 8.0, gate_required: int = 2,
                 drain_timeout: float = 5.0, probe_interval: float = 0.05,
                 clock: Callable = time.time, sleep: Callable = time.sleep, verbose: bool = False):
        self.instances = list(instances)
        self.workdir = workdir
        self.gate_timeout = float(gate_timeout)
        self.gate_required = int(gate_required)
        self.drain_timeout = float(drain_timeout)
        self.probe_interval = float(probe_interval)
        self.clock = clock
        self.sleep = sleep
        self.verbose = verbose
        self.router = Router(self.instances)

    def _log(self, msg):
        if self.verbose:
            print("[deploy] %s" % msg, flush=True)

    def _gate(self, instance: Instance) -> Dict:
        """健康门禁：**连续 gate_required 次 200** 才算通过（一次成功可能是巧合）"""
        probe = HttpProbe("gate", "127.0.0.1", instance.port, "/healthz", timeout=0.8)
        deadline = self.clock() + self.gate_timeout
        ok_count = 0
        last = ""
        while self.clock() < deadline:
            result = probe.check(self.clock())
            last = result.detail
            if result.ok:
                ok_count += 1
                if ok_count >= self.gate_required:
                    return {"passed": True, "reason": "连续 %d 次健康检查通过" % ok_count,
                            "detail": last}
            else:
                ok_count = 0
            self.sleep(0.05)
        return {"passed": False, "reason": "健康门禁超时：%s" % last, "detail": last}

    def deploy(self, param_builder: Callable[[Instance, str], None], new_version: str) -> DeployReport:
        """`param_builder(instance, version)` 由调用方决定怎么切换版本（例如 unhealthy 标志）"""
        report = DeployReport("rolling")
        started = self.clock()
        stop_probe = threading.Event()
        traffic: List[Dict] = []

        def generate_traffic():
            """发布全程持续打流量 —— 这就是"可用性"的度量方式"""
            while not stop_probe.is_set():
                traffic.append(self.router.request("/healthz"))
                self.sleep(self.probe_interval)

        thread = threading.Thread(target=generate_traffic, daemon=True)
        thread.start()
        updated: List[Instance] = []
        try:
            for instance in self.instances:
                old_version = instance.version
                step = {"instance": instance.name, "from": old_version, "to": new_version}
                # ① 优雅停机（drain → 等在途请求 → 退出）
                if instance.alive():
                    stop_info = instance.stop(graceful=True, drain_timeout=self.drain_timeout,
                                              clock=self.clock)
                    report.drain_details.append(stop_info)
                    step["drain_ms"] = stop_info.get("drain_ms")
                    step["stop_reason"] = stop_info.get("stop_reason")
                # ② 起新版本
                param_builder(instance, new_version)
                instance.version = new_version
                instance.start(timeout=self.gate_timeout, clock=self.clock)
                step["pid"] = instance.managed.pid if instance.managed else None
                # ③ 健康门禁
                gate = self._gate(instance)
                step["gate"] = gate
                report.steps.append(step)
                self._log("%s -> %s gate=%s" % (instance.name, new_version, gate["passed"]))
                if not gate["passed"]:
                    report.ok = False
                    report.gate_passed = False
                    report.gate_reason = "%s: %s" % (instance.name, gate["reason"])
                    break
                updated.append(instance)
            # ④ 门禁失败 → 回滚（把已经更新过的实例退回旧版本）
            if not report.ok:
                rollback_started = self.clock()
                report.rolled_back = True
                for instance in list(updated) + [i for i in self.instances
                                                 if i.version == new_version]:
                    instance.stop(graceful=False, drain_timeout=2.0, clock=self.clock)
                    param_builder(instance, "v1")
                    instance.version = "v1"
                    instance.start(timeout=self.gate_timeout, clock=self.clock)
                    gate = self._gate(instance)
                    report.steps.append({"instance": instance.name, "rollback": True,
                                         "gate": gate})
                report.rollback_ms = (self.clock() - rollback_started) * 1000.0
        finally:
            stop_probe.set()
            thread.join(timeout=3.0)
            # 收尾：别让发布脚本退出了服务还在跑（这里**保留**实例运行，由调用方清理）
        report.duration_ms = (self.clock() - started) * 1000.0
        report.availability = self.router.availability
        report.requests = self.router.requests
        report.failed_requests = self.router.failed
        report.retries = self.router.retries
        report.failures_by_instance = dict(self.router.failures_by_instance)
        return report

    def cleanup(self) -> List[Dict]:
        out = []
        for instance in self.instances:
            if instance.alive():
                out.append(instance.stop(graceful=True, drain_timeout=3.0, clock=self.clock))
        return out


def deploy_with_versions(workdir: str, base_port: int = 18700, count: int = 3,
                         new_version: str = "v2", bad_version: bool = False,
                         verbose: bool = False) -> Dict:
    """跑一次完整发布（可选：发布一个坏版本，验证门禁拦停 + 自动回滚）。

    注意 `bad_version=True` 时发布的进程是"活着但接口 500"的 ——
    这正是"进程起来了就算发布成功"会漏掉的那种坏版本。
    """
    instances = [Instance("i%d" % (n + 1), base_port + n, "v1", workdir) for n in range(count)]
    for instance in instances:
        instance.start(timeout=10.0)
    deployer = RollingDeployer(instances, workdir, verbose=verbose)

    def builder(instance: Instance, version: str) -> None:
        # 让"坏版本"只作用于新发布的那一次
        instance.unhealthy = bool(bad_version) and version == new_version

    try:
        report = deployer.deploy(builder, new_version)
        data = report.as_dict()
        data["instances"] = [{"name": i.name, "port": i.port, "version": i.version,
                              "alive": i.alive()} for i in instances]
        return data
    finally:
        deployer.cleanup()
