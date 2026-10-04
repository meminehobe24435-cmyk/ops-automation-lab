# -*- coding: utf-8 -*-
"""健康检查：HTTP / TCP / 进程 / 文件新鲜度 / 命令，外加**连续失败判定**。

═══ 为什么"探一次就报警"是错的 ═══
单次探活受网络抖动、GC 停顿、慢查询影响，会制造大量假告警。生产里一律用
"连续 N 次失败才判定 DOWN、连续 M 次成功才判定 UP"（rise/fall，和 keepalived 一个道理）：

    UP ──(连续 failures 次失败)──► DOWN
    DOWN ──(连续 successes 次成功)──► UP

代价是**检测延迟 = failures × interval**，恢复延迟 = successes × interval ——
所以这两个数字必须在演练报告里写出来，而不是只说"能发现故障"。

═══ 另一个必须做对的事：超时是真超时 ═══
探针一旦"连上了但对方不响应"，如果没有 socket 超时，检查线程会永远挂在那里，
整个监控系统就跟着一起假死 —— 这是最经典的"监控把自己监控死了"。
这里所有探针都带硬超时，并且有一条专门的测试去卡"挂死服务的检测时间上界"。
"""

import os
import socket
import subprocess
import sys
import time
from typing import Callable, Dict, List, Optional, Sequence, Tuple

try:  # 仅为构造 HTTP 请求
    import http.client as _http
except ImportError:  # pragma: no cover
    _http = None  # type: ignore

STARTING = "STARTING"
UP = "UP"
DOWN = "DOWN"


class ProbeResult(object):
    __slots__ = ("name", "ok", "ts", "latency_ms", "detail", "kind")

    def __init__(self, name: str, ok: bool, ts: float, latency_ms: float = 0.0,
                 detail: str = "", kind: str = ""):
        self.name = name
        self.ok = bool(ok)
        self.ts = float(ts)
        self.latency_ms = float(latency_ms)
        self.detail = detail
        self.kind = kind

    def as_dict(self) -> Dict:
        return {"name": self.name, "ok": self.ok, "ts": self.ts,
                "latency_ms": round(self.latency_ms, 3), "detail": self.detail,
                "kind": self.kind}

    def __repr__(self) -> str:
        return "<ProbeResult %s %s %.1fms %s>" % (
            self.name, "OK" if self.ok else "FAIL", self.latency_ms, self.detail)


class Probe(object):
    """探针基类：子类只需实现 `run()`，超时/计时/异常归一到失败由基类统一处理。"""

    kind = "probe"

    def __init__(self, name: str, timeout: float = 2.0, clock=None):
        self.name = name
        self.timeout = float(timeout)
        self.clock = clock or time.time

    def run(self, ts: float) -> Tuple[bool, str]:
        raise NotImplementedError

    def check(self, ts: Optional[float] = None) -> ProbeResult:
        started = self.clock()
        when = self.clock() if ts is None else ts
        try:
            ok, detail = self.run(when)
        except Exception as exc:                      # 探针绝不能把上层打挂
            ok, detail = False, "%s: %s" % (type(exc).__name__, exc)
        latency = (self.clock() - started) * 1000.0
        return ProbeResult(self.name, ok, when, latency, detail, self.kind)


class HttpProbe(Probe):
    """HTTP 探活：状态码在期望集合内（且可选响应体包含指定子串）才算健康。"""

    kind = "http"

    def __init__(self, name, host="127.0.0.1", port=80, path="/healthz",
                 expect_status=(200,), expect_body=None, timeout=2.0, clock=None):
        Probe.__init__(self, name, timeout, clock)
        self.host = host
        self.port = int(port)
        self.path = path
        self.expect_status = tuple(expect_status)
        self.expect_body = expect_body

    def run(self, ts):
        if _http is None:  # pragma: no cover
            return False, "http.client 不可用"
        conn = _http.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            conn.request("GET", self.path)
            resp = conn.getresponse()
            body = resp.read(4096).decode("utf-8", "replace")
            status = resp.status
        finally:
            conn.close()
        if status not in self.expect_status:
            return False, "HTTP %d（期望 %s）" % (status, list(self.expect_status))
        if self.expect_body is not None and self.expect_body not in body:
            return False, "响应体缺少 %r" % self.expect_body
        return True, "HTTP %d" % status


class TcpProbe(Probe):
    kind = "tcp"

    def __init__(self, name, host="127.0.0.1", port=80, timeout=2.0, clock=None):
        Probe.__init__(self, name, timeout, clock)
        self.host = host
        self.port = int(port)

    def run(self, ts):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((self.host, self.port))
        finally:
            sock.close()
        return True, "TCP 可连接 %s:%d" % (self.host, self.port)


class ProcessProbe(Probe):
    """进程探活：给 pid 或 pidfile。空/失效 pid 一律判失败（**不要**用"没有 pid 就当健康"）。"""

    kind = "process"

    def __init__(self, name, pid=None, pidfile=None, clock=None):
        Probe.__init__(self, name, 1.0, clock)
        self.pid = pid
        self.pidfile = pidfile

    def _resolve(self):
        if self.pidfile:
            try:
                with open(self.pidfile, "r", encoding="utf-8") as fh:
                    return int(fh.read().strip())
            except (IOError, OSError, ValueError):
                return None
        return self.pid

    def run(self, ts):
        pid = self._resolve()
        if not pid:
            return False, "拿不到 pid"
        if not _pid_alive(pid):
            return False, "进程 %d 不存在" % pid
        return True, "进程 %d 存活" % pid


class FileProbe(Probe):
    """文件新鲜度探活：mtime 在 max_age 秒内才算健康（用来查"任务还在跑吗"）。"""

    kind = "file"

    def __init__(self, name, path, max_age=300.0, min_size=0, clock=None):
        Probe.__init__(self, name, 1.0, clock)
        self.path = path
        self.max_age = float(max_age)
        self.min_size = int(min_size)

    def run(self, ts):
        try:
            st = os.stat(self.path)
        except (IOError, OSError) as exc:
            return False, "stat 失败：%s" % exc
        if st.st_size < self.min_size:
            return False, "文件太小（%d < %d）" % (st.st_size, self.min_size)
        age = ts - st.st_mtime
        if age > self.max_age:
            return False, "%.1fs 没更新（上限 %.1fs）" % (age, self.max_age)
        return True, "%.1fs 前更新" % age


class CommandProbe(Probe):
    """命令探活：退出码为期望值才算健康（能跑 `curl` / `pg_isready` 这类现成检查）。"""

    kind = "command"

    def __init__(self, name, argv, expect_rc=0, timeout=5.0, clock=None):
        Probe.__init__(self, name, timeout, clock)
        self.argv = list(argv)
        self.expect_rc = int(expect_rc)

    def run(self, ts):
        try:
            proc = subprocess.run(self.argv, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, timeout=self.timeout)
        except subprocess.TimeoutExpired:
            return False, "命令超时 %.1fs" % self.timeout
        rc = proc.returncode
        out = (proc.stdout or b"").decode("utf-8", "replace").strip().replace("\n", " ")[:80]
        if rc != self.expect_rc:
            return False, "退出码 %s（期望 %s）%s" % (rc, self.expect_rc, out)
        return True, "rc=0 %s" % out


def _pid_alive(pid: int) -> bool:
    """跨平台判断进程是否存活。

    POSIX 用 `kill(pid, 0)`（不发信号、只做权限/存在性检查），
    Windows 没有信号 0 的语义，用 OpenProcess 的句柄结果。
    """
    pid = int(pid)
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        code = wintypes.DWORD()
        ok = kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        kernel32.CloseHandle(handle)
        return bool(ok) and code.value == 259  # STILL_ACTIVE
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


class HealthChecker(object):
    """对一个探针集合作 rise/fall 判定。时间由外部传入，测试可确定性推进。"""

    def __init__(self, probes: Sequence[Probe], interval: float = 5.0,
                 failures_to_down: int = 3, successes_to_up: int = 2):
        if failures_to_down < 1 or successes_to_up < 1:
            raise ValueError("failures_to_down / successes_to_up 必须 >= 1")
        self.probes = list(probes)
        self.interval = float(interval)
        self.failures_to_down = int(failures_to_down)
        self.successes_to_up = int(successes_to_up)
        self._state: Dict[str, str] = {p.name: STARTING for p in self.probes}
        self._fail_count: Dict[str, int] = {p.name: 0 for p in self.probes}
        self._ok_count: Dict[str, int] = {p.name: 0 for p in self.probes}
        self._since: Dict[str, float] = {p.name: 0.0 for p in self.probes}
        self.results: List[ProbeResult] = []
        self.transitions: List[Dict] = []

    def state_of(self, name: str) -> str:
        return self._state[name]

    def down_names(self) -> List[str]:
        return sorted(n for n, s in self._state.items() if s == DOWN)

    def check_once(self, ts: float) -> List[ProbeResult]:
        out = []
        for probe in self.probes:
            result = probe.check(ts)
            out.append(result)
            self.results.append(result)
            self._apply(result, ts)
        return out

    def _apply(self, result: ProbeResult, ts: float) -> None:
        name = result.name
        before = self._state[name]
        if result.ok:
            self._ok_count[name] += 1
            self._fail_count[name] = 0
            if before in (STARTING, DOWN) and self._ok_count[name] >= self.successes_to_up:
                self._state[name] = UP
        else:
            self._fail_count[name] += 1
            self._ok_count[name] = 0
            if before in (STARTING, UP) and self._fail_count[name] >= self.failures_to_down:
                self._state[name] = DOWN
        after = self._state[name]
        if after != before:
            self._since[name] = ts
            self.transitions.append({"name": name, "from": before, "to": after,
                                     "ts": ts, "detail": result.detail})

    # -- 给告警引擎的数（探针 down = 0） --------------------------------
    def up_flags(self) -> Dict[str, float]:
        return {"probe.%s.up" % n: (1.0 if s != DOWN else 0.0)
                for n, s in self._state.items()}

    def metrics(self, now: float) -> Dict[str, float]:
        out: Dict[str, float] = {}
        for name in self._state:
            out["health." + name + ".up"] = 1.0 if self._state[name] != DOWN else 0.0
            out["health." + name + ".state_seconds"] = now - self._since.get(name, now)
        return out

    def detect_latency(self) -> float:
        """理论检测延迟上界 = failures × interval（写进演练报告，别只说"能发现"）"""
        return self.failures_to_down * self.interval
