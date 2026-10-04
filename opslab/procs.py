# -*- coding: utf-8 -*-
"""子进程管理：启动、探活、**优雅停机**、强制回收。

═══ 为什么"优雅停机"要单独写一层 ═══
`proc.kill()` 一行就能让进程消失，但线上不能这么干：
  1. 正在处理的请求会被直接切断（用户看到 502）
  2. 缓冲区里的数据/日志会丢
  3. 负载均衡器还不知道这个实例要下线，仍在往它上面发流量

所以优雅停机是三步：**先从 LB 摘除（drain）→ 等在途请求处理完 → 再退出**。
本项目把这三步都做成可观测的：
  - `stop(graceful=True)` 先调服务的 `/shutdown`（服务立刻把 /healthz 改成 503 = 摘除），
    等它自己退出；等不到再 SIGTERM；再等不到才 kill。
  - Windows 上没有真正的 SIGTERM（`terminate()` 等于 TerminateProcess，是硬杀），
    所以"HTTP 控制端点 + 优雅退出"这套做法在 Windows 上反而是唯一正确的选择 ——
    也让这个模块可以跨平台被测试，而不是"只能在 Linux 上跑"。
"""

import os
import signal
import socket
import subprocess
import sys
import time
from typing import Dict, List, Optional, Sequence

from .health import _pid_alive

IS_WINDOWS = os.name == "nt"


def port_open(host: str, port: int, timeout: float = 0.3) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, int(port)))
        return True
    except (OSError, socket.timeout):
        return False
    finally:
        try:
            sock.close()
        except OSError:
            pass


def wait_port(host: str, port: int, timeout: float = 5.0, interval: float = 0.05,
              want_open: bool = True, clock=None) -> bool:
    """等端口到期望状态。返回是否达成（**不抛异常**，由调用方决定算不算失败）。"""
    clock = clock or time.time
    deadline = clock() + timeout
    while True:
        if port_open(host, port) == want_open:
            return True
        if clock() >= deadline:
            return False
        time.sleep(interval)


def http_get(host: str, port: int, path: str = "/healthz", timeout: float = 1.0):
    """返回 (status, body)；连不上返回 (0, "")。"""
    import http.client
    conn = http.client.HTTPConnection(host, int(port), timeout=timeout)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read(2048).decode("utf-8", "replace")
        return resp.status, body
    except Exception:
        return 0, ""
    finally:
        try:
            conn.close()
        except Exception:
            pass


def http_post(host: str, port: int, path: str, timeout: float = 1.0):
    import http.client
    conn = http.client.HTTPConnection(host, int(port), timeout=timeout)
    try:
        conn.request("POST", path)
        resp = conn.getresponse()
        return resp.status, resp.read(1024).decode("utf-8", "replace")
    except Exception:
        return 0, ""
    finally:
        try:
            conn.close()
        except Exception:
            pass


class ManagedProcess(object):
    """被管理的子进程（服务实例 / 命令步骤都用它）。"""

    def __init__(self, name: str, argv: Sequence[str], cwd: Optional[str] = None,
                 env: Optional[Dict[str, str]] = None, host: str = "127.0.0.1",
                 port: Optional[int] = None, log_path: Optional[str] = None):
        self.name = name
        self.argv = [str(a) for a in argv]
        self.cwd = cwd
        self.env = dict(env or {})
        self.host = host
        self.port = port
        self.log_path = log_path
        self.proc: Optional[subprocess.Popen] = None
        self.pid: Optional[int] = None
        self.started_at: Optional[float] = None
        self.stop_reason = ""

    # ------------------------------------------------------------------ 生命周期
    def start(self, wait: bool = True, timeout: float = 10.0, clock=None) -> int:
        if self.alive():
            raise RuntimeError("进程 %s 已在运行（pid=%s）" % (self.name, self.pid))
        env = dict(os.environ)
        env.update({k: str(v) for k, v in self.env.items()})
        stdout = subprocess.DEVNULL
        if self.log_path:
            # 日志目录必须先建出来：调用方给的是相对路径（reports/deploy/xxx.log）时，
            # 目录不存在会直接 FileNotFoundError，而且是在 Popen 里才炸，很难定位。
            parent = os.path.dirname(os.path.abspath(self.log_path))
            if parent and not os.path.isdir(parent):
                os.makedirs(parent)
            stdout = open(self.log_path, "ab")
        self.proc = subprocess.Popen(self.argv, cwd=self.cwd, env=env,
                                     stdout=stdout, stderr=subprocess.STDOUT,
                                     stdin=subprocess.DEVNULL)
        self.pid = self.proc.pid
        self.started_at = (clock or time.time)()
        if wait and self.port:
            if not wait_port(self.host, self.port, timeout=timeout, clock=clock):
                # ★ 报错必须带足够的信息，否则只会看到"端口没监听"，
                #   完全分不清是"进程崩了""卡在初始化""绑错网卡"还是"端口被占"。
                #   （真实案例：macOS 上 HTTPServer 卡在反向 DNS，日志为空、进程还活着。）
                raise RuntimeError(
                    "进程 %s 起来后端口 %d 仍未监听 | alive=%s exit=%s | 日志尾部：%s"
                    % (self.name, self.port, self.alive(),
                       None if self.proc is None else self.proc.poll(),
                       self.log_tail()))
        return self.pid

    def log_tail(self, limit: int = 400) -> str:
        if not self.log_path or not os.path.exists(self.log_path):
            return "(无日志)"
        try:
            with open(self.log_path, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                fh.seek(max(0, size - limit))
                data = fh.read()
            text = data.decode("utf-8", "replace").strip()
            return text if text else "(日志为空)"
        except (IOError, OSError) as exc:
            return "(读日志失败：%s)" % exc

    def alive(self) -> bool:
        if self.proc is not None:
            return self.proc.poll() is None
        return bool(self.pid) and _pid_alive(self.pid)

    def stop(self, graceful: bool = True, drain_timeout: float = 5.0,
             clock=None) -> Dict[str, object]:
        """停进程。返回过程记录（**回滚/演练报告要的就是这段细节**）。"""
        clock = clock or time.time
        info: Dict[str, object] = {"name": self.name, "graceful": graceful,
                                   "drain_ms": None, "signal": "", "killed": False}
        if not self.alive():
            info["stop_reason"] = "已停止"
            return info
        started = clock()

        if graceful and self.port:
            # ① 优雅路径：请求服务自己退出（服务会先把健康检查置为 503 = 从 LB 摘除）
            status, _ = http_post(self.host, self.port, "/shutdown", timeout=1.0)
            if status:
                info["signal"] = "HTTP /shutdown -> %d" % status
                if self._wait_exit(drain_timeout, clock):
                    info["drain_ms"] = round((clock() - started) * 1000.0, 1)
                    info["stop_reason"] = "优雅退出"
                    return info

        # ② SIGTERM
        if not IS_WINDOWS and self.pid:
            try:
                os.kill(self.pid, signal.SIGTERM)
                info["signal"] = "SIGTERM"
            except OSError:
                pass
            if self._wait_exit(drain_timeout, clock):
                info["drain_ms"] = round((clock() - started) * 1000.0, 1)
                info["stop_reason"] = "SIGTERM 后退出"
                return info

        # ③ 硬杀（最后手段）
        try:
            if self.proc is not None:
                self.proc.kill()
            elif self.pid:
                os.kill(self.pid, signal.SIGKILL if hasattr(signal, "SIGKILL") else signal.SIGTERM)
            info["killed"] = True
            info["signal"] = info["signal"] or "kill"
        except OSError:
            pass
        self._wait_exit(2.0, clock)
        info["stop_reason"] = "强制 kill"
        info["drain_ms"] = round((clock() - started) * 1000.0, 1)
        return info

    def _wait_exit(self, timeout: float, clock) -> bool:
        deadline = clock() + timeout
        while clock() < deadline:
            if not self.alive():
                return True
            time.sleep(0.02)
        return not self.alive()

    def signal(self, sig) -> bool:
        if not self.pid:
            return False
        if IS_WINDOWS and sig in (getattr(signal, "SIGSTOP", None), getattr(signal, "SIGCONT", None)):
            return False   # Windows 没有作业控制信号（挂死注入要改用代理方式）
        try:
            os.kill(self.pid, sig)
            return True
        except OSError:
            return False

    def __repr__(self) -> str:
        return "<ManagedProcess %s pid=%s port=%s alive=%s>" % (
            self.name, self.pid, self.port, self.alive())


def python_module_argv(module: str, *args: str) -> List[str]:
    """用**当前解释器**跑模块 —— CI 上装了多个 Python 版本，绝不能写死 'python'。"""
    return [sys.executable, "-m", module] + [str(a) for a in args]
