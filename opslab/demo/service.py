# -*- coding: utf-8 -*-
"""被运维工具链管理的示例服务（纯标准库 HTTP）。

它不是一个"假服务"，而是一个**具备真实运维语义**的最小服务，用来让健康检查、
滚动发布、故障演练都有真东西可打：

  GET  /healthz   健康检查：正常 200；**drain 期间 503**（= 从负载均衡摘除）
  GET  /version   当前版本（发布门禁用它确认"新版本真的起来了"）
  GET  /metrics   自采指标（Prometheus 文本格式）
  GET  /work?ms=N 模拟一次耗时 N 毫秒的请求（用来验证**优雅停机是否等在途请求跑完**）
  POST /shutdown  优雅停机：先摘除 → 等在途请求清零 → 再退出
  POST /unhealthy 让健康检查开始返回 500（模拟"进程活着但服务不可用"）

═══ 为什么要有 drain 这一步 ═══
直接 `kill` 的话，正在处理的那笔请求会被截断，用户在客户端看到的是一次凭空失败。
正确顺序是：**先让 LB 不再往这里发流量（/healthz → 503）→ 等在途请求跑完 → 再退出**。
所以本服务在 drain 后会打印 `in_flight=0` 再关闭监听 —— 发布演练里那个
"发布期间 500 次请求成功率 100%" 的结论，靠的就是这段逻辑。
"""

import argparse
import json
import os
import signal
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

STATE = {
    "version": os.environ.get("OPSLAB_VERSION", "v1"),
    "started_at": time.time(),
    "draining": False,
    "unhealthy": os.environ.get("OPSLAB_UNHEALTHY", "") == "1",
    "requests": 0,
    "errors": 0,
    "in_flight": 0,
    "max_in_flight": 0,
    "latency_ms_total": 0.0,
    "drain_delay": float(os.environ.get("OPSLAB_DRAIN_DELAY", "0")),
}
_LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "opslab-demo/1.0"

    # ---------------------------------------------------------------- 工具
    def _send(self, code, payload, ctype="application/json"):
        body = payload.encode("utf-8") if isinstance(payload, str) else json.dumps(
            payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, fmt, *args):     # 静音：演示服务不需要把访问日志打到 stderr
        pass

    def _enter(self):
        with _LOCK:
            STATE["requests"] += 1
            STATE["in_flight"] += 1
            if STATE["in_flight"] > STATE["max_in_flight"]:
                STATE["max_in_flight"] = STATE["in_flight"]

    def _leave(self, cost_ms):
        with _LOCK:
            STATE["in_flight"] -= 1
            STATE["latency_ms_total"] += cost_ms

    # ---------------------------------------------------------------- 路由
    def do_GET(self):
        self._enter()
        started = time.time()
        try:
            parsed = urlparse(self.path)
            path, query = parsed.path, parse_qs(parsed.query)

            if path == "/healthz":
                if STATE["draining"]:
                    return self._send(503, {"status": "draining", "version": STATE["version"]})
                if STATE["unhealthy"]:
                    STATE["errors"] += 1
                    return self._send(500, {"status": "unhealthy", "version": STATE["version"]})
                return self._send(200, {"status": "ok", "version": STATE["version"],
                                        "uptime_s": round(time.time() - STATE["started_at"], 3)})
            if path == "/version":
                return self._send(200, {"version": STATE["version"]})
            if path == "/metrics":
                with _LOCK:
                    snap = dict(STATE)
                snap["uptime_s"] = round(time.time() - snap["started_at"], 3)
                body = "\n".join([
                    "# TYPE opslab_up gauge",
                    "opslab_up %d" % (0 if snap["draining"] else 1),
                    "# TYPE opslab_requests_total counter",
                    "opslab_requests_total %d" % snap["requests"],
                    "# TYPE opslab_errors_total counter",
                    "opslab_errors_total %d" % snap["errors"],
                    "# TYPE opslab_in_flight gauge",
                    "opslab_in_flight %d" % snap["in_flight"],
                    "opslab_uptime_seconds %s" % snap["uptime_s"],
                    "",
                ])
                return self._send(200, body, "text/plain; charset=utf-8")
            if path == "/work":
                ms = float(query.get("ms", ["10"])[0])
                time.sleep(ms / 1000.0)
                return self._send(200, {"slept_ms": ms, "in_flight": STATE["in_flight"]})
            return self._send(404, {"error": "not found", "path": path})
        finally:
            self._leave((time.time() - started) * 1000.0)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/shutdown":
            self._send(200, {"status": "draining", "drain_delay": STATE["drain_delay"]})
            begin_drain()
            return
        if parsed.path == "/unhealthy":
            STATE["unhealthy"] = True
            return self._send(200, {"unhealthy": True})
        if parsed.path == "/healthy":
            STATE["unhealthy"] = False
            return self._send(200, {"unhealthy": False})
        return self._send(404, {"error": "not found"})


def begin_drain(server=None):
    """摘除 → 等在途请求清零 → 退出。"""
    with _LOCK:
        STATE["draining"] = True
    if server is not None:
        threading.Thread(target=_finish_drain, args=(server,), daemon=True).start()
    else:
        threading.Thread(target=_finish_drain, args=(_SERVER[0],), daemon=True).start()


_SERVER = [None]


def _finish_drain(server):
    if STATE["drain_delay"] > 0:
        time.sleep(STATE["drain_delay"])
    deadline = time.time() + 10.0
    while time.time() < deadline:
        with _LOCK:
            if STATE["in_flight"] <= 0:
                break
        time.sleep(0.02)
    with _LOCK:
        left = STATE["in_flight"]
    sys.stderr.write("drain 完成：in_flight=%d，退出\n" % left)
    sys.stderr.flush()
    if server is not None:
        threading.Thread(target=server.shutdown, daemon=True).start()


def main(argv=None):
    parser = argparse.ArgumentParser(description="opslab 示例服务")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--version", default=None)
    parser.add_argument("--drain-delay", type=float, default=None)
    parser.add_argument("--unhealthy", action="store_true")
    args = parser.parse_args(argv)

    if args.version:
        STATE["version"] = args.version
    if args.drain_delay is not None:
        STATE["drain_delay"] = args.drain_delay
    if args.unhealthy:
        STATE["unhealthy"] = True

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.daemon_threads = True
    _SERVER[0] = server
    sys.stderr.write("opslab-demo %s 监听 %s:%d\n" % (STATE["version"], args.host, args.port))
    sys.stderr.flush()

    def _on_signal(signum, frame):
        sys.stderr.write("收到信号 %s，开始优雅停机\n" % signum)
        sys.stderr.flush()
        begin_drain(server)

    for name in ("SIGTERM", "SIGINT"):
        sig = getattr(signal, name, None)
        if sig is not None:
            try:
                signal.signal(sig, _on_signal)
            except (ValueError, OSError, RuntimeError):
                pass

    try:
        server.serve_forever(poll_interval=0.05)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
