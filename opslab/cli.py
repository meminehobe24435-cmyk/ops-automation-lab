# -*- coding: utf-8 -*-
"""命令行入口：`python -m opslab <子命令>`。

    opslab collect            采一次（或 N 次）指标并打印
    opslab check              对目标跑一轮健康检查
    opslab watch              跑守护进程（采集 + 告警 + 通知）
    opslab drill              跑故障演练（注入 5 类故障，量检测/恢复/MTTR）
    opslab deploy             跑滚动发布演练（--bad 演练坏版本被门禁拦停 + 回滚）
    opslab demo-service       起示例服务
"""

import argparse
import json
import os
import sys
import time
from typing import List, Optional

from . import __version__, chaos, deploy as deploy_mod, procfs, procs
from .alerting import AlertManager, InhibitRule, Silence
from .daemon import Daemon, build_default_daemon
from .health import HealthChecker, HttpProbe, TcpProbe
from .notify import FileNotifier, RecordingNotifier, StdoutNotifier
from .rules import Rule


def _print(obj) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False, indent=2, default=str) + "\n")


def cmd_collect(args) -> int:
    collector = procfs.Collector(root=args.root)
    prev = None
    for idx in range(args.count):
        snap = collector.snapshot()
        out = {"snapshot": snap}
        if prev is not None:
            out["derived"] = collector.derive(prev, snap)
        if args.json:
            _print(out)
        else:
            print("[%d] %s" % (idx + 1, procfs.summarize(out.get("derived", snap))))
        prev = snap
        if idx + 1 < args.count:
            time.sleep(args.interval)
    return 0


def cmd_check(args) -> int:
    probe = (HttpProbe("svc", args.host, args.port, args.path, timeout=args.timeout)
             if args.kind == "http" else TcpProbe("svc", args.host, args.port, timeout=args.timeout))
    checker = HealthChecker([probe], interval=args.interval, failures_to_down=args.failures,
                            successes_to_up=args.successes)
    for idx in range(args.count):
        results = checker.check_once(time.time())
        for r in results:
            print("%-6s %-4s %8.1fms  %s" % (r.name, "OK" if r.ok else "FAIL",
                                             r.latency_ms, r.detail))
        print("  状态=%s（连续 %d 次失败判 DOWN，检测延迟上界 %.1fs）"
              % (checker.state_of("svc"), checker.failures_to_down, checker.detect_latency()))
        if idx + 1 < args.count:
            time.sleep(args.interval)
    return 0


def cmd_watch(args) -> int:
    notifier = StdoutNotifier() if not args.quiet else RecordingNotifier()
    rules = [
        Rule("ProcessCpuHigh", metric="proc.cpu_percent", op=">", threshold=args.cpu,
             for_seconds=args.for_seconds, agg="last", severity="warning",
             annotations={"summary": "进程 CPU 高于阈值"}),
    ]
    sampler = procfs.ProcessCpuSampler()
    daemon = Daemon(args.workdir, rules, notifier=notifier, interval=args.interval,
                    verbose=not args.quiet, log_path="")
    original_tick = daemon.tick

    def tick_with_cpu():
        record = original_tick()
        daemon.store.append("proc.cpu_percent", daemon.clock(), sampler.sample())
        return record

    daemon.tick = tick_with_cpu        # type: ignore[assignment]
    summary = daemon.run(ticks=args.ticks)
    _print({"ticks": summary["ticks"], "elapsed_s": summary["elapsed_s"],
            "notified": summary["notified"], "alerting": summary["alerting"]})
    return 0


def cmd_drill(args) -> int:
    report = chaos.run_all(args.workdir, base_port=args.base_port, verbose=not args.quiet,
                           only=args.only)
    if args.out:
        if not os.path.isdir(args.out):
            os.makedirs(args.out)
        path = os.path.join(args.out, "drill_report.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
        print("演练报告：%s" % path)
    for item in report["scenarios"]:
        print("%-16s %-4s detect=%7sms mttr=%8sms  %s" % (
            item["scenario"], "PASS" if item["passed"] else "FAIL",
            item["detect_ms"], item["mttr_ms"], item["detected_by"]))
    print("合计 %d/%d 通过；检测均值 %sms（最差 %sms）；MTTR 均值 %sms（最差 %sms）" % (
        report["passed"], report["total"], report["detect_ms_avg"], report["detect_ms_max"],
        report["mttr_ms_avg"], report["mttr_ms_max"]))
    return 0 if report["passed"] == report["total"] else 1


def cmd_deploy(args) -> int:
    report = deploy_mod.deploy_with_versions(args.workdir, base_port=args.base_port,
                                             count=args.count, new_version=args.version,
                                             bad_version=args.bad, verbose=not args.quiet)
    if args.out:
        if not os.path.isdir(args.out):
            os.makedirs(args.out)
        name = "deploy_report_bad.json" if args.bad else "deploy_report.json"
        path = os.path.join(args.out, name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
        print("发布报告：%s" % path)
    print("发布 %s：门禁=%s（%s）可用性=%.2f%%（%d 次请求，失败 %d，对用户透明的重试 %d）"
          "回滚=%s%s" % (
              report["deployment"], "通过" if report["gate"]["passed"] else "拦截",
              report["gate"]["reason"], report["availability"] * 100, report["requests"],
              report["failed_requests"], report["retries"],
              "是" if report["rolled_back"] else "否",
              "" if report["rollback_ms"] is None else "（%.0fms）" % report["rollback_ms"]))
    # 退出码按**演练意图**判定：
    #   正常发布 → 要 ok（门禁通过、没回滚）
    #   坏版本演练 → 要"门禁拦停 + 回滚成功"，这才是这条防线生效的证明
    if args.bad:
        intercepted = (not report["gate"]["passed"]) and report["rolled_back"]
        if intercepted and report["availability"] >= 0.999:
            print("坏版本演练通过：门禁拦停 + 自动回滚 %.0fms，发布期间可用性 %.2f%%"
                  % (report["rollback_ms"] or 0.0, report["availability"] * 100))
            return 0
        print("坏版本演练未达预期：门禁=%s 回滚=%s 可用性=%.4f"
              % (report["gate"]["passed"], report["rolled_back"], report["availability"]))
        return 1
    return 0 if report["ok"] else 1


def cmd_demo(args) -> int:
    from .demo import service
    return service.main(["--port", str(args.port), "--version", args.version])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="opslab", description="运维自动化与可观测性工具链")
    parser.add_argument("--version", action="version", version="opslab " + __version__)
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("collect", help="采一次（或 N 次）指标")
    p.add_argument("--root", default="/proc")
    p.add_argument("--count", type=int, default=1)
    p.add_argument("--interval", type=float, default=1.0)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_collect)

    p = sub.add_parser("check", help="跑一轮健康检查")
    p.add_argument("--kind", choices=("http", "tcp"), default="http")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=18080)
    p.add_argument("--path", default="/healthz")
    p.add_argument("--timeout", type=float, default=2.0)
    p.add_argument("--interval", type=float, default=1.0)
    p.add_argument("--count", type=int, default=1)
    p.add_argument("--failures", type=int, default=3)
    p.add_argument("--successes", type=int, default=2)
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("watch", help="跑守护进程（采集 + 告警 + 通知）")
    p.add_argument("--workdir", default=".")
    p.add_argument("--ticks", type=int, default=5)
    p.add_argument("--interval", type=float, default=0.2)
    p.add_argument("--cpu", type=float, default=80.0)
    p.add_argument("--for-seconds", type=float, default=0.4)
    p.add_argument("--quiet", action="store_true")
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("drill", help="跑故障演练")
    p.add_argument("--workdir", default="reports/drill")
    p.add_argument("--base-port", type=int, default=18500)
    p.add_argument("--only", action="append", default=None)
    p.add_argument("--out", default="reports")
    p.add_argument("--quiet", action="store_true")
    p.set_defaults(func=cmd_drill)

    p = sub.add_parser("deploy", help="跑滚动发布演练")
    p.add_argument("--workdir", default="reports/deploy")
    p.add_argument("--base-port", type=int, default=18700)
    p.add_argument("--count", type=int, default=3)
    p.add_argument("--version", default="v2")
    p.add_argument("--bad", action="store_true", help="演练坏版本：门禁拦停 + 自动回滚")
    p.add_argument("--out", default="reports")
    p.add_argument("--quiet", action="store_true")
    p.set_defaults(func=cmd_deploy)

    p = sub.add_parser("demo-service", help="起示例服务")
    p.add_argument("--port", type=int, default=18080)
    p.add_argument("--version", default="v1")
    p.set_defaults(func=cmd_demo)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 2
    return int(args.func(args))
