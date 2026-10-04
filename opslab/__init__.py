# -*- coding: utf-8 -*-
"""opslab —— 运维自动化与可观测性工具链（Python 3 标准库零依赖）。

模块地图（对应一份运维岗的日常）：

    procfs.py    指标采集：解析 /proc（CPU / 内存 / 负载 / 磁盘 / 网络）
    tsdb.py      时序存储：环形缓冲 + 时间窗口聚合（avg / p50 / p95 / p99 / rate）
    rules.py     告警规则：阈值 + 持续时长 + 状态机（INACTIVE→PENDING→FIRING→RESOLVED）
    alerting.py  告警治理：去重 / 分组 / 抑制 / 静默（噪声压缩）
    health.py    健康检查：HTTP / TCP / 进程 / 文件新鲜度 / 命令 + 连续失败判定
    logs.py      结构化日志：JSON lines、正则解析、轮转、关键字事件
    notify.py    通知出口：控制台 / Webhook / 录制（测试用），带超时与重试
    playbook.py  应急预案：JSON 剧本 DSL（检查→处置→验证→回滚），超时 + 幂等 + dry-run
    chaos.py     故障演练：延迟 / 错误率 / 挂死 / 杀进程 / 资源占用 + 演练报告（MTTR）
    deploy.py    发布编排：滚动重启 + 优雅停机 + 健康门禁 + 失败自动回滚
    daemon.py    常驻守护：单实例锁 + 信号处理 + 采集/评估/通知主循环
    cli.py       命令行入口

设计上的两个硬约束（也是这个项目可测试的原因）：
  1. **运行时零第三方依赖**：只用标准库。CI 里有一条 AST 依赖检查会拦下任何偷偷引入的
     requests / psutil / yaml / prometheus_client。
  2. **一切外部输入都可注入**：/proc 的根目录、时钟、探针、通知出口、子进程启动器
     全部可以替换成假实现 —— 所以「时间推进 30 秒让告警从 PENDING 变 FIRING」
     这种断言是确定性的，而不是靠 sleep 撞运气。
"""

__version__ = "1.0.0"

__all__ = [
    "procfs",
    "tsdb",
    "rules",
    "alerting",
    "health",
    "logs",
    "notify",
    "playbook",
    "chaos",
    "deploy",
    "daemon",
]
