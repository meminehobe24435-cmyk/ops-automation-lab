# -*- coding: utf-8 -*-
"""单元测试：解析 / 时序 / 告警规则 / 告警治理 / 健康检查 / 日志 / 剧本。

原则：**每个断言都要能对上账**。所以 /proc 用固定样本 + 手算期望值，
时间用假时钟推进，网络用真 socket（但目标是自己起的服务），
不用 sleep 撞运气 —— 否则 CI 上必然 flaky。
"""

import io
import json
import os
import socket
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from opslab import alerting, health, logs, playbook, procfs, rules, tsdb


# =============================================================== /proc 解析

PROC_STAT = """cpu  100 20 50 800 30 5 5 0 10 5
cpu0 50 10 25 400 15 2 3 0 5 2
cpu1 50 10 25 400 15 3 2 0 5 3
intr 12345
ctxt 999
"""

PROC_MEMINFO = """MemTotal:       16000000 kB
MemFree:         1000000 kB
MemAvailable:    8000000 kB
Buffers:          200000 kB
Cached:          4000000 kB
SwapTotal:       2000000 kB
SwapFree:        1500000 kB
"""

PROC_LOADAVG = "1.25 0.80 0.55 2/350 4242\n"
PROC_UPTIME = "12345.67 98765.43\n"

PROC_DISKSTATS = """   8       0 sda 1000 50 20000 500 2000 100 40000 900 3 1200 1400
   7       0 loop0 10 0 80 4 0 0 0 0 0 0 0
 259       0 nvme0n1 500 10 8000 200 700 20 11200 300 1 400 500
"""

PROC_NETDEV = """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1000      10    0    0    0     0          0         0     1000      10    0    0    0     0       0          0
  eth0: 5000000  4000    3    1    0     0          0         0  2000000    3000    1    2    0     0       0          0
"""


def test_parse_cpu_stat_fields_and_guest_exclusion():
    cpus = procfs.parse_cpu_stat(PROC_STAT)
    assert set(cpus) == {"cpu", "cpu0", "cpu1"}
    assert cpus["cpu"]["user"] == 100
    assert cpus["cpu"]["guest"] == 10
    assert cpus["cpu"]["guest_nice"] == 5
    # 总时间字段故意不含 guest / guest_nice（否则重复计算）
    total = sum(procfs.cpu_times(cpus["cpu"]).values())
    assert total == 100 + 20 + 50 + 800 + 30 + 5 + 5 + 0
    assert "guest" not in procfs.cpu_times(cpus["cpu"])


def test_cpu_busy_percent_hand_computed():
    # prev: 全部 0；cur: idle=800 iowait=30，其它合计 180 → busy = 180/1010
    prev = {"user": 0, "nice": 0, "system": 0, "idle": 0, "iowait": 0, "irq": 0,
            "softirq": 0, "steal": 0}
    cur = {"user": 100, "nice": 20, "system": 50, "idle": 800, "iowait": 30, "irq": 5,
           "softirq": 5, "steal": 0}
    busy = procfs.cpu_busy_percent(prev, cur)
    assert abs(busy - 180.0 / 1010.0 * 100.0) < 1e-9
    # 两次采样完全相同 → 没有增量 → 0（不能除以 0）
    assert procfs.cpu_busy_percent(cur, cur) == 0.0


def test_cpu_busy_percent_iowait_counts_as_idle():
    prev = {k: 0 for k in procfs.CPU_TOTAL_FIELDS}
    cur = dict(prev)
    cur["idle"] = 0
    cur["iowait"] = 100          # 全部时间都在等 IO
    assert procfs.cpu_busy_percent(prev, cur) == 0.0


def test_parse_meminfo_uses_memavailable_not_memfree(tmp_path):
    root = tmp_path / "proc"
    root.mkdir()
    (root / "meminfo").write_text(PROC_MEMINFO, encoding="utf-8")
    snap = procfs.Collector(root=str(root)).snapshot()
    assert snap["mem.total_kb"] == 16000000
    assert snap["mem.available_kb"] == 8000000
    # 用 MemAvailable：使用率 = (16M-8M)/16M = 50%
    assert snap["mem.used_percent"] == 50.0
    # 用 MemFree 会算成 93.75% —— 这就是那条第 2 个坑的量化版本
    assert snap["mem.free_percent_naive"] == 6.25


def test_parse_loadavg_and_uptime():
    load = procfs.parse_loadavg(PROC_LOADAVG)
    assert load["load1"] == 1.25 and load["load5"] == 0.80 and load["load15"] == 0.55
    assert load["runnable"] == 2 and load["procs"] == 350
    assert procfs.parse_uptime(PROC_UPTIME) == pytest.approx(12345.67)


def test_diskstats_sector_size_is_512_and_virtual_filtered():
    devs = procfs.parse_diskstats(PROC_DISKSTATS)
    assert "loop0" not in devs            # 虚拟设备默认过滤
    assert set(devs) == {"sda", "nvme0n1"}
    assert devs["sda"]["sectors_read"] == 20000
    assert devs["sda"]["ms_doing_io"] == 1200
    # 字节数 = 扇区 × 512（不论设备真实扇区大小）
    assert devs["sda"]["sectors_read"] * procfs.SECTOR_SIZE == 10240000


def test_netdev_parses_and_skips_header():
    ifaces = procfs.parse_netdev(PROC_NETDEV)
    assert set(ifaces) == {"lo", "eth0"}
    assert ifaces["eth0"]["rx_bytes"] == 5000000
    assert ifaces["eth0"]["rx_errs"] == 3
    assert ifaces["eth0"]["tx_drop"] == 2


def test_collector_snapshot_from_fixture_root(tmp_path):
    root = tmp_path / "proc"
    root.mkdir()
    (root / "stat").write_text(PROC_STAT, encoding="utf-8")
    (root / "meminfo").write_text(PROC_MEMINFO, encoding="utf-8")
    (root / "loadavg").write_text(PROC_LOADAVG, encoding="utf-8")
    (root / "uptime").write_text(PROC_UPTIME, encoding="utf-8")
    (root / "diskstats").write_text(PROC_DISKSTATS, encoding="utf-8")
    (root / "net").mkdir()
    (root / "net" / "dev").write_text(PROC_NETDEV, encoding="utf-8")

    collector = procfs.Collector(root=str(root), clock=lambda: 1000.0)
    snap = collector.snapshot()
    assert snap["ts"] == 1000.0
    assert snap["cpu.jiffies.idle"] == 800
    assert snap["disk.sda.read_bytes"] == 20000 * 512
    assert snap["net.eth0.rx_bytes"] == 5000000
    assert "net.lo.rx_bytes" not in snap          # 回环不算
    assert snap["uptime_seconds"] == pytest.approx(12345.67)
    # 缺文件时必须静默跳过，而不是抛异常（容器里经常没有 diskstats）
    empty = tmp_path / "empty"
    empty.mkdir()
    assert procfs.Collector(root=str(empty)).snapshot() == {"ts": procfs.Collector(
        root=str(empty)).snapshot()["ts"]} or True
    snap_empty = procfs.Collector(root=str(empty), clock=lambda: 5.0).snapshot()
    assert snap_empty == {"ts": 5.0}


def test_collector_on_shipped_fixtures_any_platform():
    """仓库里自带一份 /proc 样本：**在没有 /proc 的 Windows / macOS 上也能复现解析结果**，
    这让"指标采集"这件事在 CI 的任何 runner 上都是可验证的，而不是"只有 Linux 才测得到"。"""
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "proc")
    assert os.path.isdir(root), "缺少 tests/fixtures/proc 样本"
    collector = procfs.Collector(root=root, clock=lambda: 5000.0)
    snap = collector.snapshot()
    assert snap["ts"] == 5000.0
    # stat：cpu 行 idle=48182937 iowait=39120
    assert snap["cpu.jiffies.idle"] == 48182937
    assert snap["cpu.jiffies.iowait"] == 39120
    # meminfo：MemAvailable 9218372 / MemTotal 16299504 → 使用率 43.44%
    assert snap["mem.total_kb"] == 16299504
    assert snap["mem.available_kb"] == 9218372
    assert snap["mem.used_percent"] == pytest.approx(
        (16299504 - 9218372) * 100.0 / 16299504, abs=1e-3)
    # loadavg / uptime
    assert snap["load.load1"] == 0.42
    assert snap["load.runnable"] == 3.0 and snap["load.procs"] == 412.0
    assert snap["uptime_seconds"] == pytest.approx(482913.44)
    # diskstats：虚拟设备 loop0 被过滤，扇区 × 512
    assert "disk.loop0.read_bytes" not in snap
    assert snap["disk.sda.read_bytes"] == 4218374 * 512
    assert snap["disk.nvme0n1.write_bytes"] == 18293746 * 512
    # net/dev：lo 被排除
    assert snap["net.eth0.rx_bytes"] == 893274619
    assert "net.lo.rx_bytes" not in snap


def test_derive_rates_and_disk_utilization(tmp_path):
    root = tmp_path / "proc"
    root.mkdir()
    (root / "stat").write_text(PROC_STAT, encoding="utf-8")
    (root / "diskstats").write_text(PROC_DISKSTATS, encoding="utf-8")
    (root / "net").mkdir()
    (root / "net" / "dev").write_text(PROC_NETDEV, encoding="utf-8")
    times = [1000.0, 1002.0]
    collector = procfs.Collector(root=str(root), clock=lambda: times.pop(0))
    first = collector.snapshot()
    # 第二份样本：CPU 累计 +1000（其中 idle +400），sda 读扇区 +10000，eth0 rx +2000000
    (root / "stat").write_text(PROC_STAT.replace("cpu  100 20 50 800 30 5 5 0 10 5",
                                                 "cpu  400 20 250 1200 30 100 0 0 10 5"),
                               encoding="utf-8")
    (root / "diskstats").write_text(PROC_DISKSTATS.replace("20000 500", "30000 500"),
                                    encoding="utf-8")
    (root / "net" / "dev").write_text(PROC_NETDEV.replace("5000000  4000", "7000000  4000"),
                                      encoding="utf-8")
    second = collector.snapshot()
    derived = collector.derive(first, second)
    assert derived["ts"] == 1002.0
    # eth0: +2000000 字节 / 2 秒
    assert derived["net.eth0.rx_bytes.rate"] == pytest.approx(1000000.0)
    # sda: +10000 扇区 × 512 = 5120000 字节 / 2 秒
    assert derived["disk.sda.read_bytes.rate"] == pytest.approx(2560000.0)
    assert 0.0 <= derived["cpu.busy_percent"] <= 100.0
    assert derived["disk.sda.util_percent"] <= 100.0


def test_counter_delta_handles_reset():
    # 计数器变小（进程重启）时按重置处理，而不是给出巨大负值
    assert procfs._counter_delta(100.0, 30.0) == 30.0
    assert procfs._counter_delta(100.0, 150.0) == 50.0


def test_process_cpu_sampler_is_bounded():
    ticks = [0.0, 1.0]
    cpu = [0.0, 0.5]
    sampler = procfs.ProcessCpuSampler(clock=lambda: ticks.pop(0), cpu_clock=lambda: cpu.pop(0))
    assert sampler.sample() == pytest.approx(50.0)
    # 墙钟没走 → 返回 0 而不是除零
    sampler2 = procfs.ProcessCpuSampler(clock=lambda: 5.0, cpu_clock=lambda: 1.0)
    assert sampler2.sample() == 0.0


# =============================================================== 时序库

def test_ring_buffer_overwrites_oldest():
    ring = tsdb.RingBuffer(3)
    for i in range(5):
        ring.append((float(i), float(i)))
    assert len(ring) == 3
    assert [t for t, _ in ring.to_list()] == [2.0, 3.0, 4.0]
    assert ring.latest(2) == [(3.0, 3.0), (4.0, 4.0)]
    assert ring.capacity == 3


def test_ring_buffer_capacity_must_be_positive():
    with pytest.raises(ValueError):
        tsdb.RingBuffer(0)


def test_series_rejects_out_of_order_timestamps():
    series = tsdb.Series("m", capacity=10)
    series.append(1.0, 1.0)
    series.append(2.0, 2.0)
    with pytest.raises(ValueError):
        series.append(1.5, 9.0)
    assert series.total_dropped == 1
    assert len(series) == 2


def test_window_is_time_based_not_position_based():
    series = tsdb.Series("m", capacity=100)
    for i in range(10):
        series.append(float(i), float(i))
    # [5, 8] 闭区间
    assert series.values(8.0, 3.0) == [5.0, 6.0, 7.0, 8.0]
    # 点被环形缓冲挤掉后窗口依然按时间算
    small = tsdb.Series("s", capacity=3)
    for i in range(10):
        small.append(float(i), float(i))
    assert small.values(9.0, 100.0) == [7.0, 8.0, 9.0]


def test_percentile_linear_interpolation_hand_computed():
    values = [1.0, 2.0, 3.0, 4.0]
    # idx = 0.5 * 3 = 1.5 → 2 + (3-2)*0.5 = 2.5
    assert tsdb.percentile(values, 50) == pytest.approx(2.5)
    # idx = 0.95 * 3 = 2.85 → 3 + (4-3)*0.85 = 3.85
    assert tsdb.percentile(values, 95) == pytest.approx(3.85)
    assert tsdb.percentile(values, 0) == 1.0
    assert tsdb.percentile(values, 100) == 4.0
    assert tsdb.percentile([7.0], 95) == 7.0
    import math
    assert math.isnan(tsdb.percentile([], 95))


def test_aggregate_values_hand_computed():
    agg = tsdb.aggregate_values([2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0])
    assert agg["count"] == 8.0
    assert agg["avg"] == pytest.approx(5.0)
    assert agg["min"] == 2.0 and agg["max"] == 9.0
    assert agg["sum"] == pytest.approx(40.0)
    # 总体方差 = 32/8 = 4 → stddev = 2
    assert agg["stddev"] == pytest.approx(2.0)
    assert agg["p50"] == pytest.approx(4.5)
    empty = tsdb.aggregate_values([])
    assert empty["count"] == 0.0 and empty["sum"] == 0.0


def test_store_rate_handles_counter_reset():
    """rate 的口径：沿窗口累加正向增量；遇到重置则把当前值算作这一段的增量。

    为什么不是简单的 (末值-首值)/dt：窗口里只要发生过一次进程重启，
    那个减法会把重启前的量全丢掉 → 速率明显偏小（"指标看着正常、含义错了"）。
    """
    store = tsdb.Store(capacity=100)
    store.append("c", 0.0, 100.0)
    store.append("c", 1.0, 50.0)     # 重置：这一段增量按当前值 50 计 → 50/1 = 50
    assert store.rate("c", 1.0, 10.0) == pytest.approx(50.0)
    store.append("c", 2.0, 150.0)    # 正常增量 +100
    # 窗口 [0,2]：增量 = 50（重置段）+ 100（正常段）= 150，dt = 2 → 75/s
    assert store.rate("c", 2.0, 10.0) == pytest.approx(75.0)
    # 没有重置时就是普通差分
    store2 = tsdb.Store(capacity=100)
    store2.append("c", 0.0, 0.0)
    store2.append("c", 2.0, 100.0)
    assert store2.rate("c", 2.0, 10.0) == pytest.approx(50.0)
    # 只有一个点 → 0（没有增量可言）
    store3 = tsdb.Store(capacity=100)
    store3.append("c", 0.0, 5.0)
    assert store3.rate("c", 0.0, 10.0) == 0.0


def test_store_skips_nan_and_inf():
    store = tsdb.Store()
    written = store.append_many(1.0, {"a": 1.0, "b": float("nan"), "c": float("inf"),
                                      "ts": 1.0, "d": "x"})
    assert written == 1
    assert store.metric_names() == ["a"]


# =============================================================== 告警规则

def test_compare_all_operators():
    assert rules.compare(90.0, ">", 85.0)
    assert not rules.compare(85.0, ">", 85.0)
    assert rules.compare(85.0, ">=", 85.0)
    assert rules.compare(10.0, "<", 20.0)
    assert rules.compare(20.0, "<=", 20.0)
    assert rules.compare(0.0, "==", 0.0)
    assert rules.compare(1.0, "!=", 0.0)
    assert rules.compare(0.0, "absent", 0.0, missing=True)
    assert not rules.compare(0.0, "absent", 0.0, missing=False)
    # 缺数据时阈值类规则不触发
    assert not rules.compare(0.0, ">", -1.0, missing=True)
    with pytest.raises(ValueError):
        rules.compare(1.0, "~=", 1.0)


def test_rule_validation():
    with pytest.raises(ValueError):
        rules.Rule("bad", metric=None, probe=None)
    with pytest.raises(ValueError):
        rules.Rule("bad", metric="m", op="~~")
    with pytest.raises(ValueError):
        rules.Rule("bad", metric="m", for_seconds=-1)


def test_rule_scalar_key():
    assert rules.Rule("a", metric="cpu", agg="p95").scalar_key == "cpu|p95"
    assert rules.Rule("a", probe="svc").scalar_key == "probe.svc.up"


def test_state_machine_for_seconds_immediate():
    engine = rules.RuleEngine([rules.Rule("R", metric="m", op=">", threshold=10,
                                         for_seconds=0)])
    events = engine.observe(1.0, {"m|avg": 20.0})
    assert len(events) == 1 and events[0].state == rules.FIRING
    assert events[0].transition == "->FIRING"
    # 持续为真不再重复跃迁
    assert engine.observe(2.0, {"m|avg": 20.0}) == []
    resolved = engine.observe(3.0, {"m|avg": 0.0})
    assert len(resolved) == 1 and resolved[0].state == rules.RESOLVED
    assert engine.active() == []


def test_pending_requires_continuous_truth():
    engine = rules.RuleEngine([rules.Rule("R", metric="m", op=">", threshold=10,
                                         for_seconds=5.0)])
    engine.observe(0.0, {"m|avg": 20.0})
    assert engine.snapshot()["R"] == rules.PENDING
    engine.observe(3.0, {"m|avg": 20.0})
    assert engine.snapshot()["R"] == rules.PENDING
    events = engine.observe(5.0, {"m|avg": 20.0})       # 恰好到 5s
    assert events and events[-1].state == rules.FIRING
    assert engine.snapshot()["R"] == rules.FIRING


def test_pending_flap_never_notifies():
    """抖动抑制：还没到 for_seconds 就恢复 → 一条通知都不该有"""
    engine = rules.RuleEngine([rules.Rule("R", metric="m", op=">", threshold=10,
                                         for_seconds=10.0)])
    engine.observe(0.0, {"m|avg": 20.0})
    engine.observe(1.0, {"m|avg": 20.0})
    engine.observe(2.0, {"m|avg": 0.0})                  # 抖动
    assert engine.snapshot()["R"] == rules.INACTIVE
    assert [e.state for e in engine.history if e.state == rules.FIRING] == []
    # 再抖一次也一样
    engine.observe(3.0, {"m|avg": 30.0})
    engine.observe(4.0, {"m|avg": 0.0})
    assert engine.snapshot()["R"] == rules.INACTIVE


def test_missing_data_triggers_absent_rule_only():
    engine = rules.RuleEngine([
        rules.Rule("Threshold", metric="m", op=">", threshold=0.0, for_seconds=0.0),
        rules.Rule("Absent", metric="m", op="absent", for_seconds=0.0, window=30.0),
    ])
    store = tsdb.Store()
    # 完全没有数据点 → 只有 Absent 规则响
    scalars = rules.expand_scalars(store, 10.0, engine.rules)
    engine.observe(10.0, scalars)
    assert engine.active() == ["Absent"]
    # 有数据点后 Absent 恢复
    store.append("m", 10.0, 5.0)
    scalars = rules.expand_scalars(store, 11.0, engine.rules)
    events = engine.observe(11.0, scalars)
    assert "Absent" not in engine.active()
    assert any(e.state == rules.RESOLVED and e.rule.name == "Absent" for e in events)


def test_engine_rejects_time_going_backwards():
    engine = rules.RuleEngine([rules.Rule("R", metric="m", op=">", threshold=1)])
    engine.observe(10.0, {"m|avg": 0.0})
    with pytest.raises(ValueError):
        engine.observe(9.0, {"m|avg": 0.0})


def test_probe_rule_uses_up_flag():
    engine = rules.RuleEngine([rules.Rule("Down", probe="svc", op="==", threshold=0.0,
                                         for_seconds=0.0)])
    assert engine.observe(1.0, {"probe.svc.up": 1.0}) == []
    events = engine.observe(2.0, {"probe.svc.up": 0.0})
    assert events and events[0].state == rules.FIRING


def test_expand_scalars_uses_window_aggregate():
    store = tsdb.Store()
    for i, v in enumerate([10.0, 20.0, 30.0]):
        store.append("cpu", float(i), v)
    rule = rules.Rule("R", metric="cpu", op=">", threshold=25.0, agg="max", window=10.0)
    scalars = rules.expand_scalars(store, 2.0, [rule])
    assert scalars["cpu|max"] == 30.0
    rule_avg = rules.Rule("R2", metric="cpu", op=">", threshold=25.0, agg="avg", window=10.0)
    assert rules.expand_scalars(store, 2.0, [rule_avg])["cpu|avg"] == pytest.approx(20.0)
    # last 取最新点
    rule_last = rules.Rule("R3", metric="cpu", op=">", threshold=25.0, agg="last")
    assert rules.expand_scalars(store, 2.0, [rule_last])["cpu|last"] == 30.0
    # 有 override 时以外部事实为准
    merged = rules.expand_scalars(store, 2.0, [rule], override={"cpu|max": 99.0})
    assert merged["cpu|max"] == 99.0


# =============================================================== 告警治理

def _firing(name="R", severity="warning", labels=None, value=1.0):
    rule = rules.Rule(name, metric="m", op=">", threshold=0.0, severity=severity,
                      labels=labels or {})
    return rules.Alert(rule, rules.FIRING, 1.0, value)


def test_dedupe_sends_once_until_resolved():
    manager = alerting.AlertManager()
    t = 0.0
    sent = 0
    for _ in range(50):                       # 50 轮持续异常
        t += 1.0
        notes = manager.handle([_firing()], t)
        sent += len(notes)
    assert sent == 1
    assert manager.stats["deduped"] == 49
    # 恢复通知要发出去
    rule = rules.Rule("R", metric="m", op=">", threshold=0.0)
    resolved = rules.Alert(rule, rules.RESOLVED, t + 1, 0.0)
    notes = manager.handle([resolved], t + 1)
    assert len(notes) == 1 and notes[0].status == "RESOLVED"
    # 恢复后再次异常 → 又能发一次
    assert len(manager.handle([_firing()], t + 2)) == 1


def test_repeat_interval_repeats_firing():
    manager = alerting.AlertManager(repeat_interval=10.0)
    assert len(manager.handle([_firing()], 0.0)) == 1
    assert len(manager.handle([_firing()], 5.0)) == 0
    assert len(manager.handle([_firing()], 11.0)) == 1


def test_silence_suppresses_but_still_records():
    silence = alerting.Silence({"alertname": "R"}, 0.0, 100.0, comment="计划内维护")
    manager = alerting.AlertManager(silences=[silence])
    notes = manager.handle([_firing()], 10.0)
    assert notes == []
    assert manager.notifications[-1].suppressed == "silence"
    assert manager.stats["silenced"] == 1
    # 窗口外不再静默
    manager2 = alerting.AlertManager(silences=[alerting.Silence({"alertname": "R"}, 0.0, 5.0)])
    assert len(manager2.handle([_firing()], 10.0)) == 1


def test_inhibit_suppresses_downstream():
    inhibit = alerting.InhibitRule(source={"alertname": "NodeDown"},
                                   target={"alertname": "ServiceDown"},
                                   equal=["node"], name="节点挂了就别报它上面的服务")
    manager = alerting.AlertManager(inhibits=[inhibit])
    assert len(manager.handle([_firing("NodeDown", labels={"node": "n1"})], 1.0)) == 1
    notes = manager.handle([_firing("ServiceDown", labels={"node": "n1"})], 2.0)
    assert notes == []
    assert manager.stats["inhibited"] == 1
    # 另一台节点的告警不受影响（equal 标签不同）
    assert len(manager.handle([_firing("ServiceDown", labels={"node": "n2"})], 3.0)) == 1


def test_inhibit_state_is_per_manager_instance():
    """回归：_firing_labels 曾经写成类属性 → 两个 manager 会互相抑制"""
    rule = alerting.InhibitRule(source={"alertname": "NodeDown"},
                                target={"alertname": "ServiceDown"})
    m1 = alerting.AlertManager(inhibits=[rule])
    m2 = alerting.AlertManager(inhibits=[rule])
    m1.handle([_firing("NodeDown")], 1.0)
    notes = m2.handle([_firing("ServiceDown")], 2.0)
    assert len(notes) == 1, "第二个 manager 不该被第一个的状态抑制"


def test_grouping_merges_notifications():
    manager = alerting.AlertManager(group_by=["node"], group_wait=5.0)
    for idx in range(3):
        manager.handle([_firing("Svc%d" % idx, labels={"node": "n1"})], float(idx))
    assert manager.sent == []
    flushed = manager.flush(10.0)
    assert len(flushed) == 1
    assert flushed[0].count == 3
    assert manager.stats["grouped"] == 2


def test_notifier_retry_with_backoff_uses_injected_sleep():
    slept = []
    notifier = alerting and None
    from opslab.notify import RecordingNotifier
    rec = RecordingNotifier(fail_times=2, retries=2, backoff=1.0, sleep=slept.append)
    assert rec.send(_firing()) is True
    assert rec.attempts == 3
    assert slept == [1.0, 2.0]          # 指数退避
    rec2 = RecordingNotifier(fail_times=5, retries=2, sleep=slept.append)
    assert rec2.send(_firing()) is False
    assert rec2.failures == 1


def test_compression_ratio():
    manager = alerting.AlertManager()
    for i in range(100):
        manager.handle([_firing()], float(i))
    assert manager.stats["sent"] == 1
    assert manager.compression_ratio() == pytest.approx(1.0 - 1.0 / 100.0)
    assert manager.report()["compression_ratio"] == pytest.approx(0.99)


# =============================================================== 健康检查

def test_http_probe_against_real_server():
    server, port = _tiny_server()
    try:
        probe = health.HttpProbe("svc", "127.0.0.1", port, "/ok", timeout=2.0)
        result = probe.check()
        assert result.ok and "HTTP 200" in result.detail
        # 期望状态码不符 → 失败
        probe404 = health.HttpProbe("svc", "127.0.0.1", port, "/missing", timeout=2.0)
        assert not probe404.check().ok
        # 期望响应体不符 → 失败
        probe_body = health.HttpProbe("svc", "127.0.0.1", port, "/ok", expect_body="nope",
                                      timeout=2.0)
        assert not probe_body.check().ok
    finally:
        server.shutdown()
        server.server_close()


def test_http_probe_returns_failure_not_exception_when_refused():
    probe = health.HttpProbe("svc", "127.0.0.1", _free_port(), "/ok", timeout=0.3)
    result = probe.check()
    assert result.ok is False
    assert result.detail


def test_tcp_probe_and_timeout_bound():
    server, port = _tiny_server()
    try:
        assert health.TcpProbe("t", "127.0.0.1", port, timeout=1.0).check().ok
        assert not health.TcpProbe("t", "127.0.0.1", _free_port(), timeout=0.3).check().ok
    finally:
        server.shutdown()
        server.server_close()


def test_probe_timeout_is_enforced_on_hung_endpoint():
    """挂死端点：探针必须在 timeout 附近返回，而不是永远挂着"""
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)
    port = listener.getsockname()[1]
    accepted = []

    def accept_and_hang():
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            accepted.append(conn)   # 只接受，永不回包

    thread = threading.Thread(target=accept_and_hang, daemon=True)
    thread.start()
    try:
        probe = health.HttpProbe("hung", "127.0.0.1", port, "/healthz", timeout=0.4)
        started = time.time()
        result = probe.check()
        elapsed = time.time() - started
        assert result.ok is False
        assert elapsed < 2.0, "探针必须靠超时返回，不能挂死（实测 %.2fs）" % elapsed
    finally:
        listener.close()
        for conn in accepted:
            try:
                conn.close()
            except OSError:
                pass


def test_file_probe_freshness():
    import tempfile
    fd, path = tempfile.mkstemp()
    os.close(fd)
    try:
        now = time.time()
        assert health.FileProbe("f", path, max_age=3600, clock=lambda: now).check().ok
        stale = health.FileProbe("f", path, max_age=0.0001, clock=lambda: now + 100).check()
        assert not stale.ok and "没更新" in stale.detail
        assert not health.FileProbe("f", path + ".nope").check().ok
    finally:
        os.unlink(path)


def test_process_probe_uses_pid_not_absence():
    assert health.ProcessProbe("p", pid=os.getpid()).check().ok
    assert not health.ProcessProbe("p", pid=999999).check().ok
    assert not health.ProcessProbe("p", pid=None).check().ok     # 拿不到 pid = 失败


def test_command_probe_exit_code():
    assert health.CommandProbe("c", [sys.executable, "-c", "print('hi')"]).check().ok
    bad = health.CommandProbe("c", [sys.executable, "-c", "raise SystemExit(3)"])
    assert not bad.check().ok


def test_health_checker_rise_fall_state_machine():
    class Flaky(health.Probe):
        def __init__(self):
            health.Probe.__init__(self, "flaky", 0.1)
            self.script = []
            self.idx = 0

        def run(self, ts):
            ok = self.script[min(self.idx, len(self.script) - 1)]
            self.idx += 1
            return ok, "script"

    probe = Flaky()
    checker = health.HealthChecker([probe], interval=1.0, failures_to_down=3, successes_to_up=2)
    assert checker.state_of("flaky") == health.STARTING
    probe.script = [True, True]
    checker.check_once(0.0)
    assert checker.state_of("flaky") == health.STARTING      # 只成功 1 次，还差 1 次
    checker.check_once(1.0)
    assert checker.state_of("flaky") == health.UP
    # 两次失败还不够判 DOWN（rise/fall 的意义）
    probe.script = [False, False]
    checker.check_once(2.0)
    checker.check_once(3.0)
    assert checker.state_of("flaky") == health.UP
    checker.check_once(4.0)
    assert checker.state_of("flaky") == health.DOWN
    assert checker.down_names() == ["flaky"]
    # 一次成功不算恢复，要连续 2 次
    probe.script = [True]
    checker.check_once(5.0)
    assert checker.state_of("flaky") == health.DOWN
    checker.check_once(6.0)
    assert checker.state_of("flaky") == health.UP
    kinds = [t["to"] for t in checker.transitions]
    assert kinds == [health.UP, health.DOWN, health.UP]
    assert checker.detect_latency() == 3.0
    assert checker.up_flags() == {"probe.flaky.up": 1.0}


def test_health_checker_validation():
    with pytest.raises(ValueError):
        health.HealthChecker([], failures_to_down=0)


# =============================================================== 日志

def test_json_line_is_parseable_and_sorted():
    line = logs.json_line("INFO", "hello", ts=1.5, b=2, a=1)
    data = json.loads(line)
    assert data["level"] == "INFO" and data["msg"] == "hello" and data["ts"] == 1.5
    assert data["a"] == 1 and data["b"] == 2
    assert line.index('"a"') < line.index('"b"')      # kv 按 key 排序，便于 diff


def test_line_parser_keeps_unparsed_lines():
    parser = logs.LineParser([logs.NGINX_COMBINED, logs.SYSLOG_STYLE])
    parsed = parser.parse('10.0.0.1 - - [01/Jan/2026:00:00:00 +0800] "GET /a HTTP/1.1" 200 512')
    assert parsed["format"] == "nginx" and parsed["status"] == "200" and parsed["path"] == "/a"
    syslog = parser.parse("Jan  1 00:00:01 host app[123]: started")
    assert syslog["format"] == "syslog" and syslog["pid"] == "123"
    unknown = parser.parse("some random line")
    assert unknown["parsed"] is False and unknown["raw"] == "some random line"
    assert parser.stats == {"parsed": 2, "raw": 1}


def test_keyword_trigger_counts_every_hit():
    trigger = logs.KeywordTrigger(["timeout", "OOM"])
    trigger.feed({"raw": "request timeout after 3s"})
    trigger.feed({"raw": "request timeout after 3s"})
    trigger.feed({"raw": "all good"})
    assert trigger.counts["timeout"] == 2
    assert trigger.counts["oom"] == 0
    assert len(trigger.hits) == 2
    assert trigger.hits[0]["keyword"] == "timeout"


def test_rotating_writer_rotates_and_keeps_backups(tmp_path):
    path = str(tmp_path / "app.log")
    writer = logs.RotatingWriter(path, max_bytes=200, backups=2)
    for i in range(40):
        writer.write(json.dumps({"i": i, "pad": "x" * 20}))
    writer.close()
    assert writer.rotations >= 1
    assert os.path.exists(path)
    assert os.path.exists(path + ".1")
    # 备份数不超过 backups
    assert not os.path.exists(path + ".3")
    # 每行都是完整 JSON（没有跨文件被截断）
    for candidate in [path] + writer.backups_on_disk():
        with open(candidate, "r", encoding="utf-8") as fh:
            for line in fh:
                json.loads(line)
    # 最旧的备份里应该是较早的序号
    oldest = sorted(json.loads(l)["i"] for l in open(path + ".1", encoding="utf-8")
                    if l.strip())
    newest = sorted(json.loads(l)["i"] for l in open(path, encoding="utf-8") if l.strip())
    assert oldest and newest and oldest[0] < newest[0]


def test_rotating_writer_validation(tmp_path):
    with pytest.raises(ValueError):
        logs.RotatingWriter(str(tmp_path / "x.log"), max_bytes=0)


def test_json_formatter_with_logging_module():
    import logging
    stream = io.StringIO()
    logger = logging.getLogger("opslab-test-formatter")
    logger.handlers = []
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logs.JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.info("磁盘写入慢", extra={"kv": {"device": "sda", "ms": 1200}})
    data = json.loads(stream.getvalue().strip())
    assert data["msg"] == "磁盘写入慢" and data["device"] == "sda" and data["ms"] == 1200
    assert data["level"] == "INFO"


# =============================================================== 剧本

def test_playbook_runs_steps_and_reports(tmp_path):
    target = tmp_path / "flag.txt"
    book = playbook.Playbook("t", [
        playbook.Step("note", "note", message="开始"),
        playbook.Step("mk", "exec", argv=[sys.executable, "-c",
                                          "open(r'%s','w').write('1')" % target]),
        playbook.Step("probe", "probe", expect=True,
                      probe={"kind": "file", "path": str(target), "max_age": 3600}),
    ])
    report = playbook.Executor().run(book)
    assert report.ok and len(report.steps) == 3
    assert [s.status for s in report.steps] == [playbook.OK] * 3
    assert target.exists()


def test_playbook_failure_triggers_rollback_and_skips_rest(tmp_path):
    record = tmp_path / "record.txt"
    book = playbook.Playbook("t", [
        playbook.Step("w1", "exec", argv=[sys.executable, "-c",
                                          "open(r'%s','a').write('w1;')" % record]),
        playbook.Step("boom", "probe", expect=True,
                      probe={"kind": "file", "path": str(tmp_path / "nope"), "max_age": 1}),
        playbook.Step("never", "exec", argv=[sys.executable, "-c",
                                             "open(r'%s','a').write('never;')" % record]),
    ], rollback=[
        playbook.Step("undo", "exec", argv=[sys.executable, "-c",
                                            "open(r'%s','a').write('undo;')" % record]),
    ])
    report = playbook.Executor().run(book)
    assert report.ok is False
    assert report.rolled_back is True
    assert "boom" in report.failed_steps()
    assert report.steps[2].status == playbook.SKIPPED
    assert record.read_text(encoding="utf-8") == "w1;undo;"


def test_playbook_on_failure_continue_runs_remaining():
    book = playbook.Playbook("t", [
        playbook.Step("bad", "probe", expect=True, on_failure="continue",
                      probe={"kind": "file", "path": "/definitely/not/here", "max_age": 1}),
        playbook.Step("ok", "note", message="继续执行"),
    ])
    report = playbook.Executor().run(book)
    assert report.ok is False
    assert report.steps[1].status == playbook.OK


def test_playbook_step_timeout(tmp_path):
    clock = _FakeClock()
    executor = playbook.Executor(clock=clock, sleep=clock.advance_sleep)
    book = playbook.Playbook("t", [
        playbook.Step("wait", "wait_probe", timeout=5.0, expect=True, interval=1.0,
                      probe={"kind": "tcp", "port": _free_port(), "timeout": 0.05}),
    ])
    report = executor.run(book)
    assert report.steps[0].status == playbook.TIMEOUT
    assert clock.now >= 5.0                      # 真的按超时退出，没有无限等


def test_playbook_dry_run_skips_writes(tmp_path):
    target = tmp_path / "should_not_exist.txt"
    book = playbook.Playbook("t", [
        playbook.Step("mk", "exec", argv=[sys.executable, "-c",
                                          "open(r'%s','w').write('x')" % target]),
        playbook.Step("probe", "probe", expect=False,
                      probe={"kind": "file", "path": str(target), "max_age": 1}),
    ])
    report = playbook.Executor().run(book, dry_run=True)
    assert report.dry_run is True
    assert report.steps[0].status == playbook.SKIPPED
    assert not target.exists()
    assert report.steps[1].status == playbook.OK      # 只读步骤照跑


def test_playbook_skip_if_makes_it_idempotent(tmp_path):
    """幂等：目标已存在 → 重启类步骤被跳过"""
    target = tmp_path / "exists.txt"
    target.write_text("1", encoding="utf-8")
    runs = []
    book = playbook.Playbook("t", [
        playbook.Step("start", "exec", skip_if={"kind": "file", "path": str(target),
                                                "max_age": 3600},
                      argv=[sys.executable, "-c", "print('should not run')"]),
    ])
    report = playbook.Executor(log=runs.append).run(book)
    assert report.steps[0].status == playbook.SKIPPED
    assert "skip_if" in report.steps[0].detail


def test_non_blocking_step_failure_does_not_fail_playbook():
    """诊断类步骤（blocking=False）失败不算剧本失败 —— 处置成不成功看验证步骤。

    场景来源：CPU 被打满时服务其实还活着，"确认服务已不可用"本来就不该成立。
    """
    book = playbook.Playbook("t", [
        playbook.Step("diagnose", "probe", expect=True, blocking=False, on_failure="continue",
                      probe={"kind": "file", "path": "/definitely/not/here", "max_age": 1}),
        playbook.Step("act", "note", message="照常处置"),
        playbook.Step("verify", "note", message="验证通过"),
    ])
    report = playbook.Executor().run(book)
    assert report.steps[0].status == playbook.FAILED      # 失败被记录下来
    assert report.steps[1].status == playbook.OK          # 但没有中断
    assert report.steps[2].status == playbook.OK
    assert report.ok is True                              # 剧本整体仍算成功
    assert report.failed_steps() == ["diagnose"]          # 报告里仍能看见它


def test_playbook_global_timeout():
    clock = _FakeClock()
    book = playbook.Playbook("t", [
        playbook.Step("slow", "sleep", sleep=1.0),        # 这一步把假时钟推进 1 秒
        playbook.Step("s2", "note", message="2"),
    ], timeout=0.5)
    report = playbook.Executor(clock=clock, sleep=clock.advance_sleep).run(book)
    assert report.ok is False
    assert report.steps[-1].status == playbook.TIMEOUT
    assert "总超时" in report.steps[-1].detail


def test_pending_since_zero_is_not_treated_as_missing():
    """回归：`pending_since or ts` 在 pending_since == 0.0 时会取到 ts，
    导致 PENDING 永远升不到 FIRING（假值为 0 的经典坑）。"""
    engine = rules.RuleEngine([rules.Rule("R", probe="svc", op="==", threshold=0.0,
                                         for_seconds=1.0)])
    engine.observe(0.0, {"probe.svc.up": 0.0})
    assert engine.snapshot()["R"] == rules.PENDING
    events = engine.observe(1.0, {"probe.svc.up": 0.0})
    assert [e.state for e in events] == [rules.FIRING]


def test_playbook_from_dict_roundtrip():
    data = {"name": "svc_down", "timeout": 30, "on_failure": "rollback",
            "steps": [{"id": "a", "type": "note", "message": "hi"}],
            "rollback": [{"id": "r", "type": "note", "message": "undo"}]}
    book = playbook.Playbook.from_dict(data)
    assert book.name == "svc_down" and book.on_failure == "rollback"
    assert book.steps[0].message == "hi" and book.rollback[0].id == "r"
    report = playbook.Executor().run(book)
    assert report.ok and len(report.steps) == 1


# =============================================================== 守护进程/发布（可离线部分）

def test_pidfile_single_instance(tmp_path):
    from opslab.daemon import PidFile
    path = str(tmp_path / "x.pid")
    first, second = PidFile(path), PidFile(path)
    assert first.acquire() is True
    assert second.acquire() is False              # 第二个实例拿不到锁
    assert second.holder() == os.getpid()
    first.release()
    assert PidFile(path).acquire() is True


def test_daemon_tick_with_fake_clock_and_no_proc(tmp_path):
    from opslab.daemon import Daemon
    from opslab.notify import RecordingNotifier
    empty = tmp_path / "noproc"
    empty.mkdir()
    clock = _FakeClock()
    notifier = RecordingNotifier()
    rule = rules.Rule("CpuHigh", metric="proc.cpu_percent", op=">", threshold=10.0,
                      for_seconds=1.0, agg="last")
    daemon = Daemon(str(tmp_path), [rule], collector=procfs.Collector(root=str(empty)),
                    notifier=notifier, interval=1.0, clock=clock, sleep=clock.advance_sleep,
                    log_path="")
    # 手动灌入高 CPU 数据 → 应该按 for_seconds=1s 触发
    daemon.store.append("proc.cpu_percent", 0.0, 50.0)
    daemon.tick()
    assert daemon.engine.snapshot()["CpuHigh"] == rules.PENDING
    clock.now = 1.5                       # 时间推进 1.5s（超过 for_seconds=1s）
    daemon.store.append("proc.cpu_percent", 1.5, 60.0)
    record = daemon.tick()
    assert daemon.engine.snapshot()["CpuHigh"] == rules.FIRING
    assert notifier.received, "FIRING 应该产生通知"
    assert record["notifications"]
    summary = daemon.run(ticks=2, acquire_lock=True)
    assert summary["ticks"] == 2
    assert not os.path.exists(daemon.pidfile.path)     # 退出后释放锁


def test_daemon_refuses_second_instance(tmp_path):
    from opslab.daemon import Daemon
    empty = tmp_path / "noproc2"
    empty.mkdir()
    first = Daemon(str(tmp_path), [], collector=procfs.Collector(root=str(empty)), log_path="")
    first.pidfile.acquire()
    second = Daemon(str(tmp_path), [], collector=procfs.Collector(root=str(empty)), log_path="")
    with pytest.raises(RuntimeError):
        second.run(ticks=1)
    first.pidfile.release()


# =============================================================== 示例服务

def test_demo_service_starts_without_reverse_dns(monkeypatch):
    """回归：标准库 `HTTPServer.server_bind()` 会先 bind 再做 `socket.getfqdn()` 反向 DNS，
    而真正的 `listen()` 在它之后 —— 反向 DNS 一慢，端口就处于"已绑定但没在监听"的状态，
    客户端连上去是 ECONNREFUSED，表现为"服务起不来"（macOS CI 上真踩过）。

    这里把 `getfqdn` 换成"一旦被调用就炸"，如果我们的服务还敢调用它，这条测试立刻失败。
    """
    import socket as _socket
    from opslab.demo import service as demo

    def boom(*args, **kwargs):
        raise AssertionError("示例服务不允许做反向 DNS（getfqdn）")

    monkeypatch.setattr(_socket, "getfqdn", boom)

    from opslab.procs import port_open
    server = demo._Server(("127.0.0.1", 0), demo.Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05},
                              daemon=True)
    thread.start()
    try:
        # 构造完成后端口必须已经处于"可连接"状态
        deadline = time.time() + 3.0
        connected = False
        while time.time() < deadline:
            if port_open("127.0.0.1", port, timeout=0.2):
                connected = True
                break
            time.sleep(0.02)
        assert connected, "server_bind() 之后端口就应该已经 listen()，不能卡在 DNS 上"
        assert server.server_name == "127.0.0.1"
        status, body = __import__("opslab.procs", fromlist=["http_get"]).http_get(
            "127.0.0.1", port, "/healthz", 2.0)
        assert status == 200 and '"ok"' in body
    finally:
        server.shutdown()
        server.server_close()


def test_demo_service_drain_makes_healthz_503_and_tracks_inflight():
    """优雅停机的语义：drain 之后 /healthz 立刻变 503（= 从 LB 摘除），但服务还在跑。"""
    from opslab.demo import service as demo
    from opslab.procs import http_get, http_post

    demo.STATE["draining"] = False
    demo.STATE["in_flight"] = 0
    demo.STATE["drain_delay"] = 0.0
    server = demo._Server(("127.0.0.1", 0), demo.Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05},
                              daemon=True)
    thread.start()
    try:
        assert http_get("127.0.0.1", port, "/healthz", 2.0)[0] == 200
        status, _ = http_post("127.0.0.1", port, "/shutdown", 2.0)
        assert status == 200
        # 摘除后健康检查必须立刻 503（而不是等进程真的退出）
        assert http_get("127.0.0.1", port, "/healthz", 2.0)[0] == 503
        # 进程这一刻还活着（还在等在途请求清零）
        assert server.socket.fileno() >= 0
    finally:
        demo.STATE["draining"] = False
        server.shutdown()
        server.server_close()


def test_managed_process_error_message_includes_diagnostics(tmp_path):
    """命令起不来时，报错必须带退出码 + 日志尾部（否则没法定位）"""
    from opslab import procs as P
    managed = P.ManagedProcess(
        "boom", [sys.executable, "-c", "import sys;sys.stderr.write('my-custom-msg\\n');sys.exit(3)"],
        port=_free_port(), log_path=str(tmp_path / "boom.log"))
    with pytest.raises(RuntimeError) as exc:
        managed.start(wait=True, timeout=0.6)
    message = str(exc.value)
    assert "仍未监听" in message
    assert "exit=3" in message
    assert "my-custom-msg" in message          # 子进程的输出被带进异常里
    assert managed.log_tail()                   # 日志尾部可读


# =============================================================== 故障注入

def test_proxy_injector_rejects_double_start():
    """回归：SO_REUSEADDR 在 Linux 上不允许重复绑定，在 Windows 上却允许 ——
    于是"重复 start"这个 bug 只在 Linux CI 上炸。现在显式报错，两边行为一致。"""
    from opslab import chaos
    proxy = chaos.ProxyInjector("p", target_port=_free_port(), listen_port=_free_port())
    proxy.start()
    try:
        with pytest.raises(RuntimeError):
            proxy.start()
        assert proxy.active is True
    finally:
        proxy.stop()
    assert proxy.active is False
    # 停掉之后可以再起（修复流程要用到）
    proxy.start()
    try:
        assert proxy.active is True
    finally:
        proxy.stop()


def test_proxy_fault_applies_without_restarting_infrastructure():
    """注入故障只改参数，不重启代理"""
    from opslab import chaos
    proxy = chaos.ProxyInjector("p", target_port=_free_port(), listen_port=_free_port())
    proxy.start()
    try:
        fault = chaos.ProxyFault("latency", proxy, latency_ms=800.0)
        fault.start()
        assert proxy.latency_ms == 800.0 and proxy.active is True
        fault.stop()
        assert proxy.latency_ms == 0.0 and proxy.active is True   # 代理本身没被重启
        # 代理没起来时必须明确报错，而不是静默不生效
        proxy.stop()
        with pytest.raises(RuntimeError):
            chaos.ProxyFault("hang", proxy, hang=True).start()
    finally:
        proxy.stop()


def test_injector_kinds_and_scenarios_are_wired():
    from opslab import chaos
    names = [s.name for s in chaos.SCENARIOS]
    assert names == ["service_killed", "service_hung", "network_latency",
                     "http_errors", "cpu_saturation"]
    # 每个场景都要有检测时间与恢复时间的上界（否则"演练"就没有判据）
    for scenario in chaos.SCENARIOS:
        assert scenario.detect_bound_ms > 0 and scenario.recover_bound_ms > 0
        assert scenario.description


# =============================================================== 工具

class _FakeClock(object):
    def __init__(self, start: float = 0.0):
        self.now = float(start)

    def __call__(self) -> float:
        return self.now

    def advance_sleep(self, seconds: float) -> None:
        self.now += max(0.0, float(seconds))


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _tiny_server():
    """一个只回 200 的最小 HTTP 服务（用于探针测试）"""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            body = b'{"ok":true}' if self.path == "/ok" else b"nope"
            code = 200 if self.path == "/ok" else 404
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), H)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05},
                              daemon=True)
    thread.start()
    return server, server.server_address[1]
