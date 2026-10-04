# ops-automation-lab

> 运维自动化与可观测性工具链：**指标采集 → 告警治理 → 健康检查 → 应急预案 → 故障演练 → 滚动发布**
> **Python 3 标准库零依赖** · **66 项单元测试** · **5 类故障演练全部自动检测并恢复** · **滚动发布期间可用性 100%** · **Docker 容器化 + CI 四平台矩阵**

这不是一个"CRUD 练习项目"，而是把**运维岗每天真正要处理的七件事**各实现一遍，
并且**每一件都给出可对账的数字**：检测延迟多少毫秒、MTTR 多少毫秒、告警被压缩掉多少条、
坏版本发布时门禁拦不拦得住、回滚要多久。

---

## 一、为什么写这个

一份运维/SRE 岗位的职责通常长这样：

> 参与系统日常运维、监控告警及故障排查 · 参与运维自动化工具建设 · 参与制定运维规范、应急预案及故障演练

这三句话对应的能力，**用"我搭过服务器"是证明不了的**。所以我把它们都做成了可运行、可验证的东西：

| 职责 | 本项目里的对应实现 | 可对账的证据 |
|---|---|---|
| 监控告警 | `/proc` 指标采集 + 时序聚合 + 告警状态机 + 去重/分组/抑制/静默 | 100 次异常采样 → **1 条通知**（噪声压缩 99%） |
| 故障排查 | 健康检查（HTTP/TCP/进程/文件/命令）+ 连续失败判定 + **探针硬超时** | 挂死端点 **在超时内**被判失败，不会把监控自己拖死 |
| 运维自动化工具 | 采集/评估/通知一体的守护进程 + CLI + **应急预案剧本 DSL** | 剧本每步都有耗时与退出码，可回放 |
| 应急预案 | JSON 剧本：检查 → 处置 → 验证 → **回滚链**，含超时/幂等/dry-run | 剧本失败自动回滚，步骤状态全留痕 |
| 故障演练 | 5 类故障注入器 + 演练报告 | **5/5 场景通过**，检测均值 ~1.0s、MTTR 均值 ~2.4s |
| 部署上线 | 滚动重启 + 优雅停机（drain）+ 健康门禁 + 失败自动回滚 | 发布期 **110 次请求成功率 100%**；坏版本 **842ms 回滚** |
| 容器 | 多阶段 Dockerfile（非 root + HEALTHCHECK）+ compose | CI 里验证 uid≠0、healthy、SIGTERM 后**退出码 0** |

---

## 二、快速开始

```bash
# 零依赖：不用装任何东西（Python 3.8+）
python -m opslab --help

# ① 采指标（Linux 读真 /proc；其它平台用仓库自带的样本）
python -m opslab collect --root tests/fixtures/proc

# ② 起一个被监控的示例服务，然后探活
python -m opslab demo-service --port 18080 &
python -m opslab check --port 18080 --count 3 --interval 0.5

# ③ 守护进程：采集 + 告警 + 通知（跑 5 轮后**优雅收尾**）
python -m opslab watch --workdir reports/watch --ticks 5 --interval 0.5

# ④ 故障演练：注入 5 类故障，量出检测时间与 MTTR
python -m opslab drill --workdir reports/drill --out reports

# ⑤ 滚动发布演练；--bad 用来演练"新版本是坏的"
python -m opslab deploy --workdir reports/deploy --out reports
python -m opslab deploy --workdir reports/deploy_bad --out reports --bad

# ⑥ 容器
docker build -t opslab .
docker compose up --build
```

### 本机实测输出（Windows / Python 3.8；数值随机器与负载浮动）

```
$ python -m opslab drill --out reports
service_killed   PASS detect= 1409.2ms mttr= 3118.1ms  ServiceDown
service_hung     PASS detect= 1438.5ms mttr= 2828.6ms  ServiceDown
network_latency  PASS detect= 1445.5ms mttr= 2904.1ms  ServiceDown
http_errors      PASS detect=  187.6ms mttr=  972.0ms  ServiceDown
cpu_saturation   PASS detect=  746.0ms mttr= 1934.3ms  ProcessCpuHigh
合计 5/5 通过；检测均值 1045.3ms（最差 1445.5ms）；MTTR 均值 2351.4ms（最差 3118.1ms）

$ python -m opslab deploy --out reports
发布 rolling：门禁=通过 可用性=100.00%（17 次请求，失败 0，对用户透明的重试 4）回滚=否

$ python -m opslab deploy --out reports --bad
发布 rolling：门禁=拦截（i1: 健康门禁超时：HTTP 500（期望 [200]））
              可用性=100.00%（110 次请求，失败 0，对用户透明的重试 52）回滚=是（842ms）
坏版本演练通过：门禁拦停 + 自动回滚 842ms，发布期间可用性 100.00%
```

---

## 三、模块地图

```
opslab/
  procfs.py    指标采集：解析 /proc（CPU/内存/负载/磁盘/网络）+ 跨平台进程 CPU 采样器
  tsdb.py      时序存储：定容环形缓冲 + 时间窗口聚合（avg/min/max/p50/p90/p95/p99/stddev/rate）
  rules.py     告警规则：阈值 + 持续时长 + 状态机（INACTIVE→PENDING→FIRING→RESOLVED）+ absent
  alerting.py  告警治理：去重 / 分组 / 抑制 / 静默 + 噪声压缩比统计
  health.py    健康检查：HTTP / TCP / 进程 / 文件新鲜度 / 命令 + rise/fall 判定 + 硬超时
  logs.py      结构化日志：JSON lines、正则解析、关键字事件、按大小轮转
  notify.py    通知出口：控制台 / 文件 / Webhook / 录制（测试用），带超时与指数退避重试
  playbook.py  应急预案：JSON 剧本 DSL，超时 / 幂等(skip_if) / dry-run / 回滚链 / 非阻塞诊断步
  chaos.py     故障演练：延迟 / 错误率 / 挂死 / 杀进程 / CPU 占满 + 演练报告（检测·恢复·MTTR）
  deploy.py    发布编排：滚动重启 + 优雅停机 + 健康门禁 + 失败自动回滚 + 可用性度量
  daemon.py    常驻守护：单实例锁 + 信号处理（SIGTERM 优雅退出 / SIGHUP 重载）+ 主循环
  procs.py     子进程管理：启动 / 探活 / 优雅停机（drain → 等在途请求 → 退出）/ 强制回收
  cli.py       命令行入口
  demo/service.py  被管理的示例服务（/healthz /metrics /version /work /shutdown）
```

### 两个让整个项目可测试的设计决定

1. **一切外部输入都可注入**：`/proc` 的根目录、时钟、睡眠、探针、通知出口、子进程启动器全部可替换。
   → "时间推进 30 秒让告警从 PENDING 变 FIRING" 这种断言是**确定性的**，不靠 `sleep` 撞运气（CI 上不会 flaky）。
2. **运行时零第三方依赖**：只用标准库。CI 里有一条 AST 依赖检查，
   任何偷偷引入的 `psutil` / `requests` / `yaml` / `prometheus_client` 都会让流水线红。

---

## 四、几个关键设计（也是面试会问的）

### 4.1 告警为什么要状态机，而不是 `if cpu > 85: 报警`

因为后者**吵**。一次 3 秒的毛刺推一条通知，值班的人很快就被训练成不看告警。

```
       条件为真                 持续 >= for_seconds
  INACTIVE ──────► PENDING ──────────────────────► FIRING
      ▲               │                              │
      │  条件变假      │ 条件变假（抖动，一条都不发）    │ 条件变假
      └───────────────┘                              ▼
                                                  RESOLVED（通知一次）
```

- `for_seconds=0` → 立即 FIRING
- **PENDING 阶段条件变假 → 回 INACTIVE，零通知**（这就是抖动抑制）
- FIRING 后恢复 → RESOLVED 并通知一次（否则值班的人永远不知道恢复了）
- 指标**没有数据**用 `op="absent"` 单独表达：采集挂了本身就是故障，不能因为"没值可比较"就静默
  —— 这是监控系统最经典的自杀方式

### 4.2 抑制（inhibit）不是可选功能

一次机架掉电会产生几百条告警，其中真正有信息量的只有最上面那条"节点不可达"。
抑制规则把人从"300 条通知"捞回"1 条通知 + 299 条已抑制"。
本项目的顺序是：**去重 → 静默 → 抑制 → 分组 → 发送**（顺序会影响语义，所以写死在文档里）。

### 4.3 "零停机发布"靠的不是"重启得快"

而是三件事同时成立：

1. **滚动**：一次只动一个实例，其余实例继续扛流量（所以至少 2 个实例）
2. **优雅停机**：实例退出前先从 LB 摘除（`/healthz → 503`）、**等在途请求跑完**（`in_flight → 0`）再退出
3. **健康门禁**：新实例必须**连续 N 次**通过健康检查才算发布成功，否则立刻回滚
   —— 而不是"进程起来了就算成功"（这是最常见的自欺：**进程活着，接口 500**）

所以才有 `--bad` 这条演练路径：发布的进程是"活着但接口 500"的，验证门禁能不能拦住、回滚要多久。

### 4.4 可用性的口径

**单个实例下线 ≠ 服务不可用**，只有所有实例都不可用时用户才真的受影响。
所以可用性是在**路由层**真实发请求量出来的，并且区分两个数：

- `requests` / `failed` → **用户视角**的请求数与失败数
- `retries` → 实例级重试次数（对用户透明）

> 第一版把"在某台实例上的一次尝试"也算成一次用户请求，结果每次请求都被重试到健康实例上成功了、
> 用户毫无感知，算出来的可用性却只有 70%。**数字看着吓人，其实是把重试当成了失败。**

---

## 五、开发过程中被测试/工具抓出来的 10 个真问题

写这个项目的过程比结果更值得说 —— 这 10 个问题**没有一个是"想"出来的**，全是跑出来的：

| # | 问题 | 为什么会发生 | 修法 |
|---|---|---|---|
| 1 | **PENDING 永远升不到 FIRING** | `st.pending_since or ts` —— `pending_since` 可能是 `0.0`，而 `0.0 or ts` 取的是 `ts`，于是"持续了多久"永远算成 0 | 改成显式判 `is not None`（假值为 0 的经典坑） |
| 2 | **派生指标名互相覆盖** | 用 `key.rsplit(".",1)[0] + ".rate"` 把 `net.eth0.rx_bytes` 变成了 `net.eth0.rate`，rx 和 tx 撞名 | 保留原计数器名：`key + ".rate"` |
| 3 | **计数器重置后速率明显偏小** | `rate = (末值-首值)/dt`，窗口里只要重启过一次，重启前的量全丢 | 按 Prometheus 口径**累加正向增量**，遇重置把当前值算作增量 |
| 4 | **CPU 饱和场景预案判失败** | "确认服务已不可用"这一步在该场景本来就不该成立（服务是活的），但它失败导致整个剧本算失败 | 引入 `blocking=False`：诊断类步骤失败只记录，不判定处置失败 |
| 5 | **日志路径不存在直接崩在 Popen 里** | 调用方给相对路径 `reports/deploy/xxx.log`，目录还没建 | 在 `ManagedProcess.start()` 里建父目录（在这一层修，所有调用方都受益） |
| 6 | **两个 `AlertManager` 互相抑制** | `_firing_labels` 写成了**类属性** → 所有实例共享同一个 dict | 移到 `__init__` 里做实例属性，并补了一条回归测试 |
| 7 | **挂死端点会让探针永久阻塞** | 连接建得起来、对方一个字节都不回，没有 socket 超时就会一直挂 | 所有探针带硬超时，并有一条测试专门卡"检测时间上界" |
| 8 | **容器里 bind 127.0.0.1 导致端口映射失效** | 服务只监听容器**内部**的 loopback，`-p 18080:18080` 进来的连接被 docker-proxy 直接重置，curl 报 **exit 56** —— 看起来像 HTTP 层坏了，其实是网络命名空间的事 | 容器内显式 `--host 0.0.0.0`；CI 失败时先 `docker logs` + `docker exec` 自诊断，别只盯着 curl 退出码 |
| 9 | **`SO_REUSEADDR` 的语义在 Linux / Windows 上不一样** | Windows 允许两个 socket 绑同一个端口（于是"重复启动注入器"这个 bug 在 Windows 上**看起来能用**），Linux 上直接 `OSError` 起不来。同一个 bug，本地全绿、**Linux CI 上 3 个演练全红** | 注入器改成"就地改参数、不重启基础设施"，并让重复 `start()` **显式报错**，让两边行为一致 |
| 10 | **容器 HEALTHCHECK 里又启动了一个服务** | 把"起服务"和"探活"写进了同一条命令，healthcheck 永不返回 | 拆开：服务是 CMD，探活用标准库 `urllib` 单独打 `/healthz` |

另外两个属于"设计层面的判断错误"，值得单独记：

- **负载均衡的可用性口径**（见 4.4）：把重试当失败 → 数字虚低。
  → 教训：**先想清楚一个指标的分母是什么**，再写代码。
- **分布/偏斜类的阈值不能写死**：最初写死"偏斜 < 1.25x"，但理论值在虚拟节点少的时候本来就大。
  → 改成断言"**随参数单调改善**"，这样断言不会因为参数选得不对而变成假绿或假红。

---

## 六、边界（面试必被追问，如实说）

1. **单机、单进程**：它是"一台机器上的运维工具链"，**没有 agent 集群、没有中心化存储、
   没有多机聚合、没有高可用**。生产级方案（Prometheus + Alertmanager + 编排系统）解决的是这些。
2. **指标来源是 `/proc` 与自采**：没有 eBPF / cgroup v2 / 内核 tracepoint / APM 探针，
   也不做分布式链路追踪。
3. **示例服务是自己写的靶子**：演练里的"服务"是标准库 HTTP 服务（≤200 行），
   不是真实业务系统；故障注入是**代理式 + 进程级**，不是内核级（没有 netem / tc / cgroup 限流）。
4. **通知出口只实现了控制台/文件/Webhook**：没有对接真实 IM/短信/电话告警，
   也没有告警升级（escalation）与值班排班（on-call schedule）。
5. **Docker 用法是"能构建、能跑、非 root、HEALTHCHECK 生效、SIGTERM 后退出码 0"**：
   **没有 K8s / Helm / 服务网格 / 云平台（AWS/Azure）实操经验**，也没做过镜像瘦身与漏洞扫描。
6. **性能数字都是本机自测**（Windows、单机、`--ticks` 有限轮），不代表生产吞吐；
   守护进程跑的是秒级采集，**没做过大规模并发与长稳定性测试**。
7. 演练的 MTTR 包含"预案执行"的时间，而预案是**本项目自己写的**（重启/重建代理/取消负载），
   所以这个 MTTR **不能等同于真实业务的恢复时间**。

---

## 七、测试与 CI

```
tests/test_opslab.py   66 项：/proc 解析（手算对账）· 时序聚合与分位数 · 告警状态机与抖动抑制
                       告警去重/抑制/静默/分组 · 探针超时上界 · 日志轮转与解析 · 剧本超时/幂等/dry-run/回滚
                       守护进程单实例锁与优雅收尾 · 回归用例（类属性共享、pending_since=0）
```

CI 四件事（`.github/workflows/ci.yml`）：

1. **单元测试**：ubuntu / windows / macos × Python 3.9 / 3.12 六矩阵
2. **故障演练 + 滚动发布 + 坏版本回滚 + 守护进程冒烟**：全部当作**测试**跑，红了就是红的
3. **静态检查**：语法编译检查 + **AST 依赖检查**（运行时只允许标准库）
4. **容器**：构建镜像 → 验证 **uid≠0** → 起容器 → **HEALTHCHECK 变 healthy** → `SIGTERM` 后**退出码 0**

---

## 八、许可

MIT
