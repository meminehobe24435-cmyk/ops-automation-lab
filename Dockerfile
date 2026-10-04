# 多阶段构建：builder 只用来产出 wheel，运行镜像里不带编译工具链与源码树
FROM python:3.12-slim AS builder

WORKDIR /build
COPY . /build
# 本项目运行时零第三方依赖 → 这一步不安装任何运行依赖，只打 wheel
RUN python -m pip install --no-cache-dir --upgrade pip build \
    && python -m build --wheel --outdir /dist

# ---------------------------------------------------------------- 运行镜像
FROM python:3.12-slim

LABEL org.opencontainers.image.title="ops-automation-lab" \
      org.opencontainers.image.description="运维自动化与可观测性工具链（零第三方依赖）" \
      org.opencontainers.image.source="https://github.com/meminehobe24435-cmyk/ops-automation-lab"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    OPSLAB_WORKDIR=/var/lib/opslab

# ① 非 root 运行：容器逃逸的影响面小一个数量级，这是运维侧的基本要求
# ② 固定 uid/gid 10001，方便在宿主机上给挂载卷设权限
RUN groupadd --gid 10001 opslab \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin opslab \
    && mkdir -p /var/lib/opslab \
    && chown -R opslab:opslab /var/lib/opslab

COPY --from=builder /dist/*.whl /tmp/
RUN python -m pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl

# 构建期就把"包能不能导入"验掉：缺模块应该在**构建阶段**红，而不是运行时空转
# （被测服务 `opslab.demo.service` 必须装进镜像，否则容器起来了但没人监听）
RUN python -c "import opslab, opslab.demo.service, opslab.cli; print('opslab', opslab.__version__, 'ok')"

USER opslab
WORKDIR /var/lib/opslab

EXPOSE 18080

# 镜像默认跑示例服务（一个真实可被探活/发布/演练的靶子）；
# 想跑 CLI 子命令就覆盖 CMD，例如：docker run --rm opslab collect
ENTRYPOINT ["python", "-m", "opslab"]
# ⚠️ --host 0.0.0.0 不能省：绑 127.0.0.1 的话端口只对容器**内部**可见，
#    `-p 18080:18080` 映射进来的连接会被 docker-proxy 直接重置
#    （curl 报 exit 56 / "Failure in receiving network data"）—— 排查时特别容易误判成 HTTP 层的问题
CMD ["demo-service", "--port", "18080", "--host", "0.0.0.0", "--version", "container"]

# HEALTHCHECK 用标准库直接打自己的健康检查端点：
# 容器里 healthcheck 失败会被编排系统看到（docker ps 显示 unhealthy / compose 触发重启）
HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=3 \
    CMD python -c "import sys,urllib.request;\
r=urllib.request.urlopen('http://127.0.0.1:18080/healthz',timeout=2);\
sys.exit(0 if r.status==200 else 1)"
