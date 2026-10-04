# -*- coding: utf-8 -*-
"""结构化日志：JSON lines 输出、正则解析、轮转、关键字事件。

线上排障最花时间的不是"没有日志"，而是"日志搜不动"：
  - 一行里混着时间戳、级别、请求 id、耗时、错误码 → 只能靠肉眼和一堆 grep
  - 出故障时日志文件涨到几个 G，`tail` 都要等半天
  - 出问题的那台机器刚好把日志轮转掉了

所以这里给三件东西：
  ① **JsonFormatter**：一行一个 JSON，字段固定（ts/level/logger/msg + 自定义 kv），
     可以直接被 jq / 日志平台解析；
  ② **LineParser**：给**别人写的**、格式不统一的日志做正则解析（真实运维现场必然遇到），
     解析失败的行走 fallback 而不是丢掉 —— 丢日志比解析失败严重；
  ③ **RotatingWriter**：按大小轮转 + 保留 N 个备份，并且**轮转时不丢写**（先切文件再写当前行）。
"""

import io
import json
import logging
import os
import re
import time
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


def json_line(level: str, msg: str, ts: Optional[float] = None, logger: str = "opslab",
              **fields) -> str:
    """一行结构化日志（字段顺序稳定，便于按行 diff）"""
    payload = {
        "ts": round(float(ts if ts is not None else time.time()), 6),
        "level": level.upper(),
        "logger": logger,
        "msg": msg,
    }
    for key in sorted(fields):
        if fields[key] is not None:
            payload[key] = fields[key]
    return json.dumps(payload, ensure_ascii=False, sort_keys=False)


class JsonFormatter(logging.Formatter):
    """挂到标准库 logging 上：`logging.getLogger(...).info("x", extra={"kv": {...}})`"""

    def format(self, record: logging.LogRecord) -> str:
        fields = getattr(record, "kv", None) or {}
        return json_line(record.levelname, record.getMessage(),
                         ts=record.created, logger=record.name, **fields)


class LineParser(object):
    """把非结构化日志行解析成 dict。

    每种格式给一组**命名组**正则；按顺序试，第一个匹配的胜出。
    全都不匹配 → `{"raw": line, "parsed": False}`（**保留原文，绝不丢**）。
    """

    def __init__(self, patterns: Sequence[Tuple[str, str]], clock=None):
        self.patterns = [(name, re.compile(rx)) for name, rx in patterns]
        self.clock = clock or time.time
        self.stats = {"parsed": 0, "raw": 0}

    def parse(self, line: str) -> Dict:
        text = line.rstrip("\n")
        for name, rx in self.patterns:
            match = rx.search(text)
            if match:
                self.stats["parsed"] += 1
                data = {k: v for k, v in match.groupdict().items() if v is not None}
                data["format"] = name
                data["raw"] = text
                return data
        self.stats["raw"] += 1
        return {"raw": text, "parsed": False}

    def parse_stream(self, lines: Iterable[str]) -> List[Dict]:
        return [self.parse(line) for line in lines if line.strip()]


# 两个现成的解析器（运维现场最常见的两种）
NGINX_COMBINED = (
    "nginx",
    r'(?P<remote>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+) [^"]*" '
    r'(?P<status>\d{3}) (?P<bytes>\d+)',
)
SYSLOG_STYLE = (
    "syslog",
    r'^(?P<time>\w{3}\s+\d+ \d+:\d+:\d+) (?P<host>\S+) (?P<proc>[\w\-\./]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$',
)
PYTHON_TRACEBACK = (
    "traceback",
    r'^(?P<exc>[\w\.]*(?:Error|Exception|Warning)): (?P<msg>.*)$',
)


class KeywordTrigger(object):
    """关键字 → 事件。用于"日志里出现 OOM / timeout / panic 就要报警"这种规则。

    匹配大小写不敏感；每个关键字单独计数，并记录**命中次数**（不是只记第一次），
    否则"1 分钟 5000 次 timeout"和"1 次 timeout"看起来会一样严重。
    """

    def __init__(self, keywords: Sequence[str], level: str = "ERROR"):
        self.keywords = [k.lower() for k in keywords]
        self.level = level.upper()
        self.counts: Dict[str, int] = {k: 0 for k in self.keywords}
        self.hits: List[Dict] = []

    def feed(self, parsed: Dict, ts: Optional[float] = None) -> List[Dict]:
        text = (parsed.get("raw") or "").lower()
        found = []
        for keyword in self.keywords:
            if keyword in text:
                self.counts[keyword] += 1
                event = {"ts": float(ts if ts is not None else time.time()),
                         "keyword": keyword, "level": self.level, "line": parsed.get("raw", "")[:200]}
                self.hits.append(event)
                found.append(event)
        return found


class RotatingWriter(object):
    """按大小轮转的写入器（`log` → `log.1` → `log.2` …，超过 backups 的最旧一个被删）。

    写路径是「先判断要不要轮转、再写当前行」，所以**单行不会跨文件被截断**。
    """

    def __init__(self, path: str, max_bytes: int = 1 << 20, backups: int = 3, clock=None):
        if max_bytes <= 0:
            raise ValueError("max_bytes 必须为正")
        self.path = os.path.abspath(path)
        self.max_bytes = int(max_bytes)
        self.backups = int(backups)
        self.clock = clock or time.time
        self.rotations = 0
        self.bytes_written = 0
        parent = os.path.dirname(self.path)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent)
        self._fh = io.open(self.path, "a", encoding="utf-8", newline="\n")

    def _size(self) -> int:
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0

    def should_rotate(self, incoming: int) -> bool:
        return self._size() + incoming > self.max_bytes

    def rotate(self) -> None:
        self._fh.close()
        # 从最旧往新搬：log.(n-1) → log.n
        for idx in range(self.backups - 1, 0, -1):
            src = "%s.%d" % (self.path, idx)
            dst = "%s.%d" % (self.path, idx + 1)
            if os.path.exists(src):
                os.replace(src, dst)
        if self.backups >= 1 and os.path.exists(self.path):
            os.replace(self.path, "%s.1" % self.path)
        self._fh = io.open(self.path, "a", encoding="utf-8", newline="\n")
        self.rotations += 1

    def write(self, line: str) -> None:
        data = line if line.endswith("\n") else line + "\n"
        raw = data.encode("utf-8")
        if self.should_rotate(len(raw)):
            self.rotate()
        self._fh.write(data)
        self._fh.flush()          # 掉电时也要能拿到最后一行
        self.bytes_written += len(raw)

    def backups_on_disk(self) -> List[str]:
        found = []
        for idx in range(1, self.backups + 1):
            candidate = "%s.%d" % (self.path, idx)
            if os.path.exists(candidate):
                found.append(candidate)
        return found

    def close(self) -> None:
        if not self._fh.closed:
            self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def setup_logging(level: str = "INFO", stream=None, path: Optional[str] = None,
                  max_bytes: int = 1 << 20, backups: int = 3) -> logging.Logger:
    """给 CLI 用的日志装配：结构化到文件、人手可读/JSON 到控制台。"""
    logger = logging.getLogger("opslab")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    if stream is not None:
        sh = logging.StreamHandler(stream)
        sh.setFormatter(JsonFormatter())
        logger.addHandler(sh)
    if path:
        writer = RotatingWriter(path, max_bytes=max_bytes, backups=backups)

        class _Handler(logging.Handler):
            def emit(self, record):
                try:
                    writer.write(JsonFormatter().format(record))
                except Exception:
                    pass

        logger.addHandler(_Handler())
    return logger
