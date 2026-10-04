# -*- coding: utf-8 -*-
"""通知出口：控制台 / 文件 / Webhook / 录制（测试用）。

三个必须做对的细节：
  1. **超时**：通知是去调外部系统的，网络一卡不能把告警主循环拖死 → 全带 timeout。
  2. **重试 + 退避**：Webhook 失败必须重试，但**退避函数和 sleep 都注入**，
     否则测试要真等好几秒（而且 CI 上必然 flaky）。
  3. **失败不影响告警状态**：通知发不出去是通知的问题，不能让告警状态机回滚 ——
     所以 send() 返回 bool，调用方只统计不抛。
"""

import json
import os
import time
from typing import Callable, Dict, List, Optional, Sequence

try:
    import urllib.error
    import urllib.request
except ImportError:  # pragma: no cover
    urllib = None  # type: ignore


class Notifier(object):
    """通知出口基类"""

    name = "notifier"

    def __init__(self, retries: int = 0, backoff: float = 0.5, sleep: Callable = time.sleep):
        self.retries = int(retries)
        self.backoff = float(backoff)
        self.sleep = sleep
        self.attempts = 0
        self.failures = 0

    def deliver(self, note) -> bool:
        raise NotImplementedError

    def send(self, note) -> bool:
        last = False
        for attempt in range(self.retries + 1):
            self.attempts += 1
            try:
                last = bool(self.deliver(note))
            except Exception:
                last = False
            if last:
                return True
            if attempt < self.retries:
                self.sleep(self.backoff * (2 ** attempt))  # 指数退避
        self.failures += 1
        return False


class RecordingNotifier(Notifier):
    """把通知记在内存里 —— 测试和演练都用它，完全不碰网络。"""

    name = "recording"

    def __init__(self, fail_times: int = 0, **kw):
        Notifier.__init__(self, **kw)
        self.received: List[object] = []
        self.fail_times = int(fail_times)
        self._seen = 0

    def deliver(self, note) -> bool:
        self._seen += 1
        if self._seen <= self.fail_times:
            return False
        self.received.append(note)
        return True


class StdoutNotifier(Notifier):
    name = "stdout"

    def __init__(self, stream=None, **kw):
        Notifier.__init__(self, **kw)
        self.stream = stream
        self.lines: List[str] = []

    def deliver(self, note) -> bool:
        text = note.text()
        self.lines.append(text)
        if self.stream is not None:
            self.stream.write(text + "\n")
            self.stream.flush()
        return True


class FileNotifier(Notifier):
    """追加 JSON lines；适用于"通知先落盘，再由别的系统消费"。"""

    name = "file"

    def __init__(self, path: str, **kw):
        Notifier.__init__(self, **kw)
        self.path = path

    def deliver(self, note) -> bool:
        parent = os.path.dirname(os.path.abspath(self.path))
        if parent and not os.path.isdir(parent):
            os.makedirs(parent)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(note.as_dict(), ensure_ascii=False) + "\n")
        return True


class WebhookNotifier(Notifier):
    """POST JSON 到 Webhook（Slack / 钉钉 / 自建网关都能接）。"""

    name = "webhook"

    def __init__(self, url: str, timeout: float = 5.0, headers: Optional[Dict[str, str]] = None,
                 retries: int = 2, backoff: float = 0.5, sleep: Callable = time.sleep,
                 opener: Optional[Callable] = None):
        Notifier.__init__(self, retries=retries, backoff=backoff, sleep=sleep)
        self.url = url
        self.timeout = float(timeout)
        self.headers = dict(headers or {"Content-Type": "application/json"})
        self.opener = opener          # 注入的"发送函数"，测试里替换掉真实网络
        self.payloads: List[bytes] = []

    def _post(self, payload: bytes) -> bool:
        if self.opener is not None:
            return bool(self.opener(self.url, payload, self.timeout, self.headers))
        if urllib is None:  # pragma: no cover
            return False
        req = urllib.request.Request(self.url, data=payload, headers=self.headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return 200 <= resp.status < 300
        except (urllib.error.URLError, OSError):
            return False

    def deliver(self, note) -> bool:
        payload = json.dumps(note.as_dict(), ensure_ascii=False).encode("utf-8")
        self.payloads.append(payload)
        return self._post(payload)


class MultiNotifier(Notifier):
    """多路扇出：任意一路成功即算成功（但每一路都记自己的失败）。"""

    name = "multi"

    def __init__(self, notifiers: Sequence[Notifier], **kw):
        Notifier.__init__(self, **kw)
        self.notifiers = list(notifiers)

    def deliver(self, note) -> bool:
        results = [n.send(note) for n in self.notifiers]
        return any(results) if results else False
