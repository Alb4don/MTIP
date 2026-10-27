from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import socket
import threading
import time
from collections import deque
from dataclasses import dataclass
from urllib.parse import urlsplit

from .logging_setup import get_logger

sec_log = get_logger("security")


class InputRejected(ValueError):
    def __init__(self, public_message: str, category: str = "validation"):
        super().__init__(public_message)
        self.public_message = public_message
        self.category = category


def check_json_depth(data: bytes, max_depth: int) -> None:
    depth = 0
    in_string = False
    escape = False
    for byte in data:
        if in_string:
            if escape:
                escape = False
            elif byte == 0x5C:
                escape = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in (0x7B, 0x5B):
            depth += 1
            if depth > max_depth:
                raise InputRejected("document nesting is too deep", "resource")
        elif byte in (0x7D, 0x5D):
            depth -= 1


_ATTACK_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    ("sqli", re.compile(r"(?i)(\b(union\s+(all\s+)?select|select\s+.+\s+from|insert\s+into|drop\s+table|delete\s+from|update\s+\w+\s+set)\b|'\s*(or|and)\s+'?\d|--\s*$|;\s*(drop|shutdown|exec)\b|\bsleep\s*\(\s*\d|\bwaitfor\s+delay\b|\bpragma\b)")),
    ("xss", re.compile(r"(?i)(<\s*script|<\s*/\s*script|javascript\s*:|on(error|load|click|mouseover|focus)\s*=|<\s*iframe|<\s*svg[^>]*on\w+|srcdoc\s*=)")),
    ("path_traversal", re.compile(r"(\.\./|\.\.\\|%2e%2e(%2f|%5c|/|\\)|\x00|%00)", re.IGNORECASE)),
    ("template_injection", re.compile(r"(\{\{.*\}\}|\$\{.*\}|<%.*%>|#\{.*\})")),
    ("command_injection", re.compile(r"(;\s*(rm|cat|curl|wget|bash|sh|powershell|cmd)\b|\|\s*(sh|bash|nc|powershell)\b|`[^`]+`|\$\([^)]+\))", re.IGNORECASE)),
    ("ldap_nosql", re.compile(r"(\$where|\$ne\b|\$gt\b|\$regex|\(\|\(|\*\)\()")),
]


def detect_attack(value: str) -> str | None:
    if not value:
        return None
    sample = value[:4096]
    for category, pattern in _ATTACK_SIGNATURES:
        if pattern.search(sample):
            return category
    return None


_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def validate_search_text(text: str, max_len: int = 200) -> str:
    text = text.strip()
    if len(text) > max_len:
        raise InputRejected("search text is too long")
    if _CONTROL_CHARS.search(text):
        raise InputRejected("search text contains control characters")
    return text


def escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _ip_is_public(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return not (
        address.is_private or address.is_loopback or address.is_link_local or address.is_multicast
        or address.is_reserved or address.is_unspecified or not address.is_global
    )


def validate_outbound_url(url: str, allow_private: bool = False) -> str:
    if not isinstance(url, str) or len(url) > 2048:
        raise InputRejected("server address is invalid")
    if detect_attack(url) in ("xss", "path_traversal", "command_injection", "template_injection"):
        raise InputRejected("server address is invalid", "ssrf")
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError as exc:
        raise InputRejected("server address is invalid") from exc
    if parts.scheme != "https":
        raise InputRejected("server address must use https")
    if parts.username or parts.password:
        raise InputRejected("credentials must not be embedded in the address", "ssrf")
    host = parts.hostname
    if not host:
        raise InputRejected("server address is invalid")
    if port is not None and not (1 <= port <= 65535):
        raise InputRejected("server address is invalid")
    if not allow_private:
        try:
            infos = socket.getaddrinfo(host, port or 443, proto=socket.IPPROTO_TCP)
        except (socket.gaierror, UnicodeError, OSError) as exc:
            raise InputRejected("server address could not be resolved") from exc
        for info in infos:
            address = ipaddress.ip_address(info[4][0].split("%")[0])
            if not _ip_is_public(address):
                raise InputRejected("server address points to a private or local network", "ssrf")
    return parts.geturl()


def client_fingerprint(client_ip: str, salt: str) -> str:
    return hmac.new(salt.encode(), client_ip.encode(), hashlib.sha256).hexdigest()[:16]


@dataclass
class _Bucket:
    tokens: float
    updated: float


class RateLimiter:
    def __init__(self, per_minute: int, burst: int | None = None):
        self.rate = per_minute / 60.0
        self.capacity = float(burst or max(10, per_minute // 4))
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, cost: float = 1.0) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(self.capacity, now)
                self._buckets[key] = bucket
            bucket.tokens = min(self.capacity, bucket.tokens + (now - bucket.updated) * self.rate)
            bucket.updated = now
            if bucket.tokens >= cost:
                bucket.tokens -= cost
                return True
            if len(self._buckets) > 10_000:
                self._buckets = {k: v for k, v in self._buckets.items() if now - v.updated < 600}
            return False


class StrikeTracker:
    def __init__(self, threshold: int, block_seconds: int, window_seconds: int = 600):
        self.threshold = threshold
        self.block_seconds = block_seconds
        self.window = window_seconds
        self._strikes: dict[str, deque[float]] = {}
        self._blocked: dict[str, float] = {}
        self._lock = threading.Lock()

    def is_blocked(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            until = self._blocked.get(key)
            if until is None:
                return False
            if now >= until:
                del self._blocked[key]
                self._strikes.pop(key, None)
                return False
            return True

    def strike(self, key: str, weight: int = 1) -> bool:
        now = time.monotonic()
        with self._lock:
            history = self._strikes.setdefault(key, deque())
            for _ in range(weight):
                history.append(now)
            while history and now - history[0] > self.window:
                history.popleft()
            if len(history) >= self.threshold:
                self._blocked[key] = now + self.block_seconds
                return True
            return False
