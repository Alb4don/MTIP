from __future__ import annotations

import logging
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path

_SECRET_PATTERNS = [
    (re.compile(r"(?i)(authorization\s*[:=]\s*)(bearer\s+|basic\s+)?[^\s,;]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b(api[_-]?key|token|secret|password|passwd|pwd|session|cookie)(\s*[:=]\s*)[^\s,;&]+"), r"\1\2[REDACTED]"),
    (re.compile(r"(?i)(https?://)[^/\s:@]+:[^/\s@]+@"), r"\1[REDACTED]@"),
    (re.compile(r"(?i)([?&](?:key|token|apikey|api_key|access_token|sig|signature)=)[^&\s]+"), r"\1[REDACTED]"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[EMAIL]"),
    (re.compile(r"(?i)(?:[a-z]:\\users\\|/home/|/users/)[^\\/\s]+"), "[HOME]"),
]
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_MAX_LEN = 2000


def redact(text: str) -> str:
    text = _CONTROL.sub(" ", str(text)).replace("\n", "\\n").replace("\r", "\\r")
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    if len(text) > _MAX_LEN:
        text = text[:_MAX_LEN] + "...[truncated]"
    return text


class RedactingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        record.msg = redact(record.getMessage())
        record.args = None
        if record.exc_info:
            record.exc_text = None
        rendered = super().format(record)
        return redact(rendered) if record.exc_info else rendered

    def formatException(self, ei) -> str:
        exc_type, exc_value, _ = ei
        name = exc_type.__name__ if exc_type else "Exception"
        return f"exception={name}"


_configured = False


def configure_logging(log_dir: Path, level: int = logging.INFO) -> None:
    global _configured
    if _configured:
        return
    log_dir.mkdir(parents=True, exist_ok=True)
    formatter = RedactingFormatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    file_handler = RotatingFileHandler(log_dir / "mtip.log", maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
    file_handler.setFormatter(formatter)
    security_handler = RotatingFileHandler(log_dir / "security.log", maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
    security_handler.setFormatter(formatter)
    root = logging.getLogger("mtip")
    root.setLevel(level)
    root.addHandler(file_handler)
    root.propagate = False
    sec = logging.getLogger("mtip.security")
    sec.addHandler(security_handler)
    for noisy in ("uvicorn.access",):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    _configured = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"mtip.{name}")
