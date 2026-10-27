from __future__ import annotations

import os
import secrets
import sys
from dataclasses import dataclass, field
from pathlib import Path


def _default_data_dir() -> Path:
    override = os.environ.get("MTIP_DATA_DIR")
    if override:
        return Path(override).expanduser().resolve()
    if sys.platform.startswith("win"):
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "MTIP"
    xdg = os.environ.get("XDG_DATA_HOME")
    return (Path(xdg) if xdg else Path.home() / ".local" / "share") / "mtip"


def _env_int(name: str, default: int, low: int, high: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(low, min(high, value))


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    data_dir: Path = field(default_factory=_default_data_dir)
    host: str = "127.0.0.1"
    port: int = field(default_factory=lambda: _env_int("MTIP_PORT", 8765, 1024, 65535))
    max_upload_bytes: int = field(default_factory=lambda: _env_int("MTIP_MAX_UPLOAD_MB", 64, 1, 512) * 1024 * 1024)
    max_json_depth: int = 64
    max_objects_per_bundle: int = 250_000
    rate_limit_per_minute: int = field(default_factory=lambda: _env_int("MTIP_RATE_LIMIT", 600, 30, 100_000))
    strike_threshold: int = 5
    block_seconds: int = 900
    allow_private_taxii: bool = field(default_factory=lambda: _env_bool("MTIP_ALLOW_PRIVATE_TAXII", False))
    taxii_timeout_seconds: int = 30
    taxii_max_pages: int = 200
    session_token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    extra_trusted_hosts: tuple[str, ...] = ()

    @property
    def db_path(self) -> Path:
        return self.data_dir / "mtip.sqlite3"

    @property
    def log_dir(self) -> Path:
        return self.data_dir / "logs"

    @property
    def backup_dir(self) -> Path:
        return self.data_dir / "backups"

    @property
    def psl_path(self) -> Path:
        return self.data_dir / "public_suffix_list.dat"

    def ensure_dirs(self) -> None:
        for directory in (self.data_dir, self.log_dir, self.backup_dir):
            directory.mkdir(parents=True, exist_ok=True)
            if not sys.platform.startswith("win"):
                try:
                    os.chmod(directory, 0o700)
                except OSError:
                    pass
