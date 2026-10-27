from __future__ import annotations

import json
import os
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import stix2
from fastapi.testclient import TestClient

from mtip.api.app import create_app
from mtip.config import Settings
from mtip.service import Platform

TOKEN = "test-token-0123456789abcdef0123456789abcdef"


def make_bundle(families: int = 6, per_family: int = 8, apps_per_family: int = 3, start: datetime | None = None,
                spread_days: int = 0, extra: list | None = None, prefix: str = "fam") -> bytes:
    start = start or datetime(2025, 1, 1, tzinfo=timezone.utc)
    objects: list = []
    for f in range(families):
        malware = stix2.Malware(name=f"{prefix.title()}Family{f}", is_family=True)
        objects.append(malware)
        values = [("domain-name:value", f"node{j}.{prefix}{f}-cloudops.com") for j in range(per_family)]
        values += [("app:id", f"com.{prefix}{f}vendor.client{j}") for j in range(apps_per_family)]
        for j, (path, value) in enumerate(values):
            when = start + timedelta(days=(f * spread_days) + (j % 3 if spread_days else 0), seconds=j)
            ind = stix2.Indicator(pattern=f"[{path}='{value}']", pattern_type="stix", valid_from=when, created=when,
                                  modified=when, allow_custom=True)
            objects.append(ind)
            objects.append(stix2.Relationship(ind, "indicates", malware))
    objects.extend(extra or [])
    return stix2.Bundle(objects=objects, allow_custom=True).serialize().encode()


def unattributed_bundle(values: list[tuple[str, str]], when: datetime | None = None) -> bytes:
    when = when or datetime(2025, 3, 1, tzinfo=timezone.utc)
    def lit(v: str) -> str:
        return v.replace("\\", "\\\\").replace("'", "\\'")
    objs = [stix2.Indicator(pattern=f"[{p}='{lit(v)}']", pattern_type="stix", valid_from=when, created=when, modified=when, allow_custom=True)
            for p, v in values]
    return stix2.Bundle(objects=objs, allow_custom=True).serialize().encode()


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    return replace(Settings(), data_dir=tmp_path / "data", session_token=TOKEN, port=8765,
                   extra_trusted_hosts=("testserver",), rate_limit_per_minute=100_000)


@pytest.fixture()
def platform(settings: Settings):
    p = Platform(settings)
    yield p
    p.close()


@pytest.fixture()
def client(settings: Settings, platform: Platform):
    app = create_app(settings, platform)
    with TestClient(app, base_url="http://testserver") as c:
        yield c


@pytest.fixture()
def auth() -> dict:
    return {"X-MTIP-Token": TOKEN}


@pytest.fixture(scope="session")
def real_data_dir() -> Path | None:
    value = os.environ.get("MTIP_REAL_DATA")
    return Path(value) if value and Path(value).is_dir() else None


def wait_job(client: TestClient, job_id: str, timeout: float = 120.0) -> dict:
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = client.get(f"/api/v1/jobs/{job_id}").json()
        if job["status"] in ("complete", "failed"):
            return job
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def dumps(obj) -> bytes:
    return json.dumps(obj).encode()
