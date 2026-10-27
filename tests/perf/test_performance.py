import statistics
import time

import pytest

from mtip.correlate.engine import EngineParams
from tests.conftest import make_bundle


@pytest.fixture()
def loaded(platform):
    platform.importer.import_bytes(make_bundle(families=60, per_family=80, apps_per_family=20), "perf-feed")
    return platform


def test_import_throughput(platform):
    data = make_bundle(families=40, per_family=100, apps_per_family=25)
    start = time.perf_counter()
    report = platform.importer.import_bytes(data, "perf")
    elapsed = time.perf_counter() - start
    assert report.indicators_new == 40 * 125
    assert elapsed < 30, elapsed


def test_correlation_runtime(loaded):
    start = time.perf_counter()
    result = loaded.engine.run(EngineParams(holdout_reps=2))
    elapsed = time.perf_counter() - start
    assert result.stats["indicators"] == 6000
    assert elapsed < 30, elapsed


def test_api_latency(client, platform):
    platform.importer.import_bytes(make_bundle(families=30, per_family=60, apps_per_family=10), "perf")
    platform.engine.run(EngineParams(holdout_reps=1))
    timings = {}
    for path in ("/api/v1/health", "/api/v1/indicators?limit=50", "/api/v1/indicators?search=node1&limit=50",
                 "/api/v1/inferences?limit=50", "/api/v1/overview", "/api/v1/graph"):
        samples = []
        for _ in range(8):
            t = time.perf_counter()
            assert client.get(path).status_code == 200
            samples.append(time.perf_counter() - t)
        timings[path] = statistics.median(samples)
    assert max(timings.values()) < 1.5, timings
