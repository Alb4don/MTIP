from pathlib import Path

import pytest

from mtip.correlate.engine import REL_CONFLICT, EngineParams


def _feeds(root: Path) -> list[tuple[str, Path]]:
    feeds = []
    stalker = root / "stalkerware-indicators" / "generated" / "stalkerware.stix2"
    if stalker.is_file():
        feeds.append(("stalkerware-indicators", stalker))
    attack = root / "mobile-attack.json"
    if attack.is_file():
        feeds.append(("mitre-attack-mobile", attack))
    for path in sorted((root / "investigations").glob("*/*.stix2")):
        feeds.append((f"amnesty-{path.stem}", path))
    return feeds


def test_public_feeds_end_to_end(platform, real_data_dir):
    if real_data_dir is None:
        pytest.skip("set MTIP_REAL_DATA to a folder with the public feeds to run this test")
    feeds = _feeds(real_data_dir)
    if not feeds:
        pytest.skip("no recognised feeds in MTIP_REAL_DATA")
    for name, path in feeds:
        report = platform.importer.import_bytes(path.read_bytes(), name)
        assert report.status == "complete"
        assert report.rejected <= max(5, report.objects_total // 100)
    result = platform.engine.run(EngineParams(holdout_reps=3))
    ev = result.stats["evaluation"]
    assert ev["status"] == "ok"
    assert ev["ablations"]["context"]["precision"]["mean"] >= 0.95
    conflicts = platform.storage.query(
        "SELECT i.value FROM inferred_edges ie JOIN indicators i ON i.id=ie.src_id WHERE ie.rel_type=?", (REL_CONFLICT,))
    assert not [r[0] for r in conflicts if "aliyuncs.com" in r[0] or "cloudfunctions.net" in r[0]]
    assert result.stats["duration_seconds"] < 60
