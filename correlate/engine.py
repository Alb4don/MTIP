from __future__ import annotations

import json
import math
import threading
import time
from dataclasses import asdict, dataclass, field, replace
from typing import Any

import numpy as np
import pandas as pd
from rapidfuzz import fuzz
from rapidfuzz.process import cdist

from ..logging_setup import get_logger
from ..normalize import (
    STRUCTURAL_KINDS, NormalizedIndicator, core_family_name, distinctive_tokens, is_shared_infrastructure,
    package_namespace, root_of,
)
from ..storage import Storage, utcnow
from .stats import (
    LogisticModel, benjamini_hochberg, beta_mean, fit_logistic, hypergeom_sf,
)

log = get_logger("engine")

FEATURES: tuple[str, ...] = (
    "same_root", "same_namespace", "token_idf", "label_similarity", "cross_type", "temporal_proximity", "temporal_known",
)
CONTEXT_FEATURES = ("same_namespace", "token_idf", "label_similarity", "cross_type")
TEMPORAL_FEATURES = ("temporal_proximity", "temporal_known")
ATTRIBUTABLE_TYPES = ("malware", "campaign", "intrusion-set", "tool")
GOOD_TS = ("observed", "publication")
ANALYST_SOURCE = "analyst"

REL_INFERRED_INDICATES = "inferred-indicates"
REL_SHARED_INFRA = "shares-infrastructure-with"
REL_SHARED_TTP = "shares-ttp-profile-with"
REL_ALIAS = "possible-alias-or-variant"
REL_CONFLICT = "conflicts-with-documented"


@dataclass(frozen=True)
class EngineParams:
    min_attribution: float = 0.6
    ambiguity_ratio: float = 0.8
    fdr_alpha: float = 0.05
    min_shared_keys: int = 2
    anchor_cap: int = 200
    label_cutoff: int = 88
    temporal_tau_days: float = 180.0
    use_context: bool = True
    use_temporal: bool = True
    root_only: bool = False
    alias_cutoff: int = 88
    max_key_share: float = 0.2
    max_key_families: int = 2
    max_key_fanout: int = 100
    feedback_weight: float = 5.0
    holdout_fraction: float = 0.2
    holdout_reps: int = 3
    seed: int = 1337

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Snapshot:
    indicators: pd.DataFrame
    labels: pd.DataFrame
    entities: pd.DataFrame
    entity_edges: pd.DataFrame
    source_reliability: dict[int, float]
    rejected: set[tuple[int, int]]
    feedback: pd.DataFrame


def load_snapshot(storage: Storage) -> Snapshot:
    conn = storage.conn
    conn.execute("BEGIN")
    try:
        return _read_snapshot(storage, conn)
    finally:
        conn.execute("COMMIT")


def _read_snapshot(storage: Storage, conn) -> Snapshot:
    ind = pd.read_sql_query(
        "SELECT i.id, i.kind, i.value, i.root, i.shared_root, i.first_seen, i.analyst_verdict, "
        "MAX(CASE WHEN s.ts_quality IN ('observed','publication') THEN 1 ELSE 0 END) AS ts_good "
        "FROM indicators i LEFT JOIN observations o ON o.indicator_id=i.id LEFT JOIN sources s ON s.id=o.source_id "
        "GROUP BY i.id", conn,
    )
    ind["first_seen"] = pd.to_datetime(ind["first_seen"], utc=True, errors="coerce")
    roots = [root_of(NormalizedIndicator(k, v)) for k, v in zip(ind["kind"], ind["value"], strict=True)]
    ind["root"] = roots
    ind["shared_root"] = [1 if (r is not None and is_shared_infrastructure(r)) else 0 for r in roots]
    ind["ts_good"] = ind["ts_good"].fillna(0).astype(bool)
    labels = pd.read_sql_query(
        "SELECT d.src_id AS ind_id, d.dst_id AS ent_id, d.source_id FROM documented_edges d "
        "JOIN entities e ON e.id=d.dst_id WHERE d.src_type='indicator' AND d.rel_type='indicates' "
        f"AND d.dst_type IN ({','.join('?' for _ in ATTRIBUTABLE_TYPES)})",
        conn, params=ATTRIBUTABLE_TYPES,
    )
    entities = pd.read_sql_query("SELECT id, etype, norm_name, display_name, first_seen, last_seen FROM entities", conn)
    ent_edges = pd.read_sql_query(
        "SELECT src_type, src_id, dst_type, dst_id, rel_type, source_id FROM documented_edges WHERE src_type<>'indicator' AND dst_type<>'indicator'",
        conn,
    )
    reliability = {int(r["id"]): beta_mean(float(r["alpha"]), float(r["beta"])) for r in storage.query("SELECT id, alpha, beta FROM sources")}
    rejected = {
        (int(r["src_id"]), int(r["dst_id"]))
        for r in storage.query("SELECT src_id, dst_id FROM feedback WHERE verdict='reject' AND rel_type=? AND src_type='indicator'", (REL_INFERRED_INDICATES,))
    }
    fb_rows = storage.query("SELECT verdict, features FROM feedback WHERE rel_type=?", (REL_INFERRED_INDICATES,))
    fb_records = []
    for row in fb_rows:
        try:
            feats = json.loads(row["features"])
        except ValueError:
            continue
        if isinstance(feats, dict):
            fb_records.append({**{f: float(feats.get(f, 0.0) or 0.0) for f in FEATURES}, "y": 1.0 if row["verdict"] == "confirm" else 0.0})
    feedback = pd.DataFrame(fb_records, columns=[*FEATURES, "y"])
    return Snapshot(ind, labels, entities, ent_edges, reliability, rejected, feedback)


def build_keys(indicators: pd.DataFrame) -> pd.DataFrame:
    rows: list[tuple[int, str, str]] = []
    structural = indicators[indicators["kind"].isin(STRUCTURAL_KINDS)]
    for ind_id, kind, value, root, shared in structural[["id", "kind", "value", "root", "shared_root"]].itertuples(index=False):
        if root and not shared:
            rows.append((int(ind_id), "root", root))
        if kind == "app_id":
            ns = package_namespace(value)
            if ns:
                rows.append((int(ind_id), "ns", ns))
        for token in distinctive_tokens(NormalizedIndicator(kind, value)):
            rows.append((int(ind_id), "tok", token))
    keys = pd.DataFrame(rows, columns=["ind_id", "ktype", "key"]).drop_duplicates()
    if keys.empty:
        keys["idf"] = pd.Series(dtype=float)
        return keys
    n_structural = max(2, structural["id"].nunique())
    df = keys.groupby(["ktype", "key"])["ind_id"].transform("nunique")
    keys["idf"] = np.where(keys["ktype"] == "tok", np.log(n_structural / df) / math.log(n_structural), 1.0)
    keys = keys[df > 1]
    token_cap = max(50, int(0.01 * n_structural))
    keys = keys[~((keys["ktype"] == "tok") & (keys.groupby(["ktype", "key"])["ind_id"].transform("nunique") > token_cap))]
    return keys.reset_index(drop=True)


def similar_label_pairs(indicators: pd.DataFrame, cutoff: int) -> pd.DataFrame:
    sub = indicators[indicators["kind"].isin(STRUCTURAL_KINDS) & indicators["root"].notna() & (indicators["shared_root"] == 0)]
    if sub.empty:
        return pd.DataFrame(columns=["la", "lb", "label_similarity"])
    labels = sub["root"].astype(str).str.split(".").str[0]
    sub = sub.assign(label=labels)
    sub = sub[sub["label"].str.len() >= 6]
    uniq = sub["label"].drop_duplicates().tolist()
    if len(uniq) < 2:
        return pd.DataFrame(columns=["la", "lb", "label_similarity"])
    if len(uniq) > 12_000:
        uniq = uniq[:12_000]
    matrix = cdist(uniq, uniq, scorer=fuzz.ratio, score_cutoff=cutoff, dtype=np.uint8, workers=-1)
    np.fill_diagonal(matrix, 0)
    top_k = 5
    if matrix.shape[1] > top_k:
        threshold = np.partition(matrix, -top_k, axis=1)[:, -top_k][:, None]
        matrix = np.where((matrix >= threshold) & (matrix > 0), matrix, 0).astype(np.uint8)
    ia, ib = np.nonzero(matrix)
    arr = np.asarray(uniq, dtype=object)
    return pd.DataFrame({"la": arr[ia], "lb": arr[ib], "label_similarity": matrix[ia, ib] / 100.0})


def _label_table(indicators: pd.DataFrame) -> pd.DataFrame:
    sub = indicators[indicators["kind"].isin(STRUCTURAL_KINDS) & indicators["root"].notna() & (indicators["shared_root"] == 0)]
    if sub.empty:
        return pd.DataFrame(columns=["ind_id", "label", "root"])
    roots = sub["root"].astype(str)
    return pd.DataFrame({"ind_id": sub["id"].astype(int), "label": roots.str.split(".").str[0], "root": roots})


def _cap_groups(frame: pd.DataFrame, by: list[str], cap: int, seed: int) -> pd.DataFrame:
    if frame.empty:
        return frame
    shuffled = frame.sample(frac=1.0, random_state=seed)
    return shuffled[shuffled.groupby(by).cumcount() < cap]


def candidate_pairs(keys: pd.DataFrame, label_pairs: pd.DataFrame, label_table: pd.DataFrame,
                    labeled_ids: set[int], params: EngineParams) -> pd.DataFrame:
    cols = ["a", "b", "same_root", "same_namespace", "token_idf", "label_similarity"]
    if not labeled_ids:
        return pd.DataFrame(columns=cols)
    anchors = _cap_groups(keys[keys["ind_id"].isin(labeled_ids)], ["ktype", "key"], params.anchor_cap, params.seed)
    merged = keys.merge(anchors[["ktype", "key", "ind_id"]].rename(columns={"ind_id": "b"}), on=["ktype", "key"])
    merged = merged[merged["ind_id"] != merged["b"]].rename(columns={"ind_id": "a"})
    frames = []
    if not merged.empty:
        merged["same_root"] = (merged["ktype"] == "root").astype(float)
        merged["same_namespace"] = (merged["ktype"] == "ns").astype(float)
        merged["token_idf"] = np.where(merged["ktype"] == "tok", merged["idf"], 0.0)
        merged["label_similarity"] = 0.0
        frames.append(merged[cols])
    if not label_pairs.empty and not label_table.empty:
        lab_anchor = label_table[label_table["ind_id"].isin(labeled_ids)]
        lab_anchor = _cap_groups(lab_anchor, ["label"], 20, params.seed)
        lp = label_pairs.merge(label_table.rename(columns={"ind_id": "a", "label": "la", "root": "ra"}), on="la")
        lp = lp.merge(lab_anchor.rename(columns={"ind_id": "b", "label": "lb", "root": "rb"}), on="lb")
        lp = lp[(lp["ra"] != lp["rb"]) & (lp["a"] != lp["b"])]
        if not lp.empty:
            lp = lp.assign(same_root=0.0, same_namespace=0.0, token_idf=0.0)
            frames.append(lp[cols])
    if not frames:
        return pd.DataFrame(columns=cols)
    pairs = pd.concat(frames, ignore_index=True).groupby(["a", "b"], as_index=False).max()
    pairs.loc[pairs["same_root"] > 0, ["token_idf", "label_similarity"]] = 0.0
    pairs["a"] = pairs["a"].astype(int)
    pairs["b"] = pairs["b"].astype(int)
    return pairs


def add_context(pairs: pd.DataFrame, indicators: pd.DataFrame, params: EngineParams) -> pd.DataFrame:
    if pairs.empty:
        for f in ("cross_type", "temporal_proximity", "temporal_known"):
            pairs[f] = pd.Series(dtype=float)
        return pairs
    ordered = indicators.sort_values("id")
    ids = ordered["id"].to_numpy(dtype=np.int64)
    kind_codes = pd.Categorical(ordered["kind"]).codes
    seen = pd.to_datetime(ordered["first_seen"], utc=True, errors="coerce")
    seconds = seen.dt.tz_convert(None).to_numpy(dtype="datetime64[s]").astype(np.float64)
    seconds[seen.isna().to_numpy()] = np.nan
    good = ordered["ts_good"].to_numpy(dtype=bool) & ~np.isnan(seconds)
    ia = np.searchsorted(ids, pairs["a"].to_numpy(dtype=np.int64))
    ib = np.searchsorted(ids, pairs["b"].to_numpy(dtype=np.int64))
    pairs = pairs.copy()
    pairs["cross_type"] = (kind_codes[ia] != kind_codes[ib]).astype(float)
    known = good[ia] & good[ib]
    delta_days = np.abs(np.nan_to_num(seconds[ia]) - np.nan_to_num(seconds[ib])) / 86_400.0
    pairs["temporal_known"] = known.astype(float)
    pairs["temporal_proximity"] = np.where(known, np.exp(-delta_days / params.temporal_tau_days), 0.0)
    return pairs


def feature_matrix(pairs: pd.DataFrame, params: EngineParams) -> np.ndarray:
    X = pairs[list(FEATURES)].to_numpy(dtype=float) if not pairs.empty else np.zeros((0, len(FEATURES)))
    mask = np.ones(len(FEATURES))
    if params.root_only or not params.use_context:
        for f in CONTEXT_FEATURES:
            mask[FEATURES.index(f)] = 0.0
    if not params.use_temporal or params.root_only:
        for f in TEMPORAL_FEATURES:
            mask[FEATURES.index(f)] = 0.0
    return X * mask


def fit_pair_model(pairs: pd.DataFrame, labels: pd.DataFrame, feedback: pd.DataFrame, params: EngineParams) -> LogisticModel:
    fam = labels.groupby("ind_id")["ent_id"].apply(frozenset)
    train = pairs[pairs["a"].isin(fam.index) & pairs["b"].isin(fam.index)]
    if len(train) > 400_000:
        train = train.sample(n=400_000, random_state=params.seed)
    fa = fam.reindex(train["a"].to_numpy()).to_numpy()
    fb = fam.reindex(train["b"].to_numpy()).to_numpy()
    y = np.fromiter((1.0 if (x & z) else 0.0 for x, z in zip(fa, fb, strict=True)), dtype=float, count=len(train))
    X = feature_matrix(train, params)
    w = np.ones(len(train))
    if not feedback.empty:
        Xf = feature_matrix(feedback, params)
        X = np.vstack([X, Xf])
        y = np.concatenate([y, feedback["y"].to_numpy(dtype=float)])
        w = np.concatenate([w, np.full(len(feedback), params.feedback_weight)])
    if len(y):
        pos = y.sum()
        neg = len(y) - pos
        if pos > 0 and neg > 0:
            w = w * np.where(y == 1, len(y) / (2 * pos), len(y) / (2 * neg))
    return fit_logistic(X, y, w, FEATURES, l2=1.0)


def attribute(pairs: pd.DataFrame, scores: np.ndarray, labels: pd.DataFrame, reliability: dict[int, float],
              rejected: set[tuple[int, int]], targets: set[int], params: EngineParams) -> pd.DataFrame:
    cols = ["ind_id", "ent_id", "score", "runner_up", "support", "via", "pair_index"]
    if pairs.empty or not targets:
        return pd.DataFrame(columns=cols)
    scored = pairs[["a", "b"]].assign(s=scores, pair_index=np.arange(len(pairs)))
    scored = scored[scored["a"].isin(targets) & (scored["s"] > 0.05)]
    lab = labels.assign(rel=labels["source_id"].map(reliability).fillna(0.5))
    lab = lab.groupby(["ind_id", "ent_id"], as_index=False)["rel"].max()
    rows = scored.merge(lab.rename(columns={"ind_id": "b"}), on="b")
    if rows.empty:
        return pd.DataFrame(columns=cols)
    rows["v"] = np.clip(rows["s"] * rows["rel"], 0.0, 1 - 1e-9)
    rows["logc"] = np.log1p(-rows["v"])
    grouped = rows.groupby(["a", "ent_id"]).agg(logc=("logc", "sum"), support=("b", "nunique"))
    best_idx = rows.loc[rows.groupby(["a", "ent_id"])["v"].idxmax(), ["a", "ent_id", "b", "pair_index"]].set_index(["a", "ent_id"])
    grouped = grouped.join(best_idx).reset_index()
    grouped["score"] = 1.0 - np.exp(grouped["logc"])
    grouped = grouped.sort_values(["a", "score"], ascending=[True, False])
    grouped["rank"] = grouped.groupby("a").cumcount()
    second = grouped[grouped["rank"] == 1].set_index("a")["score"]
    top = grouped[grouped["rank"] == 0].copy()
    top["runner_up"] = top["a"].map(second).fillna(0.0)
    keep = (top["score"] >= params.min_attribution) & (top["runner_up"] < params.ambiguity_ratio * top["score"])
    top = top[keep]
    if rejected:
        top = top[[(int(a), int(e)) not in rejected for a, e in zip(top["a"], top["ent_id"], strict=True)]]
    top = top.rename(columns={"a": "ind_id", "b": "via"})
    return top[cols].reset_index(drop=True)


def shared_key_tests(family_keys: pd.DataFrame, params: EngineParams, all_entities: int, min_shared: int | None = None, min_fanout: int = 2) -> pd.DataFrame:
    cols = ["ent_a", "ent_b", "k", "K", "n", "N", "p", "q"]
    if family_keys.empty:
        return pd.DataFrame(columns=cols)
    fk = family_keys.drop_duplicates()
    population = int(fk["ent_id"].nunique())
    fanout = fk.groupby("key")["ent_id"].transform("nunique")
    share_cap = max(2, int(params.max_key_share * fk["ent_id"].nunique()), min_fanout)
    fk = fk[fanout <= min(params.max_key_fanout, share_cap)]
    fk_pairs = fk
    pairs = fk_pairs.merge(fk_pairs, on="key", suffixes=("_a", "_b"))
    pairs = pairs[pairs["ent_id_a"] < pairs["ent_id_b"]]
    if pairs.empty:
        return pd.DataFrame(columns=cols)
    counts = pairs.groupby(["ent_id_a", "ent_id_b"]).size().rename("k").reset_index()
    sizes = fk.groupby("ent_id")["key"].nunique()
    N = int(fk["key"].nunique())
    counts["K"] = counts["ent_id_a"].map(sizes).astype(int)
    counts["n"] = counts["ent_id_b"].map(sizes).astype(int)
    counts["N"] = N
    counts["p"] = [hypergeom_sf(int(k), N, int(K), int(n)) for k, K, n in zip(counts["k"], counts["K"], counts["n"], strict=True)]
    population = min(population, all_entities) if all_entities else population
    total_tests = max(len(counts), population * (population - 1) // 2)
    counts["q"] = benjamini_hochberg(counts["p"].to_numpy(), total_tests)
    counts = counts.rename(columns={"ent_id_a": "ent_a", "ent_id_b": "ent_b"})
    threshold = params.min_shared_keys if min_shared is None else min_shared
    return counts[(counts["q"] <= params.fdr_alpha) & (counts["k"] >= threshold)][cols].reset_index(drop=True)


def alias_candidates(entities: pd.DataFrame, documented_pairs: set[tuple[int, int]], params: EngineParams) -> pd.DataFrame:
    out = []
    for etype in ATTRIBUTABLE_TYPES:
        sub = entities[entities["etype"] == etype]
        if len(sub) < 2 or len(sub) > 20_000:
            continue
        cores = [core_family_name(n) for n in sub["norm_name"].tolist()]
        mask = np.array([len(c.replace(" ", "")) >= 5 for c in cores])
        if mask.sum() < 2:
            continue
        names = sub["norm_name"].to_numpy()[mask].tolist()
        kept = [c for c, m in zip(cores, mask, strict=True) if m]
        ids = sub["id"].to_numpy()[mask]
        matrix = cdist(kept, kept, scorer=fuzz.ratio, dtype=np.float32, workers=-1)
        np.fill_diagonal(matrix, 0)
        ia, ib = np.nonzero(np.triu(matrix >= params.alias_cutoff))
        for i, j in zip(ia, ib, strict=True):
            pair = (int(min(ids[i], ids[j])), int(max(ids[i], ids[j])))
            if pair in documented_pairs:
                continue
            out.append({"ent_a": pair[0], "ent_b": pair[1], "score": float(matrix[i, j]) / 100.0,
                        "names": [names[i], names[j]], "core": [kept[i], kept[j]]})
    return pd.DataFrame(out, columns=["ent_a", "ent_b", "score", "names", "core"])


def filter_generic_keys(keys: pd.DataFrame, labels: pd.DataFrame, max_families: int) -> pd.DataFrame:
    if keys.empty or labels.empty:
        return keys
    fam = keys.merge(labels[["ind_id", "ent_id"]].drop_duplicates(), on="ind_id")
    spread = fam.groupby(["ktype", "key"])["ent_id"].nunique()
    generic = spread[spread > max_families].reset_index()[["ktype", "key"]]
    if generic.empty:
        return keys
    marked = keys.merge(generic.assign(_generic=True), on=["ktype", "key"], how="left")
    return marked[marked["_generic"].isna()].drop(columns="_generic").reset_index(drop=True)


def _family_keys(keys: pd.DataFrame, labels: pd.DataFrame) -> pd.DataFrame:
    if keys.empty or labels.empty:
        return pd.DataFrame(columns=["ent_id", "key"])
    fk = labels[["ind_id", "ent_id"]].drop_duplicates().merge(keys[keys["ktype"].isin(["root", "ns"])], on="ind_id")
    return pd.DataFrame({"ent_id": fk["ent_id"], "key": fk["ktype"] + ":" + fk["key"]})


def _ttp_keys(snapshot: Snapshot) -> pd.DataFrame:
    e = snapshot.entity_edges
    if e.empty:
        return pd.DataFrame(columns=["ent_id", "key"])
    sub = e[(e["rel_type"] == "uses") & (e["dst_type"] == "attack-pattern") & e["src_type"].isin(ATTRIBUTABLE_TYPES)]
    return pd.DataFrame({"ent_id": sub["src_id"].astype(int), "key": "ttp:" + sub["dst_id"].astype(str)})


def _attributable_labels(snapshot: Snapshot, kinds: frozenset[str] = STRUCTURAL_KINDS) -> pd.DataFrame:
    structural_ids = set(snapshot.indicators.loc[snapshot.indicators["kind"].isin(kinds), "id"].astype(int))
    return snapshot.labels[snapshot.labels["ind_id"].isin(structural_ids)]


ABLATIONS: dict[str, dict[str, bool]] = {
    "root_only": {"root_only": True, "use_context": False, "use_temporal": False},
    "context": {"root_only": False, "use_context": True, "use_temporal": False},
    "context_temporal": {"root_only": False, "use_context": True, "use_temporal": True},
}


def holdout_evaluate(snapshot: Snapshot, keys: pd.DataFrame, label_pairs: pd.DataFrame, params: EngineParams) -> dict[str, Any]:
    labels = _attributable_labels(snapshot)
    fam_count = labels.groupby("ind_id")["ent_id"].nunique()
    eligible = np.array(sorted(int(i) for i in fam_count[fam_count == 1].index))
    result: dict[str, Any] = {"eligible": int(len(eligible)), "reps": params.holdout_reps, "fraction": params.holdout_fraction, "ablations": {}}
    if len(eligible) < 10 or params.holdout_reps < 1:
        result["status"] = "insufficient-data"
        return result
    truth = labels.drop_duplicates("ind_id").set_index("ind_id")["ent_id"]
    label_table = _label_table(snapshot.indicators)
    rng = np.random.default_rng(params.seed)
    per_config: dict[str, list[dict[str, float]]] = {name: [] for name in ABLATIONS}
    for _ in range(params.holdout_reps):
        hidden = set(rng.choice(eligible, size=max(1, int(len(eligible) * params.holdout_fraction)), replace=False).tolist())
        train_labels = labels[~labels["ind_id"].isin(hidden)]
        labeled = set(train_labels["ind_id"].astype(int))
        rep_keys = filter_generic_keys(keys, train_labels, params.max_key_families)
        pairs = add_context(candidate_pairs(rep_keys, label_pairs, label_table, labeled, params), snapshot.indicators, params)
        for name, overrides in ABLATIONS.items():
            cfg = replace(params, **overrides)
            model = fit_pair_model(pairs, train_labels, pd.DataFrame(columns=[*FEATURES, "y"]), cfg)
            scores = model.predict(feature_matrix(pairs, cfg))
            preds = attribute(pairs, scores, train_labels, snapshot.source_reliability, set(), hidden, cfg)
            predicted = len(preds)
            correct = int(sum(truth.get(int(i)) == int(e) for i, e in zip(preds["ind_id"], preds["ent_id"], strict=True)))
            precision = correct / predicted if predicted else 0.0
            recall = correct / len(hidden)
            f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
            per_config[name].append({"precision": precision, "recall": recall, "f1": f1, "coverage": predicted / len(hidden), "hidden": len(hidden)})
    for name, runs in per_config.items():
        frame = pd.DataFrame(runs)
        result["ablations"][name] = {
            metric: {"mean": round(float(frame[metric].mean()), 4), "sd": round(float(frame[metric].std(ddof=0)), 4)}
            for metric in ("precision", "recall", "f1", "coverage")
        }
        result["ablations"][name]["hidden"] = int(frame["hidden"].mean())
    full = result["ablations"]["context_temporal"]["f1"]["mean"]
    ctx = result["ablations"]["context"]["f1"]["mean"]
    root = result["ablations"]["root_only"]["f1"]["mean"]
    result["lift_context_over_root_f1"] = round(ctx - root, 4)
    result["lift_temporal_over_context_f1"] = round(full - ctx, 4)
    known = float(snapshot.indicators["ts_good"].mean()) if len(snapshot.indicators) else 0.0
    result["temporal_coverage"] = round(known, 4)
    result["status"] = "ok"
    return result


@dataclass
class RunResult:
    run_id: int
    stats: dict[str, Any] = field(default_factory=dict)


class CorrelationEngine:
    def __init__(self, storage: Storage):
        self.storage = storage
        self._lock = threading.Lock()
        self._state: dict[str, Any] = {"status": "idle"}

    @property
    def state(self) -> dict[str, Any]:
        return dict(self._state)

    def is_running(self) -> bool:
        return self._lock.locked()

    def run(self, params: EngineParams | None = None, evaluate: bool = True) -> RunResult | None:
        if not self._lock.acquire(blocking=False):
            return None
        params = params or EngineParams()
        started = time.perf_counter()
        run_id = None
        try:
            self._state = {"status": "running", "stage": "loading", "started_at": utcnow()}
            with self.storage.transaction() as tx:
                run_id = tx.execute(
                    "INSERT INTO correlation_runs(started_at,status,params) VALUES(?,?,?)",
                    (utcnow(), "running", json.dumps(params.as_dict())),
                ).lastrowid
            snap = load_snapshot(self.storage)
            self._refresh_roots(snap)
            self._state["stage"] = "features"
            keys = build_keys(snap.indicators)
            label_pairs = similar_label_pairs(snap.indicators, params.label_cutoff)
            label_table = _label_table(snap.indicators)
            attr_labels = _attributable_labels(snap)
            labeled = set(attr_labels["ind_id"].astype(int))
            attr_keys = filter_generic_keys(keys, attr_labels, params.max_key_families)
            pairs = add_context(candidate_pairs(attr_keys, label_pairs, label_table, labeled, params), snap.indicators, params)
            self._state["stage"] = "model"
            model = fit_pair_model(pairs, attr_labels, snap.feedback, params)
            scores = model.predict(feature_matrix(pairs, params))
            documented_any = set(snap.labels["ind_id"].astype(int))
            targets = set(snap.indicators.loc[snap.indicators["kind"].isin(STRUCTURAL_KINDS), "id"].astype(int)) - documented_any
            attributions = attribute(pairs, scores, attr_labels, snap.source_reliability, snap.rejected, targets, params)
            documented_targets = set(attr_labels["ind_id"].astype(int))
            cross_check = attribute(pairs, scores, attr_labels, snap.source_reliability, snap.rejected, documented_targets, params)
            own = attr_labels.groupby("ind_id")["ent_id"].apply(set)
            conflicts = cross_check[[int(e) not in own.get(int(i), set()) for i, e in zip(cross_check["ind_id"], cross_check["ent_id"], strict=True)]]
            self._state["stage"] = "entity-tests"
            n_entities = int(snap.entities["etype"].isin(ATTRIBUTABLE_TYPES).sum())
            infra = shared_key_tests(_family_keys(keys, attr_labels), params, n_entities, min_fanout=params.max_key_fanout)
            ttp = shared_key_tests(_ttp_keys(snap), params, n_entities, min_shared=3)
            documented_pairs = {
                (int(min(a, b)), int(max(a, b)))
                for a, b in zip(snap.entity_edges["src_id"], snap.entity_edges["dst_id"], strict=True)
            }
            aliases = alias_candidates(snap.entities, documented_pairs, params)
            entity_agreement = {}
            for label, frame in (("infrastructure", infra), ("ttp", ttp)):
                if frame.empty:
                    entity_agreement[label] = {"significant": 0, "already_documented": 0}
                    continue
                is_doc = np.array([(int(min(a, b)), int(max(a, b))) in documented_pairs for a, b in zip(frame["ent_a"], frame["ent_b"], strict=True)])
                entity_agreement[label] = {"significant": int(len(frame)), "already_documented": int(is_doc.sum())}
                if label == "infrastructure":
                    infra = frame[~is_doc].reset_index(drop=True)
                else:
                    ttp = frame[~is_doc].reset_index(drop=True)
            evaluation = None
            if evaluate:
                self._state["stage"] = "evaluation"
                evaluation = holdout_evaluate(snap, keys, label_pairs, params)
            self._state["stage"] = "saving"
            rows = self._edge_rows(run_id, attributions, pairs, snap, infra, ttp, aliases)
            rows += [
                (r[0], r[1], r[2], r[3], r[4], REL_CONFLICT, *r[6:])
                for r in self._edge_rows(run_id, conflicts, pairs, snap, infra.iloc[0:0], ttp.iloc[0:0], aliases.iloc[0:0])
            ]
            stats = {
                "indicators": int(len(snap.indicators)),
                "documented_edges": int(self.storage.query_one("SELECT COUNT(*) FROM documented_edges")[0]),
                "candidate_pairs": int(len(pairs)),
                "inferred_attributions": int(len(attributions)),
                "conflicts_with_documented": int(len(conflicts)),
                "inferred_shared_infrastructure": int(len(infra)),
                "inferred_shared_ttp": int(len(ttp)),
                "inferred_aliases": int(len(aliases)),
                "entity_tests_agreement": entity_agreement,
                "model": model.as_dict(),
                "evaluation": evaluation,
                "duration_seconds": round(time.perf_counter() - started, 3),
            }
            with self.storage.transaction() as tx:
                tx.executemany(
                    "INSERT OR REPLACE INTO inferred_edges(run_id,src_type,src_id,dst_type,dst_id,rel_type,score,p_value,q_value,basis,features) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)", rows,
                )
                tx.execute("UPDATE correlation_runs SET status='complete', finished_at=?, stats=? WHERE id=?", (utcnow(), json.dumps(stats), run_id))
                self.storage.set_state("active_run", run_id, conn=tx)
                self.storage.set_state("pair_model", model.as_dict(), conn=tx)
                tx.execute(
                    "DELETE FROM correlation_runs WHERE id NOT IN (SELECT id FROM correlation_runs WHERE status='complete' ORDER BY id DESC LIMIT 3) AND id<>?",
                    (run_id,),
                )
            self.storage.record_episode("correlation-run", {"run_id": run_id, "attributions": stats["inferred_attributions"]}, "complete")
            self._state = {"status": "idle", "last_run": run_id, "finished_at": utcnow()}
            log.info("correlation run complete run_id=%s seconds=%s", run_id, stats["duration_seconds"])
            return RunResult(run_id, stats)
        except Exception as exc:
            log.error("correlation run failed run_id=%s error=%s", run_id, type(exc).__name__)
            if run_id is not None:
                try:
                    with self.storage.transaction() as tx:
                        tx.execute("UPDATE correlation_runs SET status='failed', finished_at=? WHERE id=?", (utcnow(), run_id))
                except Exception as inner:
                    log.error("could not mark run failed run_id=%s error=%s", run_id, type(inner).__name__)
            self._state = {"status": "failed", "finished_at": utcnow()}
            raise
        finally:
            self._lock.release()

    def _refresh_roots(self, snap: Snapshot) -> None:
        stored = {int(r["id"]): (r["root"], int(r["shared_root"])) for r in self.storage.query("SELECT id, root, shared_root FROM indicators")}
        changes = [
            (root, int(shared), int(i))
            for i, root, shared in zip(snap.indicators["id"], snap.indicators["root"], snap.indicators["shared_root"], strict=True)
            if stored.get(int(i)) != (root, int(shared))
        ]
        if changes:
            with self.storage.transaction() as tx:
                tx.executemany("UPDATE indicators SET root=?, shared_root=? WHERE id=?", changes)
            log.info("indicator roots refreshed count=%s", len(changes))

    @staticmethod
    def _edge_rows(run_id: int, attributions: pd.DataFrame, pairs: pd.DataFrame, snap: Snapshot,
                   infra: pd.DataFrame, ttp: pd.DataFrame, aliases: pd.DataFrame) -> list[tuple]:
        rows: list[tuple] = []
        etype = snap.entities.set_index("id")["etype"].to_dict()
        ind_meta = snap.indicators.set_index("id")[["kind", "value"]]
        for rec in attributions.itertuples(index=False):
            pair = pairs.iloc[int(rec.pair_index)]
            features = {f: round(float(pair[f]), 6) for f in FEATURES}
            via_kind, via_value = ind_meta.loc[int(rec.via)] if int(rec.via) in ind_meta.index else ("", "")
            reasons = [f for f in ("same_root", "same_namespace", "token_idf", "label_similarity") if features[f] > 0]
            basis = {
                "method": "pairwise-logistic+noisy-or",
                "via_indicator": {"id": int(rec.via), "kind": via_kind, "value": via_value},
                "reasons": reasons,
                "support": int(rec.support),
                "runner_up": round(float(rec.runner_up), 6),
            }
            rows.append((run_id, "indicator", int(rec.ind_id), etype.get(int(rec.ent_id), "malware"), int(rec.ent_id),
                         REL_INFERRED_INDICATES, round(float(rec.score), 6), None, None, json.dumps(basis), json.dumps(features)))
        for frame, rel in ((infra, REL_SHARED_INFRA), (ttp, REL_SHARED_TTP)):
            for rec in frame.itertuples(index=False):
                basis = {"method": "hypergeometric+benjamini-hochberg", "shared": int(rec.k), "set_a": int(rec.K), "set_b": int(rec.n), "universe": int(rec.N)}
                rows.append((run_id, etype.get(int(rec.ent_a), "malware"), int(rec.ent_a), etype.get(int(rec.ent_b), "malware"), int(rec.ent_b),
                             rel, round(1.0 - float(rec.q), 6), float(rec.p), float(rec.q), json.dumps(basis), "{}"))
        for rec in aliases.itertuples(index=False):
            basis = {"method": "string-similarity(ratio,token_set)", "names": list(rec.names)}
            rows.append((run_id, etype.get(int(rec.ent_a), "malware"), int(rec.ent_a), etype.get(int(rec.ent_b), "malware"), int(rec.ent_b),
                         REL_ALIAS, round(float(rec.score), 6), None, None, json.dumps(basis), "{}"))
        return rows
