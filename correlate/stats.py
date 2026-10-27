from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np


def log_comb(n: int, k: int) -> float:
    if k < 0 or k > n:
        return -math.inf
    return math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)


def hypergeom_sf(k: int, population: int, successes: int, draws: int) -> float:
    if k <= 0:
        return 1.0
    upper = min(successes, draws)
    if k > upper:
        return 0.0
    denom = log_comb(population, draws)
    terms = np.array([
        log_comb(successes, i) + log_comb(population - successes, draws - i) - denom
        for i in range(k, upper + 1)
    ])
    finite = terms[np.isfinite(terms)]
    if finite.size == 0:
        return 0.0
    peak = finite.max()
    return float(min(1.0, math.exp(peak) * np.exp(finite - peak).sum()))


def benjamini_hochberg(p_values: np.ndarray, total_tests: int | None = None) -> np.ndarray:
    p = np.asarray(p_values, dtype=float)
    if p.size == 0:
        return p
    m = max(int(total_tests or p.size), p.size)
    order = np.argsort(p)
    ranked = p[order] * m / np.arange(1, p.size + 1)
    q_sorted = np.minimum.accumulate(ranked[::-1])[::-1]
    q = np.empty_like(q_sorted)
    q[order] = np.clip(q_sorted, 0.0, 1.0)
    return q


def sigmoid(z: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(z, -35.0, 35.0)))


@dataclass
class LogisticModel:
    weights: np.ndarray
    bias: float
    feature_names: tuple[str, ...]
    trained_on: int = 0

    def predict(self, X: np.ndarray) -> np.ndarray:
        if X.shape[0] == 0:
            return np.zeros(0)
        return sigmoid(X @ self.weights + self.bias)

    def as_dict(self) -> dict:
        return {
            "weights": {n: round(float(w), 6) for n, w in zip(self.feature_names, self.weights, strict=True)},
            "bias": round(float(self.bias), 6),
            "trained_on": int(self.trained_on),
        }


def fit_logistic(X: np.ndarray, y: np.ndarray, sample_weight: np.ndarray | None, feature_names: tuple[str, ...],
                 l2: float = 1.0, max_iter: int = 50, prior: LogisticModel | None = None) -> LogisticModel:
    n, d = X.shape
    if n == 0 or len(np.unique(y)) < 2:
        if prior is not None:
            return prior
        return LogisticModel(np.zeros(d), 0.0, feature_names, 0)
    w_s = np.ones(n) if sample_weight is None else np.asarray(sample_weight, dtype=float)
    A = np.hstack([X, np.ones((n, 1))])
    theta = np.zeros(d + 1)
    reg = np.full(d + 1, l2)
    reg[-1] = 1e-6
    for _ in range(max_iter):
        p = sigmoid(A @ theta)
        grad = A.T @ (w_s * (p - y)) + reg * theta
        weight = w_s * p * (1 - p) + 1e-9
        hessian = (A * weight[:, None]).T @ A + np.diag(reg)
        try:
            step = np.linalg.solve(hessian, grad)
        except np.linalg.LinAlgError:
            step = np.linalg.lstsq(hessian, grad, rcond=None)[0]
        theta -= step
        if np.max(np.abs(step)) < 1e-7:
            break
    return LogisticModel(theta[:-1], float(theta[-1]), feature_names, int(n))


def noisy_or(values: np.ndarray) -> float:
    v = np.clip(np.asarray(values, dtype=float), 0.0, 1.0 - 1e-12)
    return float(1.0 - np.exp(np.log1p(-v).sum()))


def beta_mean(alpha: float, beta: float) -> float:
    return alpha / (alpha + beta)


def beta_interval(alpha: float, beta: float, z: float = 1.96) -> tuple[float, float]:
    mean = beta_mean(alpha, beta)
    var = (alpha * beta) / (((alpha + beta) ** 2) * (alpha + beta + 1))
    sd = math.sqrt(var)
    return max(0.0, mean - z * sd), min(1.0, mean + z * sd)
