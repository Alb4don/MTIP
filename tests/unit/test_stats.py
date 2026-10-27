import math
from itertools import product

import numpy as np
import pytest

from mtip.correlate.stats import beta_interval, beta_mean, benjamini_hochberg, fit_logistic, hypergeom_sf, noisy_or


def _brute_sf(k, N, K, n):
    total = math.comb(N, n)
    return sum(math.comb(K, i) * math.comb(N - K, n - i) for i in range(k, min(K, n) + 1)) / total


@pytest.mark.parametrize("k,N,K,n", [(1, 20, 5, 4), (3, 50, 10, 12), (0, 10, 3, 3), (4, 30, 4, 4), (5, 30, 4, 6), (2, 100, 2, 2)])
def test_hypergeom_matches_exact(k, N, K, n):
    assert hypergeom_sf(k, N, K, n) == pytest.approx(_brute_sf(k, N, K, n), rel=1e-9, abs=1e-15)


def test_hypergeom_large_population_matches_exact_integer_arithmetic():
    from fractions import Fraction
    k, N, K, n = 30, 100_000, 400, 500
    exact = Fraction(sum(math.comb(K, i) * math.comb(N - K, n - i) for i in range(k, min(K, n) + 1)), math.comb(N, n))
    assert hypergeom_sf(k, N, K, n) == pytest.approx(float(exact), rel=1e-8)


def test_bh_known_values():
    p = np.array([0.01, 0.04, 0.03, 0.005])
    q = benjamini_hochberg(p)
    assert q.tolist() == pytest.approx([0.02, 0.04, 0.04, 0.02])


def test_bh_respects_total_tests_and_monotonicity():
    p = np.array([0.001, 0.2, 0.01])
    q_small = benjamini_hochberg(p)
    q_big = benjamini_hochberg(p, total_tests=1000)
    assert np.all(q_big >= q_small)
    order = np.argsort(p)
    assert np.all(np.diff(q_big[order]) >= -1e-12)
    assert np.all(q_big <= 1.0)


def test_logistic_learns_direction():
    rng = np.random.default_rng(0)
    X = rng.normal(size=(2000, 2))
    y = (X[:, 0] - 0.5 * X[:, 1] + rng.normal(scale=0.3, size=2000) > 0).astype(float)
    model = fit_logistic(X, y, None, ("a", "b"))
    assert model.weights[0] > 1 and model.weights[1] < -0.3
    acc = ((model.predict(X) > 0.5) == (y == 1)).mean()
    assert acc > 0.9


def test_logistic_single_class_returns_prior_or_zero():
    model = fit_logistic(np.ones((5, 2)), np.ones(5), None, ("a", "b"))
    assert np.all(model.weights == 0)


def test_logistic_handles_perfect_separation_without_overflow():
    X = np.array([[0.0], [0.0], [1.0], [1.0]])
    y = np.array([0.0, 0.0, 1.0, 1.0])
    model = fit_logistic(X, y, None, ("a",), l2=1.0)
    assert np.isfinite(model.weights).all() and model.weights[0] > 0


def test_noisy_or():
    assert noisy_or(np.array([0.5, 0.5])) == pytest.approx(0.75)
    assert noisy_or(np.array([])) == pytest.approx(0.0)
    assert noisy_or(np.array([1.0])) < 1.0


def test_beta():
    assert beta_mean(2, 1) == pytest.approx(2 / 3)
    lo, hi = beta_interval(2, 1)
    assert 0 <= lo < beta_mean(2, 1) < hi <= 1
    lo2, hi2 = beta_interval(200, 100)
    assert hi2 - lo2 < hi - lo


@pytest.mark.parametrize("a,b", list(product([1, 5, 50], [1, 5, 50])))
def test_beta_interval_in_range(a, b):
    lo, hi = beta_interval(a, b)
    assert 0.0 <= lo <= hi <= 1.0
