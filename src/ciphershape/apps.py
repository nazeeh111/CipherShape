"""Two applications through the same closed graph language; no external datasets."""
from __future__ import annotations

import math
import random
from typing import Sequence

from .graph import Workload, dot, mul, private, scale, sub, sum_


def analytics(n: int = 8) -> Workload:
    x, y = private("x", n), private("y", n)
    mx, my = scale(sum_(x), 1 / n), scale(sum_(y), 1 / n)
    vx = sub(scale(sum_(mul(x, x)), 1 / n), mul(mx, mx))
    vy = sub(scale(sum_(mul(y, y)), 1 / n), mul(my, my))
    cov = sub(scale(sum_(mul(x, y)), 1 / n), mul(mx, my))
    public_weights = tuple((i + 1) / (n * n) for i in range(n))
    return Workload("analytics", (x, y), (
        ("mean_x", mx), ("mean_y", my), ("variance_x", vx), ("variance_y", vy),
        ("covariance", cov), ("score_x", dot(x, public_weights)), ("score_y", dot(y, public_weights)),
    ))


def analytics_reference(inputs: dict[str, Sequence[float]]) -> dict[str, float]:
    """Original centered float formula, independent of the raw-moment graph."""
    x, y = inputs["x"], inputs["y"]
    n = len(x)
    if len(y) != n or not n:
        raise ValueError("matching nonempty vectors required")
    mx, my = math.fsum(x) / n, math.fsum(y) / n
    return {
        "mean_x": mx, "mean_y": my,
        "variance_x": math.fsum((v - mx) ** 2 for v in x) / n,
        "variance_y": math.fsum((v - my) ** 2 for v in y) / n,
        "covariance": math.fsum((a - mx) * (b - my) for a, b in zip(x, y)) / n,
        "score_x": math.fsum(v * (i + 1) / (n * n) for i, v in enumerate(x)),
        "score_y": math.fsum(v * (i + 1) / (n * n) for i, v in enumerate(y)),
    }


def _target(x: Sequence[float]) -> float:
    # Original synthetic response includes a small interaction, deliberately outside
    # the fitted linear model. Task error is reported separately from CKKS error.
    return 0.4 * x[0] + 0.25 * x[1] - 0.3 * x[2] + 0.15 * x[3] + 0.05 * x[0] * x[1]


def train_model() -> tuple[float, ...]:
    """Deterministic ordinary least squares on 256 generated training examples."""
    rng = random.Random(6417)
    rows = [tuple(rng.uniform(-1, 1) for _ in range(4)) for _ in range(256)]
    augmented = [
        [math.fsum(x[i] * x[j] for x in rows) for j in range(4)] +
        [math.fsum(x[i] * _target(x) for x in rows)] for i in range(4)
    ]
    for column in range(4):
        pivot = max(range(column, 4), key=lambda i: abs(augmented[i][column]))
        augmented[column], augmented[pivot] = augmented[pivot], augmented[column]
        divisor = augmented[column][column]
        if abs(divisor) < 1e-12:
            raise ValueError("singular public training fixture")
        augmented[column] = [x / divisor for x in augmented[column]]
        for row in range(4):
            if row != column:
                factor = augmented[row][column]
                augmented[row] = [a - factor * b for a, b in zip(augmented[row], augmented[column])]
    return tuple(row[-1] for row in augmented)


def trained_model(n: int = 4) -> Workload:
    if n != 4:
        raise ValueError("the included public model has four fixed features")
    features = private("features", 4)
    return Workload("trained_model", (features,), (("prediction", dot(features, train_model())),))


def model_reference(inputs: dict[str, Sequence[float]]) -> dict[str, float]:
    weights = train_model()
    return {"prediction": math.fsum(x * w for x, w in zip(inputs["features"], weights))}


def model_task_accuracy() -> dict[str, float | int]:
    weights = train_model()
    rng = random.Random(94531)
    rows = [tuple(rng.uniform(-1, 1) for _ in range(4)) for _ in range(128)]
    errors = [math.fsum(x * w for x, w in zip(row, weights)) - _target(row) for row in rows]
    return {"train_samples": 256, "test_samples": 128,
            "rmse": math.sqrt(math.fsum(e * e for e in errors) / len(errors)),
            "max_abs_error": max(map(abs, errors))}
