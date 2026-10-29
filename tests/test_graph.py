import math

import pytest

from ciphershape.apps import analytics, analytics_reference, model_task_accuracy, train_model, trained_model
from ciphershape.graph import Budget, Node, Workload, evaluate, metadata, mul, private, scale, sum_, validate_inputs


def test_analytics_three_formula_semantics_at_boundaries():
    w = analytics()
    x = (-1.0, 1.0) * 4
    y = (1.0, -1.0) * 4
    original = analytics_reference({"x": x, "y": y})
    lowered = evaluate(w, {"x": x, "y": y})
    assert lowered == pytest.approx(original, abs=1e-14)
    assert lowered["variance_x"] == 1
    assert lowered["covariance"] == -1
    assert w.validate().output_depth == 3


def test_changed_inputs_and_cancellation():
    w = analytics()
    first = {"x": [1.0, -1.0] * 4, "y": [1.0] * 8}
    second = {"x": [0.25] * 8, "y": [-0.5] * 8}
    assert evaluate(w, first)["mean_x"] == 0
    assert evaluate(w, second)["mean_x"] == 0.25
    assert evaluate(w, second) == pytest.approx(analytics_reference(second), abs=1e-14)


@pytest.mark.parametrize("n", [0, 3, 65, True])
def test_invalid_shapes(n):
    with pytest.raises(ValueError):
        private("x", n)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), True, "1"])
def test_client_rejects_nonfinite_or_non_numeric_values(bad):
    with pytest.raises(ValueError):
        validate_inputs(trained_model(), {"features": [bad, 0, 0, 0]})


def test_client_checks_ranges_names_and_lengths():
    w = trained_model()
    for values in ({"features": [1.001, 0, 0, 0]}, {"other": [0] * 4}, {"features": [0] * 3}):
        with pytest.raises(ValueError):
            validate_inputs(w, values)


def test_unknown_ops_forged_shape_and_undeclared_input_rejected():
    x = private("x", 4)
    for node in (Node("decrypt", (x,)), Node("sum", (x,), shape=(4,)), sum_(private("y", 4))):
        with pytest.raises(ValueError):
            Workload("bad", (x,), (("result", node),)).validate()


def test_depth_includes_plain_multiplication_and_output_mask():
    x = private("x", 4)
    v = scale(mul(x, x), 0.5)
    assert metadata(v).depth == 2
    with pytest.raises(ValueError, match="masking"):
        Workload("deep", (x,), (("result", sum_(v)),), max_depth=2).validate()


def test_explicit_scalar_outputs_and_resource_limits():
    x = private("x", 4)
    with pytest.raises(ValueError, match="scalar"):
        Workload("bad", (x,), (("result", x),)).validate()
    with pytest.raises(ValueError, match="node budget"):
        Workload("small", (x,), (("result", sum_(x)),), budget=Budget(max_nodes=1)).validate()
    with pytest.raises(ValueError):
        Workload("bad", (x,), (("result", sum_(x)),), budget=Budget(requests=0)).validate()


def test_model_is_trained_and_reports_separate_task_error():
    weights = train_model()
    assert len(weights) == 4 and all(math.isfinite(w) for w in weights)
    assert weights != (0.4, 0.25, -0.3, 0.15)
    accuracy = model_task_accuracy()
    assert accuracy["train_samples"] == 256 and accuracy["test_samples"] == 128
    assert 0 < accuracy["rmse"] < 0.03
    result = evaluate(trained_model(), {"features": [1, -1, 0.5, 0]})
    assert result["prediction"] == pytest.approx(weights[0] - weights[1] + 0.5 * weights[2])
