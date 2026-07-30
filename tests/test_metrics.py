import numpy as np

from codeforesight.stage2.model import (
    _metric_set,
)


def test_metric_set_perfect_prediction():
    y = np.array(
        [1.0, 2.0, 4.0]
    )
    current = np.array(
        [0.0, 3.0, 4.0]
    )

    metrics = _metric_set(
        y,
        y,
        current,
    )

    assert metrics["mae"] == 0.0
    assert metrics["rmse"] == 0.0
    assert (
        metrics[
            "directional_accuracy"
        ]
        == 1.0
    )
