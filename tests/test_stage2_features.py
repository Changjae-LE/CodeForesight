import pandas as pd

from codeforesight.stage2.features import (
    _future_sum,
)


def test_future_sum_excludes_current_month():
    series = pd.Series(
        [1.0, 2.0, 3.0, 4.0, 5.0]
    )
    result = _future_sum(
        series,
        horizon=2,
    )

    assert result.iloc[0] == 5.0
    assert result.iloc[1] == 7.0
    assert pd.isna(result.iloc[-2])
    assert pd.isna(result.iloc[-1])
