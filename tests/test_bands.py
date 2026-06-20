from depwatch.scoring.bands import RiskBand, classify


def test_classify_at_each_boundary() -> None:
    assert classify(0.0) is RiskBand.LOW
    assert classify(0.149) is RiskBand.LOW
    assert classify(0.15) is RiskBand.MODERATE
    assert classify(0.299) is RiskBand.MODERATE
    assert classify(0.30) is RiskBand.HIGH
    assert classify(0.499) is RiskBand.HIGH
    assert classify(0.50) is RiskBand.CRITICAL
    assert classify(1.0) is RiskBand.CRITICAL


def test_classify_never_decreases_as_score_rises() -> None:
    order = [RiskBand.LOW, RiskBand.MODERATE, RiskBand.HIGH, RiskBand.CRITICAL]
    previous = 0
    for step in range(0, 101):
        current = order.index(classify(step / 100))
        assert current >= previous
        previous = current
