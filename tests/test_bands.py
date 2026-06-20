from depwatch.scoring.bands import FailOn, RiskBand, classify, should_fail


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


def test_should_fail_off_never_trips() -> None:
    for band in RiskBand:
        assert should_fail(band, FailOn.OFF) is False


def test_should_fail_trips_at_or_above_threshold() -> None:
    assert should_fail(RiskBand.HIGH, FailOn.HIGH) is True
    assert should_fail(RiskBand.CRITICAL, FailOn.HIGH) is True
    assert should_fail(RiskBand.MODERATE, FailOn.HIGH) is False
    assert should_fail(RiskBand.LOW, FailOn.MODERATE) is False
    assert should_fail(RiskBand.MODERATE, FailOn.MODERATE) is True
    assert should_fail(RiskBand.HIGH, FailOn.CRITICAL) is False
