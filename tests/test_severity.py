from depwatch.scoring.severity import best_severity, cvss_base_score, label_score

# A high-impact v3 vector (network, low complexity, full CIA) ~ 9.8.
CRITICAL_V3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
# A constrained v3 vector ~ 4.4.
MEDIUM_V3 = "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N"
LOW_IMPACT_V4 = "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H"


def test_cvss_v3_and_v4_base_scores() -> None:
    assert cvss_base_score(MEDIUM_V3) == 4.4
    assert cvss_base_score(LOW_IMPACT_V4) == 8.9


def test_cvss_unparseable_is_none() -> None:
    assert cvss_base_score("not-a-vector") is None
    assert cvss_base_score("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P") is None  # v2 not supported
    assert cvss_base_score("CVSS:3.1/garbage") is None


def test_label_score_maps_known_labels() -> None:
    assert label_score("CRITICAL") == 9.5
    assert label_score("high") == 7.5
    assert label_score("MODERATE") == 5.0
    assert label_score("medium") == 5.0
    assert label_score("low") == 2.0
    assert label_score("nonsense") is None
    assert label_score(None) is None


def test_best_severity_prefers_cvss_over_label() -> None:
    # A real CVSS vector wins even if the coarse label disagrees.
    score = best_severity([CRITICAL_V3], "LOW")
    assert score is not None and score > 8.0


def test_best_severity_takes_the_highest_cvss() -> None:
    assert best_severity([MEDIUM_V3, CRITICAL_V3], None) == cvss_base_score(CRITICAL_V3)


def test_best_severity_falls_back_to_label() -> None:
    assert best_severity([], "HIGH") == 7.5


def test_best_severity_is_none_when_nothing_is_known() -> None:
    assert best_severity([], None) is None
