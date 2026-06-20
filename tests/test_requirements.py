from depwatch.core.requirements import parse_requirements


def test_parses_pinned_and_unpinned() -> None:
    reqs = parse_requirements(["flask==2.0.1", "requests"])
    versions = {r.name: r.version for r in reqs}
    assert versions["flask"] == "2.0.1"
    assert versions["requests"] is None


def test_skips_comments_blanks_and_options() -> None:
    reqs = parse_requirements(
        [
            "# a comment",
            "",
            "   ",
            "-r other.txt",
            "-e .",
            "--hash=sha256:abc",
            "numpy==1.26.4  # inline comment",
        ]
    )
    assert [r.name for r in reqs] == ["numpy"]
    assert reqs[0].version == "1.26.4"


def test_normalizes_names_and_ignores_extras() -> None:
    reqs = parse_requirements(["Flask_Login==0.6.3", "uvicorn[standard]==0.30.0"])
    versions = {r.name: r.version for r in reqs}
    assert versions["flask-login"] == "0.6.3"
    assert versions["uvicorn"] == "0.30.0"
