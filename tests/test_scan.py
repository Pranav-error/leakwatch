from pathlib import Path

from leakwatch.detectors.scan import scan

FIXTURE = Path(__file__).parent / "fixtures" / "leaky.env"


def _providers(text, allowlist=None):
    return {m.provider for m in scan(text, allowlist)}


def test_detects_expected_providers():
    text = FIXTURE.read_text()
    found = _providers(text)
    for expected in {
        "aws_access_key_id",
        "aws_secret_access_key",
        "openai_api_key",
        "stripe_secret_key",
        "google_api_key",
        "slack_token",
        "github_pat",
    }:
        assert expected in found, f"missed {expected}"


def test_low_entropy_placeholder_is_ignored():
    # The xxxx placeholder stripe key must not be reported.
    matches = [m for m in scan("KEY=sk_live_xxxxxxxxxxxxxxxxxxxx")]
    assert matches == []


def test_weak_password_not_flagged_as_generic_secret():
    # hunter2 is short and low-entropy; the generic rule must not fire.
    assert "generic_assignment" not in _providers('DB_PASSWORD=hunter2')


def test_line_numbers_are_reported():
    text = "line1\nAWS=AKIAIOSFODNN7EXAMPLE\nline3"
    matches = list(scan(text))
    assert matches[0].line == 2


def test_repr_never_leaks_raw():
    text = "AWS=AKIAIOSFODNN7EXAMPLE"
    m = list(scan(text))[0]
    assert "AKIAIOSFODNN7EXAMPLE" not in repr(m)


def test_allowlist_filters():
    text = FIXTURE.read_text()
    only_aws = _providers(text, ["aws_access_key_id"])
    assert only_aws == {"aws_access_key_id"}
