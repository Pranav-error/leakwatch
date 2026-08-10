from leakwatch.core.redact import Redacted, fingerprint, mask, redact

# A fake, non-live key of AWS-shaped length used only to exercise redaction.
SAMPLE = "AKIAIOSFODNN7EXAMPLE"


def test_fingerprint_is_stable_and_non_reversible():
    fp = fingerprint(SAMPLE)
    assert fp == fingerprint(SAMPLE)  # stable
    assert len(fp) == 64  # sha256 hex
    assert SAMPLE not in fp  # the secret text is not present in the digest


def test_fingerprint_differs_per_secret():
    assert fingerprint("AKIAIOSFODNN7EXAMPLE") != fingerprint("AKIAIOSFODNN7DIFFEREN")


def test_mask_reveals_only_edges():
    m = mask(SAMPLE)
    assert m == "AKIA…MPLE"
    # the interior of the secret must not appear in the mask
    assert "IOSFODNN7EXA" not in m


def test_mask_hides_short_secrets_entirely():
    assert mask("shortkey") == "…"


def test_redacted_has_no_raw_field():
    r = redact(SAMPLE)
    assert isinstance(r, Redacted)
    # the dataclass exposes only non-reversible fields
    assert set(vars(r).keys()) == {"fingerprint", "preview", "length"}
    # neither the object's fields nor its repr may contain the raw secret
    assert SAMPLE not in repr(r)
    assert all(SAMPLE not in str(v) for v in vars(r).values())
    assert r.length == len(SAMPLE)
