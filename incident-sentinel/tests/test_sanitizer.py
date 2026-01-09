from core.sanitizer import sanitize


def test_masks_bearer_jwt() -> None:
    raw = (
        "Authorization: Bearer "
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.signature"
    )
    assert sanitize(raw) == "Authorization: Bearer [REDACTED]"


def test_masks_database_uri_password() -> None:
    raw = "connect postgres://app:s3cret@db:5432/billing failed"
    assert (
        sanitize(raw)
        == "connect postgres://app:[MASKED_PASSWORD]@db:5432/billing failed"
    )


def test_masks_quoted_secrets() -> None:
    raw = "boot api_key='sk-live' password=\"hunter2\" token: 'abc.def'"
    cleaned = sanitize(raw)
    assert "sk-live" not in cleaned
    assert "hunter2" not in cleaned
    assert "abc.def" not in cleaned
    assert 'api_key: "[REDACTED]"' in cleaned
    assert 'password: "[REDACTED]"' in cleaned
    assert 'token: "[REDACTED]"' in cleaned


def test_masks_private_key_block() -> None:
    raw = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0\n"
        "-----END RSA PRIVATE KEY-----"
    )
    assert sanitize(raw) == "[REDACTED_RSA_KEY]"


def test_leaves_ordinary_log_line() -> None:
    raw = "INFO worker started on port 8080"
    assert sanitize(raw) == raw
