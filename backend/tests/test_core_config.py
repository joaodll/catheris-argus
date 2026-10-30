import pytest

from argus.core.config import Settings


def test_database_url_never_renders_the_password(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARGUS_DB_PASSWORD", "s3cret-value")

    settings = Settings()

    assert "s3cret-value" not in repr(settings)
    assert "s3cret-value" not in str(settings.database_url())
    assert settings.database_url().password == "s3cret-value"


def test_database_tls_goes_into_the_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARGUS_DB_PASSWORD", "s3cret-value")
    assert Settings().database_url().query == {}  # the driver's default

    monkeypatch.setenv("ARGUS_DB_SSLMODE", "verify-full")
    monkeypatch.setenv("ARGUS_DB_SSLROOTCERT", "/etc/argus/db-ca.pem")
    url = Settings().database_url()
    assert url.query == {"sslmode": "verify-full", "sslrootcert": "/etc/argus/db-ca.pem"}


def test_an_unknown_sslmode_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARGUS_DB_PASSWORD", "s3cret-value")
    monkeypatch.setenv("ARGUS_DB_SSLMODE", "verify-everything")
    with pytest.raises(ValueError, match="db_sslmode"):
        Settings()
