import base64
from collections.abc import Iterator

import pytest
from cryptography.exceptions import InvalidTag

from argus.core import secrets
from argus.core.config import get_settings

K1 = base64.b64encode(b"1" * 32).decode()
K2 = base64.b64encode(b"2" * 32).decode()


@pytest.fixture(autouse=True)
def keyring(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("ARGUS_SECRET_KEYS", f"k2:{K2},k1:{K1}")
    monkeypatch.setenv("ARGUS_SECRET_KEY_ID", "k2")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()  # later tests must not see this keyring


def test_round_trip_with_the_current_key() -> None:
    sealed = secrets.seal("wJalr-secret", binding="connection:aws:123456789012")
    assert sealed.key_id == "k2"
    assert b"wJalr" not in sealed.blob
    assert secrets.unseal(sealed, binding="connection:aws:123456789012") == "wJalr-secret"


def test_a_ciphertext_moved_to_another_row_does_not_open() -> None:
    sealed = secrets.seal("wJalr-secret", binding="connection:aws:123456789012")
    with pytest.raises(InvalidTag):
        secrets.unseal(sealed, binding="connection:aws:999999999999")


def test_old_rows_open_after_rotation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARGUS_SECRET_KEY_ID", "k1")
    get_settings.cache_clear()
    old = secrets.seal("old", binding="b")
    monkeypatch.setenv("ARGUS_SECRET_KEY_ID", "k2")
    get_settings.cache_clear()
    assert secrets.unseal(old, binding="b") == "old"


def test_missing_keyring_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ARGUS_SECRET_KEYS")
    get_settings.cache_clear()
    with pytest.raises(secrets.SecretsNotConfiguredError):
        secrets.seal("x", binding="b")


def test_nonces_differ_between_seals() -> None:
    assert secrets.seal("x", binding="b").blob != secrets.seal("x", binding="b").blob
