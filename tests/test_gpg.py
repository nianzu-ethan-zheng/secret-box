import pytest
from secretbox.core.gpg import (
    encrypt_bytes,
    decrypt_bytes,
    gpg_available,
    DecryptError,
)


def test_gpg_available():
    assert gpg_available() is True


def test_roundtrip(gpg_passphrase):
    ct = encrypt_bytes(b"hello world", gpg_passphrase)
    assert ct != b"hello world"
    pt = decrypt_bytes(ct, gpg_passphrase)
    assert pt == b"hello world"


def test_roundtrip_empty(gpg_passphrase):
    ct = encrypt_bytes(b"", gpg_passphrase)
    assert decrypt_bytes(ct, gpg_passphrase) == b""


def test_roundtrip_large(gpg_passphrase):
    payload = b"A" * (5 * 1024 * 1024)
    ct = encrypt_bytes(payload, gpg_passphrase)
    assert decrypt_bytes(ct, gpg_passphrase) == payload


def test_decrypt_wrong_passphrase_raises(gpg_passphrase, wrong_passphrase):
    ct = encrypt_bytes(b"secret", gpg_passphrase)
    with pytest.raises(DecryptError):
        decrypt_bytes(ct, wrong_passphrase)


def test_decrypt_garbage_raises(gpg_passphrase):
    with pytest.raises(DecryptError):
        decrypt_bytes(b"not gpg data at all", gpg_passphrase)
