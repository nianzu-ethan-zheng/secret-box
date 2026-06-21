import pytest
from pathlib import Path
from secretbox.core.storage import (
    list_entries,
    add_entry,
    get_entry,
    remove_entry,
    verify_passphrase,
    ensure_sentinel,
    SentinelMissing,
    EntryExists,
    InvalidName,
    SENTINEL_NAME,
)


def test_empty_list(tmp_data_dir):
    assert list_entries(tmp_data_dir) == []


def test_verify_without_sentinel_raises(tmp_data_dir, gpg_passphrase):
    with pytest.raises(SentinelMissing):
        verify_passphrase(tmp_data_dir, gpg_passphrase)


def test_ensure_sentinel_creates_file(tmp_data_dir, gpg_passphrase):
    ensure_sentinel(tmp_data_dir, gpg_passphrase)
    assert (tmp_data_dir / SENTINEL_NAME).exists()


def test_ensure_sentinel_idempotent(tmp_data_dir, gpg_passphrase):
    ensure_sentinel(tmp_data_dir, gpg_passphrase)
    mtime_before = (tmp_data_dir / SENTINEL_NAME).stat().st_mtime_ns
    ensure_sentinel(tmp_data_dir, gpg_passphrase)
    assert (tmp_data_dir / SENTINEL_NAME).stat().st_mtime_ns == mtime_before


def test_verify_correct_passphrase(tmp_data_dir, gpg_passphrase):
    ensure_sentinel(tmp_data_dir, gpg_passphrase)
    assert verify_passphrase(tmp_data_dir, gpg_passphrase) is True


def test_verify_wrong_passphrase(tmp_data_dir, gpg_passphrase, wrong_passphrase):
    ensure_sentinel(tmp_data_dir, gpg_passphrase)
    assert verify_passphrase(tmp_data_dir, wrong_passphrase) is False


def test_add_creates_sentinel_on_first_call(tmp_data_dir, gpg_passphrase, tmp_path):
    src = tmp_path / "note.txt"
    src.write_bytes(b"hello")
    add_entry(tmp_data_dir, src, gpg_passphrase)
    assert (tmp_data_dir / SENTINEL_NAME).exists()


def test_add_deletes_source(tmp_data_dir, gpg_passphrase, tmp_path):
    src = tmp_path / "note.txt"
    src.write_bytes(b"hello")
    add_entry(tmp_data_dir, src, gpg_passphrase)
    assert not src.exists()


def test_add_creates_encrypted_file(tmp_data_dir, gpg_passphrase, tmp_path):
    src = tmp_path / "note.txt"
    src.write_bytes(b"hello")
    name = add_entry(tmp_data_dir, src, gpg_passphrase)
    assert name == "note.txt"
    assert (tmp_data_dir / "note.txt.gpg").exists()


def test_add_then_get(tmp_data_dir, gpg_passphrase, tmp_path):
    src = tmp_path / "note.txt"
    src.write_bytes(b"hello world")
    add_entry(tmp_data_dir, src, gpg_passphrase)
    assert get_entry(tmp_data_dir, "note.txt", gpg_passphrase) == b"hello world"


def test_add_refuses_overwrite(tmp_data_dir, gpg_passphrase, tmp_path):
    src1 = tmp_path / "note.txt"
    src1.write_bytes(b"v1")
    add_entry(tmp_data_dir, src1, gpg_passphrase)
    src2 = tmp_path / "note.txt"
    src2.write_bytes(b"v2")
    with pytest.raises(EntryExists):
        add_entry(tmp_data_dir, src2, gpg_passphrase)


def test_add_force_overwrites(tmp_data_dir, gpg_passphrase, tmp_path):
    src1 = tmp_path / "note.txt"
    src1.write_bytes(b"v1")
    add_entry(tmp_data_dir, src1, gpg_passphrase)
    src2 = tmp_path / "note.txt"
    src2.write_bytes(b"v2")
    add_entry(tmp_data_dir, src2, gpg_passphrase, force=True)
    assert get_entry(tmp_data_dir, "note.txt", gpg_passphrase) == b"v2"


def test_list_excludes_sentinel(tmp_data_dir, gpg_passphrase, tmp_path):
    ensure_sentinel(tmp_data_dir, gpg_passphrase)
    src = tmp_path / "a.txt"
    src.write_bytes(b"x")
    add_entry(tmp_data_dir, src, gpg_passphrase)
    assert list_entries(tmp_data_dir) == ["a.txt"]


def test_list_sorted(tmp_data_dir, gpg_passphrase, tmp_path):
    for n in ["c", "a", "b"]:
        p = tmp_path / n
        p.write_bytes(b"x")
        add_entry(tmp_data_dir, p, gpg_passphrase)
    assert list_entries(tmp_data_dir) == ["a", "b", "c"]


def test_remove(tmp_data_dir, gpg_passphrase, tmp_path):
    src = tmp_path / "n.txt"
    src.write_bytes(b"x")
    add_entry(tmp_data_dir, src, gpg_passphrase)
    remove_entry(tmp_data_dir, "n.txt")
    assert "n.txt" not in list_entries(tmp_data_dir)


def test_remove_missing_raises(tmp_data_dir):
    with pytest.raises(FileNotFoundError):
        remove_entry(tmp_data_dir, "nope")


@pytest.mark.parametrize("bad", ["../etc/passwd", "a/b", "/abs", ""])
def test_invalid_names_rejected(tmp_data_dir, gpg_passphrase, bad):
    with pytest.raises(InvalidName):
        get_entry(tmp_data_dir, bad, gpg_passphrase)
    with pytest.raises(InvalidName):
        remove_entry(tmp_data_dir, bad)
