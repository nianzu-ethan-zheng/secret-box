import json
import os
import stat
import time
import pytest
from secretbox.core.session import (
    write_session,
    read_session,
    clear_session,
    session_status,
    session_dir,
    session_file,
    DEFAULT_TTL,
)


def test_read_returns_none_when_missing(tmp_session_dir):
    assert read_session() is None


def test_write_then_read(tmp_session_dir):
    write_session("secret pass")
    assert read_session() == "secret pass"


def test_write_creates_dir_700(tmp_session_dir):
    write_session("x")
    mode = stat.S_IMODE(session_dir().stat().st_mode)
    assert mode == 0o700


def test_write_creates_file_600(tmp_session_dir):
    write_session("x")
    mode = stat.S_IMODE(session_file().stat().st_mode)
    assert mode == 0o600


def test_expired_returns_none_and_deletes(tmp_session_dir):
    write_session("x", ttl=1)
    time.sleep(1.2)
    assert read_session() is None
    assert not session_file().exists()


def test_clear_removes_file(tmp_session_dir):
    write_session("x")
    clear_session()
    assert read_session() is None


def test_clear_when_missing_is_noop(tmp_session_dir):
    clear_session()


def test_status_logged_out(tmp_session_dir):
    s = session_status()
    assert s["logged_in"] is False
    assert s["expires_in_seconds"] is None


def test_status_logged_in(tmp_session_dir):
    write_session("x", ttl=100)
    s = session_status()
    assert s["logged_in"] is True
    assert 90 <= s["expires_in_seconds"] <= 100


def test_default_ttl_from_env(tmp_session_dir, monkeypatch):
    monkeypatch.setenv("SECRETBOX_TTL_SECONDS", "60")
    write_session("x")
    s = session_status()
    assert 55 <= s["expires_in_seconds"] <= 60
