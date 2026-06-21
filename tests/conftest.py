import os
import shutil
from pathlib import Path
import pytest


@pytest.fixture
def gpg_passphrase() -> str:
    return "correct horse battery staple"


@pytest.fixture
def wrong_passphrase() -> str:
    return "wrong password"


@pytest.fixture
def tmp_data_dir(tmp_path: Path) -> Path:
    d = tmp_path / "data"
    d.mkdir()
    return d


@pytest.fixture
def tmp_session_dir(tmp_path: Path, monkeypatch) -> Path:
    d = tmp_path / "session"
    monkeypatch.setenv("SECRETBOX_SESSION_DIR_OVERRIDE", str(d))
    return d


@pytest.fixture(autouse=True)
def require_gpg():
    if shutil.which("gpg") is None:
        pytest.skip("gpg binary not on PATH")
