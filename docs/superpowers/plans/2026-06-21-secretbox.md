# Secretbox Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a single-user local GPG-symmetric file vault with a CLI (sourced via `env.sh`) and a Flask web UI sharing one data directory.

**Architecture:** One Python package `secretbox` with three core modules (`gpg`, `storage`, `session`) used by two front-ends (`cli.py`, `web/`). GPG passphrase is never written to disk except a 0600 tmpfs session file for the CLI; web holds it in process memory only. A sentinel file `.secretbox-check.gpg` validates passphrase entries.

**Tech Stack:** Python 3.11+, click, Flask, python-dotenv, bcrypt, pytest. System `gpg` 2.x binary via subprocess (no `python-gnupg`).

## Global Constraints

- Python 3.11 or newer.
- GPG accessed via subprocess only — no `python-gnupg` or other GPG library.
- Cipher pinned to AES256 in all encrypt calls.
- Passphrase passed to `gpg` via stdin (`--passphrase-fd 0`), never via argv or env.
- Web binds `127.0.0.1` only — never `0.0.0.0`.
- Read operations (`cat`, `list`, web viewer) may use cached/in-memory passphrase. Write operations (`add`, web import) MUST re-prompt for passphrase even when a session/memory copy exists.
- Linux/WSL2 only — relies on `/run/user/$UID` tmpfs (with fallback documented).
- Sentinel filename: `.secretbox-check.gpg`; plaintext: `b"OK"`.
- Default web port `8765`, override via `SECRETBOX_WEB_PORT`.
- Default session TTL `1800` seconds, override via `SECRETBOX_TTL_SECONDS`.

---

## File Structure

```
secretbox/
├── env.sh                              # Task 6
├── pyproject.toml                      # Task 1
├── .env.example                        # Task 1
├── .gitignore                          # Task 1
├── README.md                           # Task 9
├── data/                               # gitignored, created at runtime
├── src/secretbox/
│   ├── __init__.py                     # Task 1
│   ├── core/
│   │   ├── __init__.py                 # Task 1
│   │   ├── gpg.py                      # Task 2
│   │   ├── storage.py                  # Task 3
│   │   └── session.py                  # Task 4
│   ├── cli.py                          # Task 5
│   └── web/
│       ├── __init__.py                 # Task 7
│       ├── __main__.py                 # Task 9
│       ├── app.py                      # Tasks 7-8
│       ├── templates/                  # Task 9
│       │   ├── base.html
│       │   ├── login.html
│       │   ├── unlock.html
│       │   └── index.html
│       └── static/                     # Task 9
│           ├── app.js
│           └── app.css
└── tests/
    ├── conftest.py                     # Task 1
    ├── test_gpg.py                     # Task 2
    ├── test_storage.py                 # Task 3
    ├── test_session.py                 # Task 4
    ├── test_cli.py                     # Task 5
    └── test_web.py                     # Tasks 7-8
```

---

### Task 1: Project Scaffold

**Files:**
- Create: `pyproject.toml`, `.gitignore`, `.env.example`
- Create: `src/secretbox/__init__.py`, `src/secretbox/core/__init__.py`
- Create: `tests/conftest.py`, `tests/__init__.py`

**Interfaces:**
- Consumes: nothing
- Produces: installable package `secretbox` with version `0.1.0`; pytest fixtures `tmp_data_dir`, `tmp_session_dir`, `gpg_passphrase`

- [ ] **Step 1: Create `pyproject.toml`**

```toml
[project]
name = "secretbox"
version = "0.1.0"
description = "Local GPG-symmetric file vault with CLI and web UI"
requires-python = ">=3.11"
dependencies = [
    "click>=8.1",
    "flask>=3.0",
    "python-dotenv>=1.0",
    "bcrypt>=4.1",
]

[project.optional-dependencies]
dev = ["pytest>=8.0"]

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

- [ ] **Step 2: Create `.gitignore`**

```
.venv/
__pycache__/
*.pyc
.pytest_cache/
*.egg-info/
data/
.env
```

- [ ] **Step 3: Create `.env.example`**

```
# Bcrypt hash of the web login password.
# Generate with: python -c "import bcrypt,getpass; print(bcrypt.hashpw(getpass.getpass().encode(),bcrypt.gensalt()).decode())"
SECRETBOX_LOGIN_HASH=

# Flask session-cookie signing key. Any random string.
SECRETBOX_FLASK_SECRET=

# Optional: override defaults.
# SECRETBOX_WEB_PORT=8765
# SECRETBOX_TTL_SECONDS=1800
```

- [ ] **Step 4: Create package `__init__.py` files**

`src/secretbox/__init__.py`:
```python
__version__ = "0.1.0"
```

`src/secretbox/core/__init__.py`:
```python
```

`tests/__init__.py`:
```python
```

- [ ] **Step 5: Create `tests/conftest.py` with shared fixtures**

```python
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
```

- [ ] **Step 6: Install and verify**

Run:
```bash
cd /home/nianzuzheng/work/secretbox
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest --collect-only
```

Expected: pytest collects 0 tests, no errors. Package imports cleanly.

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml .gitignore .env.example src/ tests/
git commit -m "chore: project scaffold"
```

---

### Task 2: `core/gpg.py` — GPG subprocess wrapper

**Files:**
- Create: `src/secretbox/core/gpg.py`
- Create: `tests/test_gpg.py`

**Interfaces:**
- Consumes: system `gpg` binary
- Produces:
  - `encrypt_bytes(plaintext: bytes, passphrase: str) -> bytes`
  - `decrypt_bytes(ciphertext: bytes, passphrase: str) -> bytes` — raises `DecryptError` on bad passphrase
  - `gpg_available() -> bool`
  - exception `class DecryptError(Exception): pass`

- [ ] **Step 1: Write failing tests**

`tests/test_gpg.py`:
```python
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
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `.venv/bin/pytest tests/test_gpg.py -v`
Expected: `ModuleNotFoundError: secretbox.core.gpg`

- [ ] **Step 3: Implement `core/gpg.py`**

```python
import shutil
import subprocess


class DecryptError(Exception):
    pass


def gpg_available() -> bool:
    return shutil.which("gpg") is not None


def _run_gpg(args: list[str], stdin: bytes, passphrase: str) -> tuple[int, bytes, bytes]:
    full_args = [
        "gpg",
        "--batch",
        "--quiet",
        "--pinentry-mode", "loopback",
        "--passphrase-fd", "0",
        *args,
    ]
    proc = subprocess.Popen(
        full_args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    payload = passphrase.encode("utf-8") + b"\n" + stdin
    out, err = proc.communicate(input=payload)
    return proc.returncode, out, err


def encrypt_bytes(plaintext: bytes, passphrase: str) -> bytes:
    rc, out, err = _run_gpg(
        ["--symmetric", "--cipher-algo", "AES256"],
        plaintext,
        passphrase,
    )
    if rc != 0:
        raise RuntimeError(f"gpg encrypt failed (rc={rc})")
    return out


def decrypt_bytes(ciphertext: bytes, passphrase: str) -> bytes:
    rc, out, err = _run_gpg(["--decrypt"], ciphertext, passphrase)
    if rc != 0:
        raise DecryptError("passphrase incorrect or data corrupt")
    return out
```

- [ ] **Step 4: Run tests, verify they pass**

Run: `.venv/bin/pytest tests/test_gpg.py -v`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add src/secretbox/core/gpg.py tests/test_gpg.py
git commit -m "feat(core): gpg subprocess wrapper with symmetric AES256"
```

---

### Task 3: `core/storage.py` — File vault operations

**Files:**
- Create: `src/secretbox/core/storage.py`
- Create: `tests/test_storage.py`

**Interfaces:**
- Consumes: `core.gpg.encrypt_bytes`, `core.gpg.decrypt_bytes`, `core.gpg.DecryptError`
- Produces:
  - `list_entries(data_dir: Path) -> list[str]` — sorted, excludes sentinel
  - `add_entry(data_dir: Path, source: Path, passphrase: str, force: bool=False) -> str`
  - `get_entry(data_dir: Path, name: str, passphrase: str) -> bytes`
  - `remove_entry(data_dir: Path, name: str) -> None` — raises `FileNotFoundError`
  - `verify_passphrase(data_dir: Path, passphrase: str) -> bool` — raises `SentinelMissing` if no sentinel
  - `ensure_sentinel(data_dir: Path, passphrase: str) -> None`
  - exceptions: `SentinelMissing`, `EntryExists`, `InvalidName`
  - constants: `SENTINEL_NAME = ".secretbox-check.gpg"`, `SENTINEL_PLAINTEXT = b"OK"`

- [ ] **Step 1: Write failing tests**

`tests/test_storage.py`:
```python
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
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `.venv/bin/pytest tests/test_storage.py -v`
Expected: `ModuleNotFoundError`.

- [ ] **Step 3: Implement `core/storage.py`**

```python
from pathlib import Path

from .gpg import encrypt_bytes, decrypt_bytes, DecryptError


SENTINEL_NAME = ".secretbox-check.gpg"
SENTINEL_PLAINTEXT = b"OK"


class SentinelMissing(Exception):
    pass


class EntryExists(Exception):
    pass


class InvalidName(Exception):
    pass


def _validate_name(name: str) -> None:
    if not name:
        raise InvalidName("empty name")
    if "/" in name or "\\" in name:
        raise InvalidName(f"name may not contain path separators: {name!r}")
    if name.startswith(".."):
        raise InvalidName(f"name may not start with '..': {name!r}")
    if name == SENTINEL_NAME or name == SENTINEL_NAME.removesuffix(".gpg"):
        raise InvalidName("reserved name")


def _entry_path(data_dir: Path, name: str) -> Path:
    _validate_name(name)
    return data_dir / f"{name}.gpg"


def list_entries(data_dir: Path) -> list[str]:
    names = []
    for p in data_dir.glob("*.gpg"):
        if p.name == SENTINEL_NAME:
            continue
        names.append(p.name.removesuffix(".gpg"))
    return sorted(names)


def ensure_sentinel(data_dir: Path, passphrase: str) -> None:
    sentinel = data_dir / SENTINEL_NAME
    if sentinel.exists():
        return
    ct = encrypt_bytes(SENTINEL_PLAINTEXT, passphrase)
    sentinel.write_bytes(ct)


def verify_passphrase(data_dir: Path, passphrase: str) -> bool:
    sentinel = data_dir / SENTINEL_NAME
    if not sentinel.exists():
        raise SentinelMissing("no sentinel yet — add a file first")
    try:
        pt = decrypt_bytes(sentinel.read_bytes(), passphrase)
    except DecryptError:
        return False
    return pt == SENTINEL_PLAINTEXT


def add_entry(
    data_dir: Path, source: Path, passphrase: str, force: bool = False
) -> str:
    name = source.name
    if name.endswith(".gpg"):
        name = name.removesuffix(".gpg")
    _validate_name(name)
    target = data_dir / f"{name}.gpg"
    if target.exists() and not force:
        raise EntryExists(name)
    ensure_sentinel(data_dir, passphrase)
    ct = encrypt_bytes(source.read_bytes(), passphrase)
    target.write_bytes(ct)
    try:
        source.unlink()
    except OSError:
        pass
    return name


def get_entry(data_dir: Path, name: str, passphrase: str) -> bytes:
    p = _entry_path(data_dir, name)
    if not p.exists():
        raise FileNotFoundError(name)
    return decrypt_bytes(p.read_bytes(), passphrase)


def remove_entry(data_dir: Path, name: str) -> None:
    p = _entry_path(data_dir, name)
    if not p.exists():
        raise FileNotFoundError(name)
    p.unlink()
```

- [ ] **Step 4: Run tests, verify they pass**

Run: `.venv/bin/pytest tests/test_storage.py -v`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/secretbox/core/storage.py tests/test_storage.py
git commit -m "feat(core): vault storage with sentinel-based passphrase verification"
```

---

### Task 4: `core/session.py` — Tmpfs session file

**Files:**
- Create: `src/secretbox/core/session.py`
- Create: `tests/test_session.py`

**Interfaces:**
- Consumes: env vars `SECRETBOX_SESSION_DIR_OVERRIDE`, `SECRETBOX_TTL_SECONDS`
- Produces:
  - `session_dir() -> Path` — resolves to override, then `/run/user/$UID/secretbox`, then `tempfile.gettempdir()/secretbox-$UID`
  - `session_file() -> Path` — `session_dir() / "session"`
  - `write_session(passphrase: str, ttl: int | None = None) -> None`
  - `read_session() -> str | None` — returns None if missing or expired; expired files are deleted on read
  - `clear_session() -> None`
  - `session_status() -> dict` — `{"logged_in": bool, "expires_in_seconds": int | None}`
  - constant: `DEFAULT_TTL = 1800`

- [ ] **Step 1: Write failing tests**

`tests/test_session.py`:
```python
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
    clear_session()  # should not raise


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
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `.venv/bin/pytest tests/test_session.py -v`
Expected: `ModuleNotFoundError`.

- [ ] **Step 3: Implement `core/session.py`**

```python
import json
import os
import tempfile
import time
from pathlib import Path


DEFAULT_TTL = 1800


def session_dir() -> Path:
    override = os.environ.get("SECRETBOX_SESSION_DIR_OVERRIDE")
    if override:
        return Path(override)
    uid = os.getuid()
    runtime = Path(f"/run/user/{uid}")
    if runtime.is_dir():
        return runtime / "secretbox"
    return Path(tempfile.gettempdir()) / f"secretbox-{uid}"


def session_file() -> Path:
    return session_dir() / "session"


def _ttl_default() -> int:
    raw = os.environ.get("SECRETBOX_TTL_SECONDS")
    if raw is None:
        return DEFAULT_TTL
    try:
        return int(raw)
    except ValueError:
        return DEFAULT_TTL


def write_session(passphrase: str, ttl: int | None = None) -> None:
    if ttl is None:
        ttl = _ttl_default()
    d = session_dir()
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    f = session_file()
    payload = json.dumps(
        {"passphrase": passphrase, "expires_at": int(time.time()) + ttl}
    ).encode("utf-8")
    fd = os.open(str(f), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)
    os.chmod(f, 0o600)


def read_session() -> str | None:
    f = session_file()
    if not f.exists():
        return None
    try:
        data = json.loads(f.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    if int(time.time()) >= data.get("expires_at", 0):
        try:
            f.unlink()
        except OSError:
            pass
        return None
    return data.get("passphrase")


def clear_session() -> None:
    try:
        session_file().unlink()
    except FileNotFoundError:
        pass


def session_status() -> dict:
    f = session_file()
    if not f.exists():
        return {"logged_in": False, "expires_in_seconds": None}
    try:
        data = json.loads(f.read_text())
    except (OSError, json.JSONDecodeError):
        return {"logged_in": False, "expires_in_seconds": None}
    remaining = data.get("expires_at", 0) - int(time.time())
    if remaining <= 0:
        return {"logged_in": False, "expires_in_seconds": None}
    return {"logged_in": True, "expires_in_seconds": remaining}
```

- [ ] **Step 4: Run tests, verify they pass**

Run: `.venv/bin/pytest tests/test_session.py -v`
Expected: 10 passed.

- [ ] **Step 5: Commit**

```bash
git add src/secretbox/core/session.py tests/test_session.py
git commit -m "feat(core): tmpfs session file with TTL"
```

---

### Task 5: `cli.py` — `app` commands via click

**Files:**
- Create: `src/secretbox/cli.py`
- Create: `tests/test_cli.py`

**Interfaces:**
- Consumes: `core.gpg`, `core.storage`, `core.session`
- Produces: click command group, callable as `python -m secretbox.cli`
- Exit codes: `0` success, `1` auth error, `2` not found, `3` precondition (sentinel missing, exists without force, invalid name), `10` internal

Reads `SECRETBOX_HOME` from env to locate data dir as `$SECRETBOX_HOME/data`. Falls back to `./data` relative to CWD if unset (with a stderr warning).

- [ ] **Step 1: Write failing tests**

`tests/test_cli.py`:
```python
import os
from pathlib import Path
import pytest
from click.testing import CliRunner

from secretbox.cli import cli


@pytest.fixture
def app_env(tmp_path, tmp_session_dir, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    (home / "data").mkdir()
    monkeypatch.setenv("SECRETBOX_HOME", str(home))
    return home


def test_status_logged_out(app_env):
    r = CliRunner().invoke(cli, ["status"])
    assert r.exit_code == 0
    assert "logged_in: False" in r.output


def test_login_no_files_yet(app_env, gpg_passphrase):
    r = CliRunner().invoke(cli, ["login"], input=f"{gpg_passphrase}\n")
    assert r.exit_code == 3
    assert "add a file first" in r.output.lower()


def test_add_then_list_then_cat(app_env, gpg_passphrase, tmp_path):
    src = tmp_path / "note.txt"
    src.write_text("hello")
    runner = CliRunner()
    r = runner.invoke(cli, ["add", str(src)], input=f"{gpg_passphrase}\n")
    assert r.exit_code == 0, r.output

    r = runner.invoke(cli, ["list"])
    assert r.exit_code == 0
    assert "note.txt" in r.output

    r = runner.invoke(cli, ["login"], input=f"{gpg_passphrase}\n")
    assert r.exit_code == 0

    r = runner.invoke(cli, ["cat", "note.txt"])
    assert r.exit_code == 0
    assert "hello" in r.output


def test_wrong_passphrase_on_login_does_not_write_session(
    app_env, gpg_passphrase, wrong_passphrase, tmp_path
):
    src = tmp_path / "note.txt"
    src.write_text("hello")
    runner = CliRunner()
    runner.invoke(cli, ["add", str(src)], input=f"{gpg_passphrase}\n")

    r = runner.invoke(cli, ["login"], input=f"{wrong_passphrase}\n")
    assert r.exit_code == 1
    r = runner.invoke(cli, ["status"])
    assert "logged_in: False" in r.output


def test_cat_without_login_prompts(app_env, gpg_passphrase, tmp_path):
    src = tmp_path / "note.txt"
    src.write_text("hello")
    runner = CliRunner()
    runner.invoke(cli, ["add", str(src)], input=f"{gpg_passphrase}\n")
    r = runner.invoke(cli, ["cat", "note.txt"], input=f"{gpg_passphrase}\n")
    assert r.exit_code == 0
    assert "hello" in r.output


def test_cat_missing_entry(app_env, gpg_passphrase, tmp_path):
    src = tmp_path / "n.txt"
    src.write_text("x")
    runner = CliRunner()
    runner.invoke(cli, ["add", str(src)], input=f"{gpg_passphrase}\n")
    runner.invoke(cli, ["login"], input=f"{gpg_passphrase}\n")
    r = runner.invoke(cli, ["cat", "nope"])
    assert r.exit_code == 2
    assert "no such entry" in r.output.lower()


def test_add_refuses_overwrite(app_env, gpg_passphrase, tmp_path):
    src1 = tmp_path / "n.txt"
    src1.write_text("v1")
    runner = CliRunner()
    runner.invoke(cli, ["add", str(src1)], input=f"{gpg_passphrase}\n")
    src2 = tmp_path / "n.txt"
    src2.write_text("v2")
    r = runner.invoke(cli, ["add", str(src2)], input=f"{gpg_passphrase}\n")
    assert r.exit_code == 3
    assert "exists" in r.output.lower()


def test_rm_with_yes(app_env, gpg_passphrase, tmp_path):
    src = tmp_path / "n.txt"
    src.write_text("x")
    runner = CliRunner()
    runner.invoke(cli, ["add", str(src)], input=f"{gpg_passphrase}\n")
    r = runner.invoke(cli, ["rm", "n.txt", "--yes"])
    assert r.exit_code == 0
    r = runner.invoke(cli, ["list"])
    assert "n.txt" not in r.output


def test_logout(app_env, gpg_passphrase, tmp_path):
    src = tmp_path / "n.txt"
    src.write_text("x")
    runner = CliRunner()
    runner.invoke(cli, ["add", str(src)], input=f"{gpg_passphrase}\n")
    runner.invoke(cli, ["login"], input=f"{gpg_passphrase}\n")
    r = runner.invoke(cli, ["logout"])
    assert r.exit_code == 0
    r = runner.invoke(cli, ["status"])
    assert "logged_in: False" in r.output
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `.venv/bin/pytest tests/test_cli.py -v`
Expected: `ModuleNotFoundError`.

- [ ] **Step 3: Implement `cli.py`**

```python
import os
import sys
from pathlib import Path

import click

from .core import gpg as gpg_mod
from .core import storage
from .core import session


def _data_dir() -> Path:
    home = os.environ.get("SECRETBOX_HOME")
    if home:
        return Path(home) / "data"
    click.echo("warning: SECRETBOX_HOME not set, using ./data", err=True)
    d = Path.cwd() / "data"
    d.mkdir(exist_ok=True)
    return d


def _ensure_gpg() -> None:
    if not gpg_mod.gpg_available():
        click.echo("error: gpg binary not found on PATH", err=True)
        sys.exit(10)


def _get_passphrase(prompt_msg: str = "passphrase") -> str:
    return click.prompt(prompt_msg, hide_input=True)


@click.group()
def cli():
    pass


@cli.command()
def login():
    _ensure_gpg()
    data = _data_dir()
    pw = _get_passphrase()
    try:
        ok = storage.verify_passphrase(data, pw)
    except storage.SentinelMissing:
        click.echo("no files yet — add a file first with `app add <path>`", err=True)
        sys.exit(3)
    if not ok:
        click.echo("passphrase incorrect", err=True)
        sys.exit(1)
    session.write_session(pw)
    click.echo("logged in")


@cli.command()
def logout():
    session.clear_session()
    click.echo("logged out")


@cli.command()
def status():
    s = session.session_status()
    data = _data_dir()
    click.echo(f"data_dir: {data}")
    click.echo(f"logged_in: {s['logged_in']}")
    if s["logged_in"]:
        click.echo(f"expires_in_seconds: {s['expires_in_seconds']}")


@cli.command(name="list")
def list_cmd():
    for name in storage.list_entries(_data_dir()):
        click.echo(name)


@cli.command()
@click.argument("name")
def cat(name: str):
    _ensure_gpg()
    data = _data_dir()
    pw = session.read_session()
    if pw is None:
        pw = _get_passphrase()
    try:
        body = storage.get_entry(data, name, pw)
    except storage.InvalidName as e:
        click.echo(f"invalid name: {e}", err=True)
        sys.exit(3)
    except FileNotFoundError:
        click.echo(f"no such entry: {name}", err=True)
        sys.exit(2)
    except gpg_mod.DecryptError:
        click.echo("passphrase incorrect", err=True)
        sys.exit(1)
    sys.stdout.buffer.write(body)
    if body and not body.endswith(b"\n"):
        sys.stdout.write("\n")


@cli.command()
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--force", is_flag=True, help="overwrite existing entry")
def add(path: Path, force: bool):
    _ensure_gpg()
    data = _data_dir()
    pw = _get_passphrase()
    # If sentinel exists, verify; otherwise this passphrase becomes canonical.
    try:
        ok = storage.verify_passphrase(data, pw)
        if not ok:
            click.echo("passphrase incorrect", err=True)
            sys.exit(1)
    except storage.SentinelMissing:
        pass
    try:
        name = storage.add_entry(data, path, pw, force=force)
    except storage.EntryExists:
        click.echo(f"entry exists, use --force: {path.name}", err=True)
        sys.exit(3)
    except storage.InvalidName as e:
        click.echo(f"invalid name: {e}", err=True)
        sys.exit(3)
    click.echo(f"added: {name}")


@cli.command()
@click.argument("name")
@click.option("--yes", is_flag=True, help="skip confirmation")
def rm(name: str, yes: bool):
    if not yes:
        if not click.confirm(f"remove {name}?"):
            click.echo("cancelled")
            return
    try:
        storage.remove_entry(_data_dir(), name)
    except storage.InvalidName as e:
        click.echo(f"invalid name: {e}", err=True)
        sys.exit(3)
    except FileNotFoundError:
        click.echo(f"no such entry: {name}", err=True)
        sys.exit(2)
    click.echo(f"removed: {name}")


if __name__ == "__main__":
    cli()
```

- [ ] **Step 4: Run tests, verify they pass**

Run: `.venv/bin/pytest tests/test_cli.py -v`
Expected: 9 passed.

- [ ] **Step 5: Run full test suite**

Run: `.venv/bin/pytest -v`
Expected: all tests in `test_gpg.py`, `test_storage.py`, `test_session.py`, `test_cli.py` pass.

- [ ] **Step 6: Commit**

```bash
git add src/secretbox/cli.py tests/test_cli.py
git commit -m "feat(cli): click commands for login/logout/status/list/cat/add/rm"
```

---

### Task 6: `env.sh` — Source-able CLI entry

**Files:**
- Create: `env.sh`

**Interfaces:**
- Consumes: nothing (env-only)
- Produces: shell function `app` available after `source env.sh`; env var `SECRETBOX_HOME`

This task has no automated test; the smoke-test step is the verification.

- [ ] **Step 1: Create `env.sh`**

```bash
#!/usr/bin/env bash
# Source me: source env.sh
# After sourcing: `app login`, `app list`, `app cat <name>`, `app add <path>`,
# `app rm <name>`, `app status`, `app logout`, `secretbox-web`.

if [ -z "${BASH_SOURCE[0]:-}" ]; then
    echo "env.sh: must be sourced, not executed" >&2
    return 1 2>/dev/null || exit 1
fi

export SECRETBOX_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -d "$SECRETBOX_HOME/.venv" ]; then
    echo "secretbox: creating venv at $SECRETBOX_HOME/.venv"
    python3 -m venv "$SECRETBOX_HOME/.venv"
    "$SECRETBOX_HOME/.venv/bin/pip" install -q -e "$SECRETBOX_HOME"
fi

# shellcheck source=/dev/null
source "$SECRETBOX_HOME/.venv/bin/activate"

mkdir -p "$SECRETBOX_HOME/data"

app() {
    python -m secretbox.cli "$@"
}

secretbox-web() {
    python -m secretbox.web "$@"
}

echo "secretbox: ready. Try \`app status\` or \`app add <path>\`."
```

- [ ] **Step 2: Smoke test**

```bash
cd /home/nianzuzheng/work/secretbox
bash -c 'source env.sh && app status'
```

Expected: `data_dir: .../data`, `logged_in: False`.

- [ ] **Step 3: End-to-end CLI smoke test**

```bash
cd /home/nianzuzheng/work/secretbox
echo "test content" > /tmp/sb-test.txt
bash <<'EOF'
source env.sh
echo "testpass" | app add /tmp/sb-test.txt
app list
echo "testpass" | app login
app cat sb-test.txt
app logout
EOF
```

Expected: `added: sb-test.txt`, list shows `sb-test.txt`, `logged in`, `test content`, `logged out`. `/tmp/sb-test.txt` should no longer exist; `data/sb-test.txt.gpg` should exist.

- [ ] **Step 4: Clean up the smoke-test entry**

```bash
cd /home/nianzuzheng/work/secretbox
rm -f data/sb-test.txt.gpg data/.secretbox-check.gpg
```

- [ ] **Step 5: Commit**

```bash
git add env.sh
git commit -m "feat: env.sh source-able CLI entry"
```

---

### Task 7: `web/app.py` — Flask app factory + auth routes

**Files:**
- Create: `src/secretbox/web/__init__.py`
- Create: `src/secretbox/web/app.py`
- Create: `tests/test_web.py`

**Interfaces:**
- Consumes: `core.gpg`, `core.storage`, env vars `SECRETBOX_LOGIN_HASH`, `SECRETBOX_FLASK_SECRET`, `SECRETBOX_HOME`
- Produces:
  - `create_app(data_dir: Path | None = None) -> Flask`
  - Routes: `GET/POST /login`, `GET/POST /unlock`, `POST /lock`, `POST /logout`, `GET /api/status`
  - Decorators: `login_required`, `unlocked_required`
  - In-memory passphrase stored at `app.config['GPG_PASSPHRASE']`; cleared on lock/logout

- [ ] **Step 1: Write failing tests**

`tests/test_web.py`:
```python
import os
from pathlib import Path

import bcrypt
import pytest

from secretbox.web.app import create_app
from secretbox.core import storage


LOGIN_PASSWORD = "letmein"


@pytest.fixture
def web_env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    data = home / "data"
    data.mkdir()
    hashed = bcrypt.hashpw(LOGIN_PASSWORD.encode(), bcrypt.gensalt()).decode()
    monkeypatch.setenv("SECRETBOX_HOME", str(home))
    monkeypatch.setenv("SECRETBOX_LOGIN_HASH", hashed)
    monkeypatch.setenv("SECRETBOX_FLASK_SECRET", "test-secret")
    return data


@pytest.fixture
def app(web_env):
    a = create_app(data_dir=web_env)
    a.config["TESTING"] = True
    return a


@pytest.fixture
def client(app):
    return app.test_client()


def _login(client):
    return client.post("/login", data={"password": LOGIN_PASSWORD}, follow_redirects=False)


def test_login_required_redirects(client):
    r = client.get("/")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_login_success(client):
    r = _login(client)
    assert r.status_code == 302


def test_login_wrong_password(client):
    r = client.post("/login", data={"password": "nope"})
    assert r.status_code == 200
    assert b"incorrect" in r.data.lower()


def test_api_status_unauth(client):
    r = client.get("/api/status")
    assert r.status_code == 401


def test_api_status_logged_in_locked(client):
    _login(client)
    r = client.get("/api/status")
    assert r.status_code == 200
    assert r.get_json()["unlocked"] is False


def test_unlock_requires_sentinel(client, gpg_passphrase):
    _login(client)
    r = client.post("/unlock", data={"passphrase": gpg_passphrase})
    assert r.status_code == 200
    assert b"add a file first" in r.data.lower()


def test_unlock_success(client, gpg_passphrase, web_env):
    storage.ensure_sentinel(web_env, gpg_passphrase)
    _login(client)
    r = client.post("/unlock", data={"passphrase": gpg_passphrase})
    assert r.status_code == 302
    r = client.get("/api/status")
    assert r.get_json()["unlocked"] is True


def test_unlock_wrong_passphrase(client, gpg_passphrase, wrong_passphrase, web_env):
    storage.ensure_sentinel(web_env, gpg_passphrase)
    _login(client)
    r = client.post("/unlock", data={"passphrase": wrong_passphrase})
    assert r.status_code == 200
    assert b"incorrect" in r.data.lower()


def test_lock_clears_passphrase(client, gpg_passphrase, web_env):
    storage.ensure_sentinel(web_env, gpg_passphrase)
    _login(client)
    client.post("/unlock", data={"passphrase": gpg_passphrase})
    r = client.post("/lock")
    assert r.status_code == 302
    r = client.get("/api/status")
    assert r.get_json()["unlocked"] is False


def test_logout_clears_everything(client, gpg_passphrase, web_env):
    storage.ensure_sentinel(web_env, gpg_passphrase)
    _login(client)
    client.post("/unlock", data={"passphrase": gpg_passphrase})
    r = client.post("/logout")
    assert r.status_code == 302
    r = client.get("/")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_missing_login_hash_refuses_start(tmp_path, monkeypatch):
    monkeypatch.delenv("SECRETBOX_LOGIN_HASH", raising=False)
    monkeypatch.setenv("SECRETBOX_FLASK_SECRET", "x")
    with pytest.raises(RuntimeError):
        create_app(data_dir=tmp_path)
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `.venv/bin/pytest tests/test_web.py -v`
Expected: `ModuleNotFoundError`.

- [ ] **Step 3: Create `src/secretbox/web/__init__.py`**

```python
```

- [ ] **Step 4: Implement `src/secretbox/web/app.py` (auth portion)**

```python
import os
from functools import wraps
from pathlib import Path

import bcrypt
from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from ..core import storage
from ..core.gpg import DecryptError


def _data_dir_default() -> Path:
    home = os.environ.get("SECRETBOX_HOME")
    if home:
        return Path(home) / "data"
    return Path.cwd() / "data"


def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if not session.get("user"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "unauthorized"}), 401
            return redirect(url_for("login"))
        return view(*a, **kw)
    return wrapped


def unlocked_required(view):
    @wraps(view)
    @login_required
    def wrapped(*a, **kw):
        from flask import current_app
        if not current_app.config.get("GPG_PASSPHRASE"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "locked"}), 401
            return redirect(url_for("unlock"))
        return view(*a, **kw)
    return wrapped


def create_app(data_dir: Path | None = None) -> Flask:
    app = Flask(__name__)
    login_hash = os.environ.get("SECRETBOX_LOGIN_HASH")
    if not login_hash:
        raise RuntimeError(
            "SECRETBOX_LOGIN_HASH not set — generate one and add it to .env"
        )
    flask_secret = os.environ.get("SECRETBOX_FLASK_SECRET")
    if not flask_secret:
        raise RuntimeError("SECRETBOX_FLASK_SECRET not set")
    app.config["SECRET_KEY"] = flask_secret
    app.config["LOGIN_HASH"] = login_hash.encode()
    app.config["DATA_DIR"] = data_dir or _data_dir_default()
    app.config["DATA_DIR"].mkdir(parents=True, exist_ok=True)
    app.config["GPG_PASSPHRASE"] = None

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            pw = request.form.get("password", "")
            if bcrypt.checkpw(pw.encode(), app.config["LOGIN_HASH"]):
                session["user"] = "ok"
                return redirect(url_for("index"))
            return render_template("login.html", error="incorrect"), 200
        return render_template("login.html", error=None)

    @app.route("/unlock", methods=["GET", "POST"])
    @login_required
    def unlock():
        if request.method == "POST":
            pw = request.form.get("passphrase", "")
            try:
                ok = storage.verify_passphrase(app.config["DATA_DIR"], pw)
            except storage.SentinelMissing:
                return render_template(
                    "unlock.html",
                    error="no files yet — add a file first via the CLI",
                ), 200
            if not ok:
                return render_template("unlock.html", error="incorrect"), 200
            app.config["GPG_PASSPHRASE"] = pw
            return redirect(url_for("index"))
        return render_template("unlock.html", error=None)

    @app.route("/lock", methods=["POST"])
    @login_required
    def lock():
        app.config["GPG_PASSPHRASE"] = None
        return redirect(url_for("index"))

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        app.config["GPG_PASSPHRASE"] = None
        session.clear()
        return redirect(url_for("login"))

    @app.route("/")
    @login_required
    def index():
        return render_template(
            "index.html",
            unlocked=bool(app.config.get("GPG_PASSPHRASE")),
        )

    @app.route("/api/status")
    @login_required
    def api_status():
        return jsonify({
            "unlocked": bool(app.config.get("GPG_PASSPHRASE")),
            "entries": len(storage.list_entries(app.config["DATA_DIR"])),
        })

    return app
```

Note: `render_template("index.html", ...)` and friends will 500 until Task 9 creates the templates. The auth tests don't reach `/`; the index test in this task is the redirect-to-login check, which doesn't render the template.

- [ ] **Step 5: Run tests, verify they pass**

Run: `.venv/bin/pytest tests/test_web.py -v`
Expected: 11 passed. The `test_login_required_redirects` test asserts a 302 to `/login` before any template is rendered.

- [ ] **Step 6: Commit**

```bash
git add src/secretbox/web/__init__.py src/secretbox/web/app.py tests/test_web.py
git commit -m "feat(web): flask app factory and auth routes"
```

---

### Task 8: Web file API routes

**Files:**
- Modify: `src/secretbox/web/app.py` (append routes inside `create_app`)
- Modify: `tests/test_web.py` (append tests)

**Interfaces:**
- Consumes: routes from Task 7
- Produces:
  - `GET /api/files` → `{"entries": [...]}`
  - `GET /api/files/<name>` → `text/plain; charset=utf-8`
  - `POST /api/files` → multipart `file`, `passphrase` field
  - `DELETE /api/files/<name>` → form `passphrase` field

- [ ] **Step 1: Append failing tests to `tests/test_web.py`**

```python
import io


def _unlock(client, pw):
    return client.post("/unlock", data={"passphrase": pw})


def _add_via_cli(data_dir, name, content, passphrase):
    """Seed an entry without going through the web API."""
    from secretbox.core import gpg as gpg_mod
    storage.ensure_sentinel(data_dir, passphrase)
    (data_dir / f"{name}.gpg").write_bytes(
        gpg_mod.encrypt_bytes(content, passphrase)
    )


def test_api_files_locked_returns_401(client, gpg_passphrase, web_env):
    storage.ensure_sentinel(web_env, gpg_passphrase)
    _login(client)
    r = client.get("/api/files")
    assert r.status_code == 401


def test_api_files_list_unlocked(client, gpg_passphrase, web_env):
    _add_via_cli(web_env, "a", b"AA", gpg_passphrase)
    _add_via_cli(web_env, "b", b"BB", gpg_passphrase)
    _login(client)
    _unlock(client, gpg_passphrase)
    r = client.get("/api/files")
    assert r.status_code == 200
    assert r.get_json()["entries"] == ["a", "b"]


def test_api_get_file(client, gpg_passphrase, web_env):
    _add_via_cli(web_env, "note", b"hello", gpg_passphrase)
    _login(client)
    _unlock(client, gpg_passphrase)
    r = client.get("/api/files/note")
    assert r.status_code == 200
    assert r.data == b"hello"
    assert r.mimetype == "text/plain"


def test_api_get_missing_file(client, gpg_passphrase, web_env):
    _add_via_cli(web_env, "x", b"x", gpg_passphrase)
    _login(client)
    _unlock(client, gpg_passphrase)
    r = client.get("/api/files/nope")
    assert r.status_code == 404


def test_api_get_invalid_name(client, gpg_passphrase, web_env):
    _add_via_cli(web_env, "x", b"x", gpg_passphrase)
    _login(client)
    _unlock(client, gpg_passphrase)
    r = client.get("/api/files/..%2Fetc")
    assert r.status_code in (400, 404)


def test_api_add_requires_passphrase_field(client, gpg_passphrase, web_env):
    _add_via_cli(web_env, "seed", b"x", gpg_passphrase)
    _login(client)
    _unlock(client, gpg_passphrase)
    r = client.post(
        "/api/files",
        data={"file": (io.BytesIO(b"new content"), "new.txt")},
        content_type="multipart/form-data",
    )
    assert r.status_code == 400


def test_api_add_wrong_passphrase(client, gpg_passphrase, wrong_passphrase, web_env):
    _add_via_cli(web_env, "seed", b"x", gpg_passphrase)
    _login(client)
    _unlock(client, gpg_passphrase)
    r = client.post(
        "/api/files",
        data={
            "file": (io.BytesIO(b"new content"), "new.txt"),
            "passphrase": wrong_passphrase,
        },
        content_type="multipart/form-data",
    )
    assert r.status_code == 401


def test_api_add_success(client, gpg_passphrase, web_env):
    _add_via_cli(web_env, "seed", b"x", gpg_passphrase)
    _login(client)
    _unlock(client, gpg_passphrase)
    r = client.post(
        "/api/files",
        data={
            "file": (io.BytesIO(b"new content"), "new.txt"),
            "passphrase": gpg_passphrase,
        },
        content_type="multipart/form-data",
    )
    assert r.status_code == 201
    assert (web_env / "new.txt.gpg").exists()


def test_api_add_refuses_existing(client, gpg_passphrase, web_env):
    _add_via_cli(web_env, "dup", b"x", gpg_passphrase)
    _login(client)
    _unlock(client, gpg_passphrase)
    r = client.post(
        "/api/files",
        data={
            "file": (io.BytesIO(b"y"), "dup"),
            "passphrase": gpg_passphrase,
        },
        content_type="multipart/form-data",
    )
    assert r.status_code == 409


def test_api_delete(client, gpg_passphrase, web_env):
    _add_via_cli(web_env, "doomed", b"x", gpg_passphrase)
    _login(client)
    _unlock(client, gpg_passphrase)
    r = client.delete(
        "/api/files/doomed", data={"passphrase": gpg_passphrase}
    )
    assert r.status_code == 204
    assert not (web_env / "doomed.gpg").exists()


def test_api_delete_wrong_passphrase(client, gpg_passphrase, wrong_passphrase, web_env):
    _add_via_cli(web_env, "safe", b"x", gpg_passphrase)
    _login(client)
    _unlock(client, gpg_passphrase)
    r = client.delete(
        "/api/files/safe", data={"passphrase": wrong_passphrase}
    )
    assert r.status_code == 401
    assert (web_env / "safe.gpg").exists()
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `.venv/bin/pytest tests/test_web.py -v`
Expected: the new tests fail (404 on `/api/files` etc.) while Task 7's tests still pass.

- [ ] **Step 3: Append file API routes inside `create_app` in `src/secretbox/web/app.py`**

Insert these routes inside `create_app` after the existing routes, before `return app`:

```python
    @app.route("/api/files", methods=["GET"])
    @unlocked_required
    def api_list():
        return jsonify({"entries": storage.list_entries(app.config["DATA_DIR"])})

    @app.route("/api/files/<name>", methods=["GET"])
    @unlocked_required
    def api_get(name: str):
        try:
            body = storage.get_entry(
                app.config["DATA_DIR"], name, app.config["GPG_PASSPHRASE"]
            )
        except storage.InvalidName:
            return jsonify({"error": "invalid_name"}), 400
        except FileNotFoundError:
            return jsonify({"error": "not_found"}), 404
        except DecryptError:
            return jsonify({"error": "decrypt_failed"}), 500
        return body, 200, {"Content-Type": "text/plain; charset=utf-8"}

    @app.route("/api/files", methods=["POST"])
    @unlocked_required
    def api_add():
        f = request.files.get("file")
        pw = request.form.get("passphrase")
        if not f or not pw:
            return jsonify({"error": "missing_field"}), 400
        try:
            ok = storage.verify_passphrase(app.config["DATA_DIR"], pw)
        except storage.SentinelMissing:
            ok = True  # first add establishes sentinel
        if not ok:
            return jsonify({"error": "passphrase_incorrect"}), 401

        import tempfile
        from pathlib import Path as _P
        with tempfile.TemporaryDirectory() as td:
            tmp = _P(td) / f.filename
            f.save(tmp)
            try:
                name = storage.add_entry(
                    app.config["DATA_DIR"], tmp, pw, force=False
                )
            except storage.EntryExists:
                return jsonify({"error": "exists"}), 409
            except storage.InvalidName:
                return jsonify({"error": "invalid_name"}), 400
        return jsonify({"name": name}), 201

    @app.route("/api/files/<name>", methods=["DELETE"])
    @unlocked_required
    def api_delete(name: str):
        pw = request.form.get("passphrase")
        if not pw:
            return jsonify({"error": "missing_field"}), 400
        try:
            ok = storage.verify_passphrase(app.config["DATA_DIR"], pw)
        except storage.SentinelMissing:
            return jsonify({"error": "no_sentinel"}), 400
        if not ok:
            return jsonify({"error": "passphrase_incorrect"}), 401
        try:
            storage.remove_entry(app.config["DATA_DIR"], name)
        except storage.InvalidName:
            return jsonify({"error": "invalid_name"}), 400
        except FileNotFoundError:
            return jsonify({"error": "not_found"}), 404
        return "", 204
```

- [ ] **Step 4: Run tests, verify they pass**

Run: `.venv/bin/pytest tests/test_web.py -v`
Expected: all `test_web.py` tests pass (auth + file API).

- [ ] **Step 5: Run full test suite**

Run: `.venv/bin/pytest -v`
Expected: all tests across all files pass.

- [ ] **Step 6: Commit**

```bash
git add src/secretbox/web/app.py tests/test_web.py
git commit -m "feat(web): file API routes (list/get/add/delete) with passphrase guard on writes"
```

---

### Task 9: Web frontend, `__main__`, and README

**Files:**
- Create: `src/secretbox/web/__main__.py`
- Create: `src/secretbox/web/templates/base.html`
- Create: `src/secretbox/web/templates/login.html`
- Create: `src/secretbox/web/templates/unlock.html`
- Create: `src/secretbox/web/templates/index.html`
- Create: `src/secretbox/web/static/app.css`
- Create: `src/secretbox/web/static/app.js`
- Modify: `pyproject.toml` (include templates + static in package)
- Create: `README.md`

**Interfaces:**
- Consumes: routes from Tasks 7-8
- Produces: `python -m secretbox.web` launches Flask on `127.0.0.1:$SECRETBOX_WEB_PORT`

- [ ] **Step 1: Update `pyproject.toml` to include templates and static assets**

Append under `[tool.setuptools.packages.find]`:

```toml
[tool.setuptools.package-data]
secretbox = ["web/templates/*.html", "web/static/*"]
```

- [ ] **Step 2: Create `src/secretbox/web/__main__.py`**

```python
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from .app import create_app


def main() -> None:
    home = os.environ.get("SECRETBOX_HOME")
    if home:
        load_dotenv(Path(home) / ".env")
    else:
        load_dotenv()
    port = int(os.environ.get("SECRETBOX_WEB_PORT", "8765"))
    try:
        app = create_app()
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        print(
            "Hint: copy .env.example to .env and fill in SECRETBOX_LOGIN_HASH "
            "and SECRETBOX_FLASK_SECRET.",
            file=sys.stderr,
        )
        sys.exit(2)
    print(f"secretbox web: http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False)


if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Create `src/secretbox/web/templates/base.html`**

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>secretbox</title>
<link rel="stylesheet" href="{{ url_for('static', filename='app.css') }}">
</head>
<body>
{% block body %}{% endblock %}
</body>
</html>
```

- [ ] **Step 4: Create `src/secretbox/web/templates/login.html`**

```html
{% extends "base.html" %}
{% block body %}
<main class="auth">
  <h1>secretbox</h1>
  <form method="post" action="{{ url_for('login') }}">
    <label>password<input type="password" name="password" autofocus></label>
    {% if error %}<p class="err">{{ error }}</p>{% endif %}
    <button type="submit">sign in</button>
  </form>
</main>
{% endblock %}
```

- [ ] **Step 5: Create `src/secretbox/web/templates/unlock.html`**

```html
{% extends "base.html" %}
{% block body %}
<main class="auth">
  <h1>unlock vault</h1>
  <form method="post" action="{{ url_for('unlock') }}">
    <label>gpg passphrase<input type="password" name="passphrase" autofocus></label>
    {% if error %}<p class="err">{{ error }}</p>{% endif %}
    <button type="submit">unlock</button>
  </form>
  <form method="post" action="{{ url_for('logout') }}" class="logout-inline">
    <button type="submit">sign out</button>
  </form>
</main>
{% endblock %}
```

- [ ] **Step 6: Create `src/secretbox/web/templates/index.html`**

```html
{% extends "base.html" %}
{% block body %}
<header class="topbar">
  <h1>secretbox</h1>
  <div class="topbar-actions">
    <button id="import-btn">import</button>
    <form method="post" action="{{ url_for('lock') }}" class="inline">
      <button type="submit">lock</button>
    </form>
    <form method="post" action="{{ url_for('logout') }}" class="inline">
      <button type="submit">sign out</button>
    </form>
  </div>
</header>
<div class="layout">
  <aside id="sidebar"><ul id="file-list"></ul></aside>
  <section id="viewer">
    <header id="viewer-title">select a file</header>
    <pre id="viewer-body"></pre>
  </section>
</div>

<dialog id="import-dialog">
  <form method="post" id="import-form" enctype="multipart/form-data">
    <h2>import file</h2>
    <label>file<input type="file" name="file" required></label>
    <label>gpg passphrase<input type="password" name="passphrase" required></label>
    <p class="err" id="import-err" hidden></p>
    <menu>
      <button value="cancel" formmethod="dialog">cancel</button>
      <button type="submit">add</button>
    </menu>
  </form>
</dialog>

<script src="{{ url_for('static', filename='app.js') }}"></script>
{% endblock %}
```

- [ ] **Step 7: Create `src/secretbox/web/static/app.css`**

```css
* { box-sizing: border-box; }
body { margin: 0; font-family: ui-sans-serif, system-ui, sans-serif; color: #222; }
.auth { max-width: 360px; margin: 10vh auto; padding: 24px; border: 1px solid #ddd; border-radius: 8px; }
.auth h1 { margin-top: 0; }
.auth label { display: block; margin: 12px 0 4px; }
.auth input { width: 100%; padding: 8px; }
.auth button { margin-top: 16px; padding: 8px 16px; }
.err { color: #b00020; }
.logout-inline { margin-top: 16px; }

.topbar { display: flex; justify-content: space-between; align-items: center; padding: 8px 16px; border-bottom: 1px solid #ddd; }
.topbar h1 { margin: 0; font-size: 18px; }
.topbar-actions { display: flex; gap: 8px; }
.inline { display: inline; margin: 0; }

.layout { display: grid; grid-template-columns: 240px 1fr; height: calc(100vh - 48px); }
#sidebar { border-right: 1px solid #ddd; overflow-y: auto; padding: 8px; }
#file-list { list-style: none; padding: 0; margin: 0; }
#file-list li button { display: block; width: 100%; text-align: left; padding: 6px 8px; background: none; border: 0; cursor: pointer; }
#file-list li button:hover, #file-list li button.active { background: #f0f0f0; }

#viewer { display: flex; flex-direction: column; }
#viewer-title { padding: 8px 16px; border-bottom: 1px solid #eee; font-weight: 600; }
#viewer-body { flex: 1; margin: 0; padding: 16px; overflow: auto; white-space: pre-wrap; font-family: ui-monospace, monospace; }

dialog { border: 1px solid #ccc; border-radius: 8px; padding: 16px; }
dialog label { display: block; margin: 12px 0 4px; }
dialog input { width: 100%; padding: 6px; }
dialog menu { display: flex; justify-content: flex-end; gap: 8px; padding: 0; margin: 16px 0 0; }
```

- [ ] **Step 8: Create `src/secretbox/web/static/app.js`**

```javascript
const list = document.getElementById("file-list");
const title = document.getElementById("viewer-title");
const body = document.getElementById("viewer-body");
const dlg = document.getElementById("import-dialog");
const dlgForm = document.getElementById("import-form");
const dlgErr = document.getElementById("import-err");

async function refresh() {
  const r = await fetch("/api/files");
  if (r.status === 401) { location.href = "/unlock"; return; }
  const data = await r.json();
  list.innerHTML = "";
  for (const name of data.entries) {
    const li = document.createElement("li");
    const btn = document.createElement("button");
    btn.textContent = name;
    btn.addEventListener("click", () => open(name, btn));
    li.appendChild(btn);
    list.appendChild(li);
  }
}

async function open(name, btn) {
  document.querySelectorAll("#file-list button").forEach(b => b.classList.remove("active"));
  if (btn) btn.classList.add("active");
  const r = await fetch(`/api/files/${encodeURIComponent(name)}`);
  if (!r.ok) { title.textContent = `error: ${r.status}`; body.textContent = ""; return; }
  title.textContent = name;
  body.textContent = await r.text();
}

document.getElementById("import-btn").addEventListener("click", () => {
  dlgErr.hidden = true;
  dlgForm.reset();
  dlg.showModal();
});

dlgForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(dlgForm);
  const r = await fetch("/api/files", { method: "POST", body: fd });
  if (r.ok) {
    dlg.close();
    refresh();
  } else {
    let msg = `error ${r.status}`;
    try {
      const j = await r.json();
      if (j.error) msg = j.error;
    } catch (_) {}
    dlgErr.textContent = msg;
    dlgErr.hidden = false;
  }
});

refresh();
```

- [ ] **Step 9: Create `README.md`**

```markdown
# secretbox

Local single-user GPG-symmetric file vault with a CLI and a web UI sharing one data directory.

## Setup

```bash
cd secretbox
source env.sh                    # creates .venv, installs package, defines `app`
cp .env.example .env
# Generate a login-password hash and a flask secret, fill them into .env:
python -c "import bcrypt, getpass; print(bcrypt.hashpw(getpass.getpass().encode(), bcrypt.gensalt()).decode())"
python -c "import secrets; print(secrets.token_hex(32))"
```

## CLI

```
app status                 # show login state and data dir
app add <path>             # encrypt <path> → data/<name>.gpg, delete <path>
app list                   # list entries
app login                  # enter passphrase to enable cached reads
app cat <name>             # decrypt and print to stdout
app rm <name> [--yes]      # remove
app logout                 # clear cached passphrase
```

Session is stored in `/run/user/$UID/secretbox/session` (tmpfs; 0600 file, 0700 dir).
TTL defaults to 30 minutes; override with `SECRETBOX_TTL_SECONDS`.
**Add re-prompts every time, even when logged in.**

## Web

```bash
source env.sh
secretbox-web              # http://127.0.0.1:8765
```

Login flow: login password → unlock with GPG passphrase → file list + viewer.
GPG passphrase lives only in process memory and is cleared on `/lock`, `/logout`, or shutdown.

## Manual smoke test

1. `source env.sh && app status` → shows data dir, `logged_in: False`
2. `echo "hello" > /tmp/note.txt && app add /tmp/note.txt` → prompts passphrase, prints `added: note.txt`. `/tmp/note.txt` is gone; `data/note.txt.gpg` exists.
3. `app list` → `note.txt`
4. `app login` (same passphrase) → `logged in`
5. `app cat note.txt` → `hello`
6. `secretbox-web` then browser → log in → unlock → click `note.txt` in sidebar → see content. Use import button to add another file.

## Limitations

- Linux/WSL2 only (requires `/run/user/$UID` or a writable temp dir).
- Single user. No multi-user, no remote access, no TLS.
- Text viewer only in the web UI. CLI `app cat` works for any file but writes raw bytes to stdout.
- No passphrase-rotation command yet.
```

- [ ] **Step 10: Reinstall and verify package data shipping**

```bash
cd /home/nianzuzheng/work/secretbox
.venv/bin/pip install -q -e .
.venv/bin/python -c "from secretbox.web.app import create_app; print('ok')"
```

Expected: `ok` (note: this will raise without env vars set; the goal is to verify the import path works).

- [ ] **Step 11: End-to-end manual smoke test**

```bash
cd /home/nianzuzheng/work/secretbox
cp .env.example .env
HASH=$(python -c "import bcrypt; print(bcrypt.hashpw(b'webpass', bcrypt.gensalt()).decode())")
SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")
sed -i "s|^SECRETBOX_LOGIN_HASH=.*|SECRETBOX_LOGIN_HASH=$HASH|" .env
sed -i "s|^SECRETBOX_FLASK_SECRET=.*|SECRETBOX_FLASK_SECRET=$SECRET|" .env

source env.sh
echo "hello from secretbox" > /tmp/sb-smoke.txt
echo "smokepass" | app add /tmp/sb-smoke.txt
app list                                  # → sb-smoke.txt
echo "smokepass" | app login
app cat sb-smoke.txt                      # → hello from secretbox

# Web smoke (manual)
secretbox-web &
WEB_PID=$!
sleep 1
echo "Visit http://127.0.0.1:8765 — login with 'webpass' then unlock with 'smokepass'"
# After visual check:
kill $WEB_PID
rm -f data/*.gpg
```

Expected: all CLI commands succeed. Web UI loads, login + unlock work, sidebar shows `sb-smoke.txt`, viewer shows file content, import dialog works.

- [ ] **Step 12: Run full test suite one more time**

```bash
.venv/bin/pytest -v
```

Expected: all tests pass.

- [ ] **Step 13: Commit**

```bash
git add src/secretbox/web/__main__.py src/secretbox/web/templates/ src/secretbox/web/static/ pyproject.toml README.md
git commit -m "feat(web): frontend templates, static assets, entry point, README"
```
```

