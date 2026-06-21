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
