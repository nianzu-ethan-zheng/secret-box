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
