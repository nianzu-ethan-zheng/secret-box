# Secretbox Design

**Date:** 2026-06-21
**Status:** Approved

## 1. Goal

A single-user, local-only GPG-symmetric file vault with two front-ends sharing one data directory:

- **CLI** — sourced via `env.sh`, exposes `app` commands (`login`, `logout`, `status`, `list`, `cat`, `add`, `rm`).
- **Web** — local Flask app on `127.0.0.1:8765`, left sidebar of file names, right viewer pane, top-right import button.

The vault is **single-user**, **single-host**, **WSL2/Linux only** (relies on `/run/user/$UID` tmpfs).

## 2. Security Model

Two independent secrets:

| Secret | Purpose | Storage |
|---|---|---|
| **Login password** | Gate web access (prevent random LAN hits) | bcrypt hash in `.env` as `SECRETBOX_LOGIN_HASH`. Never persisted in plaintext. |
| **GPG passphrase** | Encrypt/decrypt vault files | Never persisted in plaintext anywhere. CLI: tmpfs session file. Web: process memory only. |

**Invariants:**

- No code path writes the GPG passphrase to a non-tmpfs location.
- No error message, log line, or HTTP response echoes either secret.
- Web binds `127.0.0.1` only — never `0.0.0.0`.
- Read operations (`cat`, `list`, web viewer) may use cached passphrase.
- Write operations (`add`, web import) always re-prompt for passphrase, even when a session/memory copy exists. Rationale: writing is a higher-trust action; an unattended terminal with a live session should not let a passerby add files.

## 3. Layout

```
secretbox/
├── env.sh                  # source-able: activates venv, exports SECRETBOX_HOME, defines app() function
├── pyproject.toml
├── .env                    # SECRETBOX_LOGIN_HASH=...  (gitignored)
├── .env.example            # template with comments
├── .gitignore              # data/, .env, *.pyc, .venv/
├── data/                   # *.gpg files + .secretbox-check.gpg sentinel  (gitignored)
├── src/secretbox/
│   ├── __init__.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── gpg.py          # encrypt_bytes / decrypt_bytes / verify_passphrase via subprocess
│   │   ├── storage.py      # list_entries / add_entry / get_entry / remove_entry / sentinel
│   │   └── session.py      # write/read/clear tmpfs session + TTL
│   ├── cli.py              # click commands
│   └── web/
│       ├── __init__.py
│       ├── __main__.py     # entry for `python -m secretbox.web` (parses host/port, runs Flask)
│       ├── app.py          # Flask factory, routes, auth decorators
│       ├── templates/
│       │   ├── base.html
│       │   ├── login.html
│       │   ├── unlock.html
│       │   └── index.html
│       └── static/
│           ├── app.js
│           └── app.css
└── tests/
    ├── conftest.py         # fixtures: tmp data dir, tmp session dir, fake gpg env
    ├── test_gpg.py
    ├── test_storage.py
    ├── test_session.py
    ├── test_cli.py
    └── test_web.py
```

Data directory is `$SECRETBOX_HOME/data/`. `SECRETBOX_HOME` is exported by `env.sh` as the directory containing `env.sh` itself (`dirname` of `${BASH_SOURCE[0]}`).

## 4. Components

### 4.1 `core/gpg.py`

Wraps the `gpg` binary via `subprocess`. No `python-gnupg` dependency.

```python
def encrypt_bytes(plaintext: bytes, passphrase: str) -> bytes:
    """gpg --batch --symmetric --cipher-algo AES256 --passphrase-fd 0 --pinentry-mode loopback"""

def decrypt_bytes(ciphertext: bytes, passphrase: str) -> bytes:
    """gpg --batch --decrypt --passphrase-fd 0 --pinentry-mode loopback. Raises DecryptError on bad passphrase."""

def gpg_available() -> bool:
    """Check `gpg --version` exits 0."""
```

- Passphrase passed via fd 0 (stdin), never argv.
- Subprocess stderr captured; on failure raise `DecryptError("passphrase incorrect or data corrupt")` without exposing gpg's raw output.
- Cipher pinned to AES256 for determinism in tests.

### 4.2 `core/storage.py`

```python
SENTINEL_NAME = ".secretbox-check.gpg"
SENTINEL_PLAINTEXT = b"OK"

def list_entries(data_dir: Path) -> list[str]:
    """Return names (without .gpg suffix), excluding sentinel."""

def add_entry(data_dir: Path, source: Path, passphrase: str, force: bool = False) -> str:
    """Encrypt source → data_dir/<basename>.gpg. Refuse if target exists and not force.
       Create sentinel if missing. Delete source on success.
       Returns the entry name."""

def get_entry(data_dir: Path, name: str, passphrase: str) -> bytes:
    """Decrypt data_dir/<name>.gpg → plaintext bytes."""

def remove_entry(data_dir: Path, name: str) -> None:
    """Delete data_dir/<name>.gpg. Raise FileNotFoundError if missing."""

def verify_passphrase(data_dir: Path, passphrase: str) -> bool:
    """Decrypt sentinel and check == SENTINEL_PLAINTEXT. Raise SentinelMissing if no sentinel yet."""

def ensure_sentinel(data_dir: Path, passphrase: str) -> None:
    """Create .secretbox-check.gpg if it doesn't exist, using the given passphrase."""
```

- Entry name is `source.name` minus any existing `.gpg` suffix. We append `.gpg` ourselves.
- Names containing `/` or `..` are rejected (path traversal guard).
- Source-deletion failure after successful encrypt: log a warning, return the name anyway. We don't unlink the encrypted file because the user's plaintext is still on disk and that's the more recoverable state.

### 4.3 `core/session.py`

```python
SESSION_DIR = Path(f"/run/user/{os.getuid()}/secretbox")
SESSION_FILE = SESSION_DIR / "session"
DEFAULT_TTL = 1800  # 30 minutes, override via SECRETBOX_TTL_SECONDS

def write_session(passphrase: str, ttl: int = DEFAULT_TTL) -> None:
    """Create SESSION_DIR with 0700, write SESSION_FILE with 0600,
       contents: JSON {"passphrase": "...", "expires_at": <unix>}."""

def read_session() -> str | None:
    """Return passphrase if file exists and not expired, else None.
       Expired sessions are deleted on read."""

def clear_session() -> None:
    """Unlink SESSION_FILE if present. No error if absent."""

def session_status() -> dict:
    """{'logged_in': bool, 'expires_in_seconds': int | None}"""
```

- File mode enforced via `os.open(..., O_CREAT|O_WRONLY|O_TRUNC, 0o600)`.
- Directory mode enforced via `Path.mkdir(mode=0o700, exist_ok=True)`.
- If `/run/user/$UID` doesn't exist (rare — e.g., non-systemd container), fall back to `$XDG_RUNTIME_DIR` or `tempfile.gettempdir() + "/secretbox-$UID"` with a warning. Document this in the README.

### 4.4 `cli.py` (click)

```
app login                  # prompt passphrase, verify_passphrase, write_session
app logout                 # clear_session
app status                 # session_status + data dir + count
app list                   # list_entries → one per line on stdout
app cat <name>             # passphrase = read_session() or prompt; print plaintext to stdout
app add <path> [--force]   # always prompt passphrase; verify or ensure sentinel; add_entry
app rm <name> [--yes]      # confirm unless --yes; remove_entry
```

Exit codes: `0` success, `1` passphrase/auth error, `2` not found, `3` precondition (sentinel missing, force needed), `10` internal error.

### 4.5 `web/app.py` (Flask)

**Configuration on startup:**
- Load `.env` via `python-dotenv`.
- Require `SECRETBOX_LOGIN_HASH` (refuse start with clear error).
- Generate or read `SECRETBOX_FLASK_SECRET` from `.env` for cookie signing.
- Bind `127.0.0.1:8765` (port overridable via `SECRETBOX_WEB_PORT`).

**In-memory state:** `app.config['GPG_PASSPHRASE']` — set on `/unlock`, cleared on `/lock` and `/logout`. Never persisted.

**Routes:**

| Method | Path | Auth | Behavior |
|---|---|---|---|
| GET | `/login` | none | render login form |
| POST | `/login` | none | bcrypt check vs hash → set `session['user']` → redirect `/` |
| GET | `/unlock` | logged_in | render passphrase form |
| POST | `/unlock` | logged_in | `verify_passphrase` → set `app.config['GPG_PASSPHRASE']` → redirect `/` |
| POST | `/lock` | logged_in | clear `GPG_PASSPHRASE` → redirect `/` |
| POST | `/logout` | logged_in | clear session + `GPG_PASSPHRASE` → redirect `/login` |
| GET | `/` | logged_in | render `index.html` (shell). JS decides whether to show unlock prompt based on `/api/status`. |
| GET | `/api/status` | logged_in | `{"unlocked": bool, "entries": int}` |
| GET | `/api/files` | unlocked | `{"entries": ["a","b",...]}` |
| GET | `/api/files/<name>` | unlocked | `text/plain; charset=utf-8` decrypted body |
| POST | `/api/files` | unlocked | multipart: `file`, `passphrase`. Verify, add_entry, return 201 |
| DELETE | `/api/files/<name>` | unlocked | form: `passphrase`. Verify, remove_entry, 204 |

**Auth decorators:** `@login_required` checks `session['user']`; `@unlocked_required` additionally checks `app.config.get('GPG_PASSPHRASE')`. API endpoints return JSON 401; HTML routes redirect.

### 4.6 Web frontend

Single page, vanilla JS — no React/Vue. ~150 lines total.

- Layout: CSS grid, sidebar `220px` left, viewer fills right. Top bar 48px with title, lock indicator, lock button, import button.
- On load: fetch `/api/status`. If `unlocked: false` redirect to `/unlock`.
- Sidebar: fetch `/api/files`, render `<button>` per entry. Click → fetch `/api/files/<name>` → set right pane `<pre>` text.
- Import: `<dialog>` with `<input type="file">` + passphrase `<input type="password">` + submit. On submit, FormData POST to `/api/files`. On success, refresh sidebar.
- Lock button: POST `/lock` → reload.

### 4.7 `env.sh`

```bash
#!/usr/bin/env bash
# Source me: source env.sh

export SECRETBOX_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -d "$SECRETBOX_HOME/.venv" ]; then
    python3 -m venv "$SECRETBOX_HOME/.venv"
    "$SECRETBOX_HOME/.venv/bin/pip" install -e "$SECRETBOX_HOME"
fi

source "$SECRETBOX_HOME/.venv/bin/activate"

app() {
    python -m secretbox.cli "$@"
}

secretbox-web() {
    python -m secretbox.web "$@"
}
```

## 5. Error Handling

| Scenario | CLI | Web |
|---|---|---|
| Passphrase wrong | exit 1, stderr `passphrase incorrect` | form re-render with flash `passphrase incorrect` |
| Session expired / not unlocked | stderr `session expired, run 'app login'` | API 401, HTML redirect `/unlock` |
| Entry not found | exit 2, stderr `no such entry: <name>` | 404 `{"error":"not_found"}` |
| Entry exists on add | exit 3, stderr `entry exists, use --force` | 409 `{"error":"exists"}` |
| Source delete failed after encrypt | warning to stderr, exit 0 | 201 with `warning` in JSON body |
| Path traversal in name | exit 3, stderr `invalid name` | 400 `{"error":"invalid_name"}` |
| gpg binary missing | exit 10 on first run | startup refuses with clear message |
| `SECRETBOX_LOGIN_HASH` missing | — | startup refuses |
| Sentinel missing on login (empty vault) | exit 3, stderr `no files yet — add one first` | unlock form shows hint |

## 6. Testing

**Unit (pytest + tmp_path):**
- `test_gpg.py`: round-trip, wrong passphrase raises, empty bytes, 5MB payload, missing binary.
- `test_storage.py`: list filters sentinel, add creates sentinel on first call, add refuses overwrite without force, traversal name rejected, sentinel verification.
- `test_session.py`: write+read returns passphrase, expired file returns None and is deleted, file mode is 0600, dir mode is 0700, fallback when `/run/user/$UID` missing.

**Integration:**
- `test_cli.py` (`click.testing.CliRunner`, monkeypatched `SECRETBOX_HOME` and session dir): full login → add → list → cat → rm → logout. Wrong passphrase doesn't write session. Expired session reprompts.
- `test_web.py` (Flask `test_client`): unauthenticated → 401/redirect, login → unlock → list → cat → add (multipart) → lock cycle. Missing passphrase field on add → 400. Wrong unlock passphrase → form rerender.

**Manual smoke checklist** (in `README.md`):
1. `source env.sh`
2. `app add ~/notes.txt` → check `data/notes.gpg` exists, original gone
3. `app list` shows `notes`
4. `app login`, `app cat notes` → content
5. `secretbox-web` → browser to `http://127.0.0.1:8765`, full UI cycle

## 7. Dependencies

- `click` — CLI
- `flask` — web
- `python-dotenv` — `.env` loading
- `bcrypt` — login password hashing
- `pytest` — tests (dev)

GPG accessed via `subprocess` to the system `gpg` binary (no Python GPG library).

## 8. Out of Scope

- Multi-user / RBAC
- Remote access (would require TLS, real auth)
- Non-text file preview (binary download only — but current scope is text-only, see Q&A)
- Key-pair (asymmetric) GPG
- Key rotation / passphrase change (future: `app rekey` would decrypt all + re-encrypt with new passphrase + update sentinel)
- Backup/sync to remote
- Windows / non-Linux support
