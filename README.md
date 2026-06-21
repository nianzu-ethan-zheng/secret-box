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
app add <path>             # encrypt <path> -> data/<name>.gpg, delete <path>
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

Login flow: login password -> unlock with GPG passphrase -> file list + viewer.
GPG passphrase lives only in process memory and is cleared on `/lock`, `/logout`, or shutdown.

## Manual smoke test

1. `source env.sh && app status` -> shows data dir, `logged_in: False`
2. `echo "hello" > /tmp/note.txt && app add /tmp/note.txt` -> prompts passphrase, prints `added: note.txt`. `/tmp/note.txt` is gone; `data/note.txt.gpg` exists.
3. `app list` -> `note.txt`
4. `app login` (same passphrase) -> `logged in`
5. `app cat note.txt` -> `hello`
6. `secretbox-web` then browser -> log in -> unlock -> click `note.txt` in sidebar -> see content. Use import button to add another file.

## Limitations

- Linux/WSL2 only (requires `/run/user/$UID` or a writable temp dir).
- Single user. No multi-user, no remote access, no TLS.
- Text viewer only in the web UI. CLI `app cat` works for any file but writes raw bytes to stdout.
- No passphrase-rotation command yet.
