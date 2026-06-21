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
