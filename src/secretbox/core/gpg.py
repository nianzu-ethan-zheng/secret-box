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
