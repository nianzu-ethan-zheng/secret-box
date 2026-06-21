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
