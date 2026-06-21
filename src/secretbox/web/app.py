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
            ok = True
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

    return app
