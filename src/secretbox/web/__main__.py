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
