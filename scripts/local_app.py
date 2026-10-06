"""Open the web workbench with local CLI capabilities and no account setup."""

import argparse
import os
from pathlib import Path
import secrets
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from web_adapter.companion import LocalServer


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=5330)
    arguments = parser.parse_args()
    if not 1024 <= arguments.port <= 65535:
        parser.error("Choose a port between 1024 and 65535.")
    if not (Path(__file__).resolve().parents[1] / "dist" / "index.html").is_file():
        parser.error("Run npm ci and npm run build before starting the local application.")
    token = secrets.token_urlsafe(32)
    os.environ["H8MAIL_ACCESS_TOKEN"] = token
    server = LocalServer(arguments.port, token)
    print(f"H8MAIL local workbench: http://127.0.0.1:{arguments.port}")
    print("Files and configuration stay on this computer. Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
