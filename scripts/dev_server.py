"""Run the same API handler locally without logging private request details."""

import sys
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api.index import handler


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 5329), handler)
    print("H8MAIL API listening on http://127.0.0.1:5329")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
