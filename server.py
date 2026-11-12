"""Start the local service or ingest a JSON batch from an audit exporter."""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from store import connect, ingest, review, snapshot, suggest

ROOT = Path(__file__).parent.resolve()
ASSETS = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"),
          "/style.css": ("style.css", "text/css"), "/example.json": ("example.json", "application/json")}


def handler(db):
    class Handler(BaseHTTPRequestHandler):
        def reply(self, code, data, mime="application/json"):
            body = json.dumps(data).encode() if mime == "application/json" and not isinstance(data, bytes) else data
            self.send_response(code)
            self.send_header("Content-Type", mime + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
            self.end_headers()
            self.wfile.write(body)

        def local(self):
            allowed = {f"{name}:{self.server.server_port}" for name in ("127.0.0.1","localhost")}
            host = self.headers.get("Host", "")
            return host in allowed and self.headers.get("Origin", "http://" + host) == "http://" + host

        def do_GET(self):
            if not self.local():
                return self.reply(403, {"error":"Local requests only"})
            path = urlsplit(self.path).path
            if path == "/api/state":
                return self.reply(200, snapshot(db))
            if path in ASSETS:
                file, mime = ASSETS[path]
                return self.reply(200, (ROOT / file).read_bytes(), mime)
            self.reply(404, {"error":"Unknown resource"})

        def do_POST(self):
            if not self.local():
                return self.reply(403, {"error":"Local requests only"})
            if self.headers.get_content_type() != "application/json":
                return self.reply(415, {"error":"Send application/json"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 1024 * 1024:
                    return self.reply(413, {"error":"Batch must be 1 byte to 1 MiB"})
                data = json.loads(self.rfile.read(length))
                if self.path == "/api/events":
                    return self.reply(200, ingest(db, data))
                if self.path == "/api/review":
                    review(db, data)
                    return self.reply(200, {"saved":True})
                if self.path == "/api/triage":
                    if not isinstance(data, dict):
                        raise ValueError("Expected an object")
                    return self.reply(200, suggest(db, data.get("id"), data.get("summary")))
                self.reply(404, {"error":"Unknown resource"})
            except (ValueError, UnicodeError) as exc:
                self.reply(400, {"error":str(exc)})
            except RuntimeError as exc:
                self.reply(409, {"error":str(exc)})
    return Handler


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=str(ROOT / "data" / "soc.sqlite3"))
    parser.add_argument("--port", type=int, default=8780)
    parser.add_argument("--import-events", type=Path)
    args = parser.parse_args()
    if args.import_events:
        print(json.dumps(ingest(args.db, json.loads(args.import_events.read_text(encoding="utf-8-sig")))))
    else:
        connect(args.db).close()
        with ThreadingHTTPServer(("127.0.0.1", args.port), handler(args.db)) as server:
            print(f"Signal Desk is running at http://127.0.0.1:{server.server_port}", flush=True)
            server.serve_forever()

