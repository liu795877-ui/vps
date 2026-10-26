"""Disposable loopback-only UI fixture; never touches production services."""
import json
from pathlib import Path
import sys
import tempfile
import threading
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from panel import server
from panel.test_multiuser_http import isolated_telemetry_runner
from panel.test_operations import Controls

with tempfile.TemporaryDirectory(prefix="membership-browser-") as directory:
    root = Path(directory)
    with mock.patch.object(server.base, "PORT", 443):
        manager = server.Manager(root, "8.8.8.8", root / "config.json", demo=True)
    httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    origin = "http://127.0.0.1:" + str(httpd.server_address[1])
    app = server.Application(manager, origin, "/", True)
    app.telemetry.runner = isolated_telemetry_runner
    app.telemetry.controls = Controls()
    httpd.application = app
    def tick():
        while not app.background_stop.wait(.2):
            with app.mutation_lock:
                app.memberships.tick()
    threading.Thread(target=tick, daemon=True).start()
    print(json.dumps({"origin": origin}), flush=True)
    httpd.serve_forever()
