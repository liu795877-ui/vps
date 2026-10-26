"""Disposable local member-history fixture with explicitly synthetic connections."""
import json
from pathlib import Path
import sys
import tempfile
import time
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from panel import server
from panel.test_multiuser_http import isolated_telemetry_runner
from panel.test_operations import Controls
from panel.test_access_records import entry


with tempfile.TemporaryDirectory(prefix="access-records-browser-") as directory:
    root = Path(directory)
    with mock.patch.object(server.base, "PORT", 443):
        manager = server.Manager(root, "8.8.8.8", root / "config.json", demo=True)
    httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    origin = "http://127.0.0.1:" + str(httpd.server_address[1])
    app = server.Application(manager, origin, "/", True)
    app.telemetry.runner = isolated_telemetry_runner
    app.telemetry.controls = Controls()
    for username, name in (("member_alpha", "成员 <b>A</b>"), ("member_beta", "成员 B")):
        app.accounts.create_user({"username": username, "display_name": name,
                                  "password": "synthetic-browser-password-2026"})
    a, b = app.accounts.records
    now = time.time()
    rows = [entry("alpha-"+str(i), a["id"], "site"+str(i % 5)+".example:443",
                  "hy2" if i % 2 else "reality", now-i*30) for i in range(56)]
    rows += [entry("beta-"+str(i), b["id"], "beta.example:443", "hy2", now-i*60) for i in range(8)]
    rows += [entry("ip", a["id"], "1.1.1.1:443", "hy2", now-5)]
    rows += [dict(entry("owner", a["id"], "owner-private.example:443", at=now), _SYSTEMD_UNIT="xray.service")]
    app.access_records.reader = lambda *args: (rows, False)
    app.accounts.demo = False
    try:
        app.access_records.tick()
    finally:
        app.accounts.demo = True
    httpd.application = app
    print(json.dumps({"origin": origin}), flush=True)
    httpd.serve_forever()
