"""Verify live nickname controls over the owned WLAN CONNECT proxy."""
import json
import os
from pathlib import Path
import re
import socketserver
import subprocess
import sys
import threading

from run_browser_smoke import Handler
from verify_panel import NO_WINDOW, physical_wifi

folder = Path(__file__).resolve().parent
release = sys.argv[1] if len(sys.argv) == 2 else ""
if not re.fullmatch(r"console-optimization-release-\d{8}-[A-Za-z0-9_-]+", release):
    raise SystemExit("Use a frozen release name")
physical_wifi()
with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler) as proxy:
    proxy.daemon_threads = True
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    environment = dict(os.environ, NODE_CONSOLE_TEST_PROXY="http://127.0.0.1:" + str(proxy.server_address[1]))
    try:
        process = subprocess.run(["node", str(folder / "nickname_live_browser.mjs"), release],
            env=environment, capture_output=True, timeout=300, creationflags=NO_WINDOW)
        for line in process.stdout.decode("utf-8", "replace").splitlines():
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if isinstance(value, dict) and set(value) <= {"success", "checks", "report"}:
                print(json.dumps(value))
    finally:
        proxy.shutdown()
raise SystemExit(process.returncode)
