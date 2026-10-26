"""Read-only browser acceptance over an owned WLAN-bound CONNECT proxy.

The imported handler accepts only the .63 management TLS endpoint. This runner
does not import or execute browser_smoke.mjs and never changes client settings.
"""

import argparse
import json
import os
from pathlib import Path
import re
import socketserver
import subprocess
import threading

from run_browser_smoke import Handler
from verify_panel import FOLDER, NO_WINDOW, physical_wifi


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-name", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"console-optimization-release-[A-Za-z0-9_-]+", args.release_name):
        parser.error("Use a local console optimization release name")
    manifest = FOLDER / args.release_name / "manifest.json"
    if not manifest.is_file():
        parser.error("The requested local release manifest is missing")

    server = None
    return_code = 1
    runner_failure = None
    try:
        physical_wifi()
        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        environment = os.environ.copy()
        environment["NODE_CONSOLE_TEST_PROXY"] = "http://127.0.0.1:" + str(server.server_address[1])
        result = subprocess.run(
            ["node", str(FOLDER / "console_optimization_browser.mjs"),
             "--release-name", args.release_name],
            env=environment, timeout=480, capture_output=True,
            stdin=subprocess.DEVNULL, creationflags=NO_WINDOW,
        )
        # Browser output can include private input when a locator fails. Keep
        # only the script's structured public summary, never raw stdout/stderr.
        for line in result.stdout.decode("utf-8", errors="replace").splitlines():
            try:
                value = json.loads(line)
            except (ValueError, TypeError):
                continue
            if isinstance(value, dict) and set(value).issubset({"success", "stage", "checks", "accounts", "report"}):
                print(json.dumps(value, ensure_ascii=False))
        return_code = result.returncode
        if return_code:
            runner_failure = "Browser acceptance did not pass; inspect its sanitized report"
    except subprocess.TimeoutExpired:
        runner_failure = "Browser acceptance exceeded its bounded timeout"
    except Exception:
        runner_failure = "Local browser acceptance runner failed before completion"
    finally:
        if server:
            server.shutdown()
            server.server_close()
        public = {
            "success": return_code == 0,
            "release_name": args.release_name,
            "owned_connect_proxy": True,
            "target": "198.200.49.63:8443",
            "physical_wlan": True,
            "secrets_included": False,
            "raw_process_output_saved": False,
        }
        if runner_failure:
            public["failure"] = runner_failure
        (FOLDER / "console-optimization-browser-runner.json").write_text(
            json.dumps(public, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print("63 read-only console browser acceptance passed." if return_code == 0 else
              "63 read-only console browser acceptance failed; inspect the sanitized report.")
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
