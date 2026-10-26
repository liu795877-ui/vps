"""Read-only 158 browser acceptance through an owned WLAN CONNECT proxy.

Importing this module does not access private data, start a listener, or contact
production. Only this invocation's loopback listener and browser are owned here.
"""

import argparse
import json
import os
import re
import select
import socketserver
import subprocess
import threading

from smart_access import FOLDER, HOST, IP, NO_WINDOW, physical_socket, physical_wifi


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        upstream = None
        try:
            self.request.settimeout(10)
            header = b""
            while b"\r\n\r\n" not in header and len(header) < 8192:
                part = self.request.recv(1024)
                if not part:
                    return
                header += part
            boundary = header.find(b"\r\n\r\n")
            request = header.split(b"\r\n", 1)[0].decode("ascii").split()
            if (boundary < 0 or len(request) != 3 or request[0] != "CONNECT"
                    or request[1] not in (HOST + ":8443", IP + ":8443")
                    or request[2] not in ("HTTP/1.0", "HTTP/1.1")):
                self.request.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                return
            upstream = physical_socket(8443, timeout=10)
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            remaining = header[boundary + 4:]
            if remaining:
                upstream.sendall(remaining)
            self.request.settimeout(None)
            upstream.settimeout(None)
            while True:
                ready, _, _ = select.select([self.request, upstream], [], [], 15)
                if not ready:
                    return
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    (upstream if source is self.request else self.request).sendall(data)
        except (OSError, ValueError, UnicodeError):
            pass
        finally:
            if upstream:
                upstream.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-name", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"console-optimization-release-[A-Za-z0-9_-]+", args.release_name):
        parser.error("Use a local console optimization release name")
    if not (FOLDER / args.release_name / "manifest.json").is_file():
        parser.error("The requested local release manifest is missing")
    server = None
    return_code = 1
    failure = None
    try:
        physical_wifi()
        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        environment = os.environ.copy()
        environment["NODE_CONSOLE_TEST_PROXY"] = "http://127.0.0.1:" + str(server.server_address[1])
        result = subprocess.run([
            "node", str(FOLDER / "console_optimization_browser.mjs"),
            "--release-name", args.release_name,
        ], env=environment, timeout=480, capture_output=True,
           stdin=subprocess.DEVNULL, creationflags=NO_WINDOW)
        # Never print raw Playwright errors: input, URL, or private DOM values
        # can be included in failed locator diagnostics.
        for line in result.stdout.decode("utf-8", errors="replace").splitlines():
            try:
                value = json.loads(line)
            except (ValueError, TypeError):
                continue
            if (isinstance(value, dict)
                    and set(value).issubset({"success", "stage", "checks", "accounts", "report"})):
                print(json.dumps(value, ensure_ascii=False))
        return_code = result.returncode
        if return_code:
            failure = "Browser acceptance did not pass; inspect its sanitized report"
    except subprocess.TimeoutExpired:
        failure = "Browser acceptance exceeded its bounded timeout"
    except Exception:
        failure = "Local browser acceptance runner failed before completion"
    finally:
        if server:
            server.shutdown()
            server.server_close()
        public = {"success": return_code == 0, "release_name": args.release_name,
                  "owned_connect_proxy": True, "target": IP + ":8443",
                  "physical_wlan": True, "secrets_included": False,
                  "raw_process_output_saved": False}
        if failure:
            public["failure"] = failure
        (FOLDER / "console-optimization-browser-runner.json").write_text(
            json.dumps(public, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print("158 read-only console browser acceptance passed." if return_code == 0 else
              "158 read-only console browser acceptance failed; inspect the sanitized report.")
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
