"""Isolated CONNECT proxy: browser HTTPS reaches only the 63 node via WLAN."""

import os
from pathlib import Path
import select
import socketserver
import subprocess
import threading
import traceback

from verify_panel import FOLDER, HOST, IP, NO_WINDOW, physical_socket, physical_wifi


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
            request = header.split(b"\r\n", 1)[0].decode("ascii").split()
            if len(request) != 3 or request[0] != "CONNECT" or request[1] not in (HOST + ":8443", IP + ":8443"):
                self.request.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                return
            upstream = physical_socket(8443, 12)
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.request.settimeout(None)
            upstream.settimeout(None)
            while True:
                ready, _, _ = select.select([self.request, upstream], [], [], 25)
                if not ready:
                    return
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    target = upstream if source is self.request else self.request
                    target.sendall(data)
        except (OSError, UnicodeError):
            pass
        finally:
            if upstream:
                upstream.close()


def main():
    server = None
    with (FOLDER / "panel-browser-verification.private.log").open("w", encoding="utf-8") as log:
        try:
            physical_wifi()
            server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
            server.daemon_threads = True
            threading.Thread(target=server.serve_forever, daemon=True).start()
            environment = os.environ.copy()
            environment["NODE_CONSOLE_TEST_PROXY"] = "http://127.0.0.1:" + str(server.server_address[1])
            result = subprocess.run(["node", str(FOLDER / "browser_smoke.mjs")], env=environment,
                                    timeout=220, capture_output=True, stdin=subprocess.DEVNULL,
                                    creationflags=NO_WINDOW)
            log.write(result.stdout.decode("utf-8", errors="replace"))
            log.write(result.stderr.decode("utf-8", errors="replace"))
            print("Browser verification passed." if result.returncode == 0 else
                  "Browser verification failed; inspect the private diagnostic log.")
            return result.returncode
        except Exception:
            traceback.print_exc(file=log)
            print("Browser verification failed; inspect the private diagnostic log.")
            return 1
        finally:
            if server:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
