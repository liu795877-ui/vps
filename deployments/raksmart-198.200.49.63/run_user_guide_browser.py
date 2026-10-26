"""Read-only user-guide browser acceptance through the physical WLAN."""

import os
import select
import socketserver
import subprocess
import threading
import traceback

from frontend_motion_access import FOLDER, HOST, IP, NO_WINDOW, physical_socket, physical_wifi


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
                    (upstream if source is self.request else self.request).sendall(data)
        except (OSError, UnicodeError):
            pass
        finally:
            if upstream:
                upstream.close()


def main():
    server = None
    with (FOLDER / "user-guide-browser.private.log").open("w", encoding="utf-8") as log:
        try:
            physical_wifi()
            server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
            server.daemon_threads = True
            threading.Thread(target=server.serve_forever, daemon=True).start()
            environment = os.environ.copy()
            environment["NODE_CONSOLE_TEST_PROXY"] = "http://127.0.0.1:" + str(server.server_address[1])
            result = subprocess.run(["node", str(FOLDER / "user-guide-browser.mjs")],
                                    env=environment, timeout=360, capture_output=True,
                                    stdin=subprocess.DEVNULL, creationflags=NO_WINDOW)
            log.write(result.stdout.decode("utf-8", errors="replace"))
            log.write(result.stderr.decode("utf-8", errors="replace"))
            print("63 user guide browser acceptance passed." if result.returncode == 0 else
                  "63 user guide browser acceptance failed; inspect its private diagnostic log.")
            return result.returncode
        except Exception:
            traceback.print_exc(file=log)
            print("63 user guide browser acceptance failed; inspect its private diagnostic log.")
            return 1
        finally:
            if server:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
