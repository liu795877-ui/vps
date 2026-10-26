"""Verify the deployed smart routing page over the existing physical WLAN proxy."""

import os
import socketserver
import subprocess
import threading
import traceback

from run_browser_smoke import Handler
from verify_panel import FOLDER, NO_WINDOW, physical_wifi


def main():
    server = None
    with (FOLDER / "smart-routing-browser-verification.private.log").open("w", encoding="utf-8") as log:
        try:
            physical_wifi()
            server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
            server.daemon_threads = True
            threading.Thread(target=server.serve_forever, daemon=True).start()
            environment = os.environ.copy()
            environment["NODE_CONSOLE_TEST_PROXY"] = "http://127.0.0.1:" + str(server.server_address[1])
            result = subprocess.run(["node", str(FOLDER / "smart-routing-browser.mjs")],
                                    env=environment, timeout=220, capture_output=True,
                                    stdin=subprocess.DEVNULL, creationflags=NO_WINDOW)
            log.write(result.stdout.decode("utf-8", errors="replace"))
            log.write(result.stderr.decode("utf-8", errors="replace"))
            print("Smart routing browser verification passed." if result.returncode == 0 else
                  "Smart routing browser verification failed; inspect the private diagnostic log.")
            return result.returncode
        except Exception:
            traceback.print_exc(file=log)
            print("Smart routing browser verification failed; inspect the private diagnostic log.")
            return 1
        finally:
            if server:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
