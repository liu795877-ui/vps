"""Run the 158 smart routing page verifier over the physical WLAN only."""

import os
import socketserver
import subprocess
import threading
import traceback

from smart_access import FOLDER, NO_WINDOW, physical_wifi
from smart_browser_proxy import Handler


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
            print("158 smart routing browser verification passed." if result.returncode == 0 else
                  "158 smart routing browser verification failed; inspect the private diagnostic log.")
            return result.returncode
        except Exception:
            traceback.print_exc(file=log)
            print("158 smart routing browser verification failed; inspect the private diagnostic log.")
            return 1
        finally:
            if server:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
