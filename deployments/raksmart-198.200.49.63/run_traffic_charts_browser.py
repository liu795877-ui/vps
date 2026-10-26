"""Read-only traffic-chart acceptance through trusted physical WLAN HTTPS."""
import os
import socketserver
import subprocess
import threading
import traceback

from frontend_motion_access import FOLDER, NO_WINDOW, physical_wifi
from run_user_guide_browser import Handler


def main():
    server = None
    with (FOLDER / "traffic-charts-browser.private.log").open("w", encoding="utf-8") as log:
        try:
            physical_wifi()
            server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
            server.daemon_threads = True
            threading.Thread(target=server.serve_forever, daemon=True).start()
            environment = os.environ.copy()
            environment["NODE_CONSOLE_TEST_PROXY"] = "http://127.0.0.1:" + str(server.server_address[1])
            result = subprocess.run(["node", str(FOLDER / "traffic-charts-browser.mjs")], env=environment,
                                    timeout=240, capture_output=True, stdin=subprocess.DEVNULL,
                                    creationflags=NO_WINDOW)
            log.write(result.stdout.decode("utf-8", errors="replace"))
            log.write(result.stderr.decode("utf-8", errors="replace"))
            print("63 traffic chart browser acceptance passed." if result.returncode == 0 else
                  "63 traffic chart acceptance failed; inspect its redacted report and private log.")
            return result.returncode
        except Exception:
            traceback.print_exc(file=log)
            print("63 traffic chart acceptance failed; inspect its private diagnostic log.")
            return 1
        finally:
            if server:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
