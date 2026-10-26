"""Initialize the fresh console through its live authenticated HTTPS API."""
from datetime import datetime, timezone
import json
import time
import traceback

import verify_panel as live


def main():
    report = {"started_at": datetime.now(timezone.utc).isoformat(),
              "origin": live.ORIGIN, "success": False}
    csrf = None
    with (live.FOLDER / "panel-initialization.private.log").open("w", encoding="utf-8") as log:
        try:
            deadline = time.monotonic() + 120
            while True:
                try:
                    status, _, body = live.request("GET", "api/session")
                    live.require(status == 200 and not json.loads(body)["authenticated"],
                                 "Initial HTTPS session is invalid")
                    break
                except Exception as error:
                    if time.monotonic() >= deadline:
                        raise
                    log.write(type(error).__name__ + " while waiting for HTTPS\n")
                    log.flush()
                    time.sleep(2)
            login = json.loads((live.FOLDER / "panel-login.private.json").read_text(encoding="utf-8"))
            live.require(login["url"] == live.ORIGIN + "/node-console/", "Wrong deployment login file")
            status, headers, body = live.request("POST", "api/login", {
                "username": login["username"], "password": login["password"]})
            live.require(status == 200, "Initialization login failed")
            live.cookie = headers["Set-Cookie"].split(";", 1)[0]
            csrf = json.loads(body)["csrf"]
            status, _, body = live.request("GET", "api/state")
            state = json.loads(body)
            live.require(status == 200 and state["server_ip"] == live.IP and
                         not state["demo"] and state["service_active"], "Unexpected live server")
            live.require(not state["exits"], "Only a fresh console without static exits can be initialized")
            if not state["download_ready"]:
                status, _, body = live.request("POST", "api/apply", {"id": "server"},
                                              headers={"X-CSRF-Token": csrf})
                live.require(status == 202, "Server target initialization was not accepted")
                job_id = json.loads(body)["job_id"]
                deadline = time.monotonic() + 100
                while True:
                    status, _, body = live.request("GET", "api/jobs/" + job_id)
                    job = json.loads(body)
                    live.require(status == 200, "Initialization job cannot be read")
                    if job["status"] == "success":
                        break
                    if job["status"] != "running":
                        log.write(json.dumps(job, ensure_ascii=False) + "\n")
                        raise RuntimeError("Server initialization job failed")
                    live.require(time.monotonic() < deadline, "Initialization job exceeded bounded wait")
                    time.sleep(.5)
            status, _, body = live.request("GET", "api/state")
            state = json.loads(body)
            live.require(status == 200 and state["active_target"] == "server" and
                         state["download_ready"] and state["service_active"] and
                         state["server_exit"]["observed_ip"] == live.IP, "Initialized state is incorrect")
            report.update(success=True, active_target="server", exit_count=0,
                          observed_ip=state["server_exit"]["observed_ip"], download_ready=True)
        except Exception:
            traceback.print_exc(file=log)
            report["error"] = "Initialization failed; inspect the private diagnostic log."
        finally:
            if csrf:
                try:
                    live.request("POST", "api/logout", {}, headers={"X-CSRF-Token": csrf})
                except Exception:
                    traceback.print_exc(file=log)
            live.cookie = None
    (live.FOLDER / "panel-initialization.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
