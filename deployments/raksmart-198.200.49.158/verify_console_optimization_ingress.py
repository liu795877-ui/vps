"""Verify the 158 Caddy backup-preview size exception with invalid data.

Only a synthetic invalid preview and a nonexistent API request are submitted.
The payload cannot create a backup or restore anything. Production credentials,
cookies, CSRF values, response bodies and state snapshots stay in memory.
Normal TLS trust and the owned physical-WLAN connection are required.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import smart_access as live

FOLDER = Path(__file__).resolve().parent
REPORT = FOLDER / "console-optimization-ingress-verification.json"
CONFIG_KEYS = ("user", "server_ip", "server_port", "active_target", "active", "exits",
               "domains", "direct_domains", "routing_mode", "dirty", "routing_dirty")
RUNTIME_KEYS = {"updated", "updated_at", "stats", "traffic", "telemetry", "health",
                "sampled_at", "checked_at", "tested_at", "created_at", "last_sample",
                "service_active", "hy2_service_active"}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def semantic(value):
    if isinstance(value, dict):
        return {key: semantic(child) for key, child in value.items() if key not in RUNTIME_KEYS}
    if isinstance(value, list):
        return [semantic(child) for child in value]
    return value


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def get_json(path):
    status, headers, body = live.request("GET", path)
    require(status == 200, "Read-only observation is unavailable")
    value = json.loads(body)
    require(isinstance(value, dict), "Read-only observation has an invalid shape")
    return value


def snapshot():
    state = get_json("api/state")
    require(state.get("server_ip") == live.IP and (state.get("user") or {}).get("role") == "admin",
            "Authenticated observation targets another server or account")
    require(not state.get("job"), "An exit task is active during ingress acceptance")
    entrances = get_json("api/entrances")
    tasks = get_json("api/users/provision")
    return {"state": semantic({key: state.get(key) for key in CONFIG_KEYS}),
            "entrances": semantic(entrances), "tasks": semantic(tasks)}


def main():
    report = {"success": False, "checked_at": datetime.now(timezone.utc).isoformat(),
              "deployment_ip": live.IP, "origin": live.ORIGIN, "secrets_included": False,
              "physical_wlan": True, "trusted_https": True, "configuration_mutations": 0,
              "synthetic_failed_preview_only": True, "backup_created": False,
              "restore_attempted": False, "audit_may_grow": True, "checks": []}
    stage = "trusted_session"
    csrf = None
    live.cookie = None
    try:
        live.physical_wifi()
        session = get_json("api/session")
        require(session.get("authenticated") is False, "Fresh ingress session is unexpectedly authenticated")
        stage = "administrator_login"
        login = json.loads((FOLDER / "panel-login.private.json").read_text(encoding="utf-8"))
        require(login.get("url") == live.ORIGIN + "/node-console/" and login.get("username") == "admin",
                "Local administrator metadata targets another node")
        status, headers, body = live.request("POST", "api/login",
                                           {"username": login["username"], "password": login["password"]})
        login = None
        require(status == 200, "Administrator login did not pass")
        cookie = headers.get("Set-Cookie", "")
        require(all(flag in cookie for flag in ("Secure", "HttpOnly", "SameSite=Strict", "Path=/node-console/")),
                "Session cookie protections differ")
        live.cookie = cookie.split(";", 1)[0]
        csrf = json.loads(body)["csrf"]
        require(isinstance(csrf, str) and csrf, "Login CSRF token is unavailable")
        report["checks"].append("Trusted HTTPS administrator session and protected cookie")
        stage = "before_snapshot"
        before = snapshot()
        # The invalid base64 marker guarantees rejection before decryption,
        # snapshot validation, or creation of a preview token. Large padding
        # solely exercises the ingress body limit; it is synthetic ASCII.
        payload = {"data": "!" + "A" * (96 * 1024), "password": "synthetic-ingress-password-only"}
        body_length = len(json.dumps(payload).encode("utf-8"))
        require(65536 < body_length < 128 * 1024, "Synthetic probe size is outside its intended bound")
        report["synthetic_request_bytes"] = body_length
        stage = "preview_size_exception"
        status, headers, body = live.request("POST", "api/backups/preview", payload,
                                           headers={"X-CSRF-Token": csrf})
        require(status == 400 and headers.get("Content-Type", "").lower().startswith("application/json"),
                "Backup preview did not reach the panel as a JSON validation failure")
        error = json.loads(body)
        require(isinstance(error, dict) and set(error) == {"error"}
                and error["error"] == "请选择有效的加密备份文件。",
                "Synthetic preview was not rejected by the expected panel validator")
        report["preview_status"] = 400
        report["panel_preview_validator_reached"] = True
        report["checks"].append("Preview accepts more than 64KB through Caddy and rejects invalid data with panel JSON 400")
        stage = "ordinary_api_body_limit"
        status, _, _ = live.request("POST", "api/_console_ingress_limit_probe", payload,
                                    headers={"X-CSRF-Token": csrf})
        require(status == 413, "Ordinary API request no longer enforces the small body limit")
        report["ordinary_api_status"] = 413
        report["checks"].append("The same oversized synthetic JSON remains rejected with 413 on an ordinary nonexistent API")
        stage = "after_snapshot"
        after = snapshot()
        require(after == before, "Ingress probes changed configuration, entrance pool or preparation tasks")
        report["protected_semantic_sha256"] = {name: fingerprint(value) for name, value in before.items()}
        report["checks"].append("Routing, exit, account, entrance pool and preparation tasks retain their previous values")
        report["success"] = True
    except Exception:
        report["failure"] = {"stage": stage, "message": "Ingress acceptance did not pass"}
    finally:
        if csrf:
            try:
                status, _, _ = live.request("POST", "api/logout", {}, headers={"X-CSRF-Token": csrf})
                require(status == 200, "Ingress session logout failed")
                report["logout_completed"] = True
                report["checks"].append("Temporary administrator session logged out")
            except Exception:
                report["success"] = False
                report["logout_completed"] = False
                report["failure"] = {"stage": "logout", "message": "Ingress acceptance could not close its session"}
        live.cookie = None
        csrf = None
        REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"success": report["success"], "stage": stage,
                          "checks": len(report["checks"]), "report": REPORT.name}))
    return 0 if report["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
