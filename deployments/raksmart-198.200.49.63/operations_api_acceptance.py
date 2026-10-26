"""Exercise operations APIs without changing production accounts or routes."""

import base64
from datetime import datetime, timezone
import hashlib
import json
import secrets

import frontend_motion_access as live
from ssh_access import FOLDER
from update_routing_url import login_sessions, logout_sessions


def main():
    report = {"success": False, "checked_at": datetime.now(timezone.utc).isoformat(),
              "checks": [], "transport": "physical_wlan", "destructive_actions": []}
    sessions = {}
    states = {}

    def check(name, condition):
        live.require(condition, name)
        report["checks"].append({"name": name, "passed": True})

    def api(identity, path, data=None, expected=200):
        session = sessions[identity]
        status, headers, payload = live.request("POST" if data is not None else "GET", path, data,
            {"Cookie": session["cookie"], "X-CSRF-Token": session["csrf"]})
        live.require(status == expected, "Unexpected HTTP status for " + path.split("?", 1)[0] + ": " + str(status))
        return payload, headers

    def api_json(identity, path, data=None, expected=200):
        return json.loads(api(identity, path, data, expected)[0])

    def fingerprint(state):
        fields = ("active", "active_target", "exits", "routing_mode", "domains", "direct_domains", "client_config")
        return hashlib.sha256(json.dumps({key: state.get(key) for key in fields}, sort_keys=True).encode()).hexdigest()

    try:
        deployed = json.loads((FOLDER / "operations-update.json").read_text(encoding="utf-8"))
        check("Release completed before acceptance", deployed.get("success"))
        sessions = login_sessions()
        subscriptions = {}
        for identity in sessions:
            state = api_json(identity, "api/state")
            states[identity] = state
            check("Account state includes health and traffic", "health" in state and "traffic" in state)
            check("Default failover requires manual choice", state["health"]["mode"] == "manual")
            check("Existing accounts remain unlimited", state["traffic"]["quota_bytes"] == state["traffic"]["rate_bps"] == 0)
            traffic = api_json(identity, "api/traffic")
            check("Live telemetry is readable", traffic.get("available") is True)
            check("Traffic isolation follows account role", ("users" in traffic) == (identity == "admin"))
            subscriptions[identity] = api_json(identity, "api/subscription")
            subscription = subscriptions[identity]
            check("Complete profile subscription belongs to this origin", subscription["url"].startswith(live.ORIGIN + "/node-console/subscription/"))
            resource = subscription["url"].split("/node-console/", 1)[1]
            status, headers, profile = live.request("GET", resource)
            check("Bearer subscription downloads the current complete profile", status == 200 and
                  hashlib.sha256(profile).hexdigest() == subscription["hash"])
            stored_profile = api(identity, "api/profile")[0]
            check("Subscription and existing profile content agree", profile == stored_profile)
            audit = api_json(identity, "api/audit?limit=200")
            check("Activity records have the correct scope", audit["scope"] == ("all" if identity == "admin" else "own"))
            if identity != "admin":
                others = [item["user"]["username"] for other_id, item in states.items() if other_id not in (identity, "admin")]
                check("Member activity does not reveal other members", not any(event["actor"] in others for event in audit["events"]))
                for resource in ("api/users", "api/backups", "api/backups/download?token=invalid"):
                    api(identity, resource, expected=403)
            domain = next(iter(state.get("direct_domains", [])), "mooc1.chaoxing.com")
            result = api_json(identity, "api/diagnostics", {"url": "https://" + domain + "/private-course?enc=synthetic-private-token"})
            check("Diagnostics strips private parameters and marks the client unverified", result["domain"] == domain and
                  result["client_verified"] is False and "synthetic-private-token" not in json.dumps(result))
            if state.get("direct_domains"):
                check("Explicit direct domain is predicted DIRECT", result["decision"] == "direct")
        check("All accounts have distinct subscriptions", len({item["url"] for item in subscriptions.values()}) == len(sessions))
        invalid = secrets.token_urlsafe(32)
        status, unused, payload = live.request("GET", "subscription/" + invalid + ".yaml")
        check("Unknown bearer subscription is rejected", status == 404)
        backups = api_json("admin", "api/backups")
        check("Daily encrypted backups are enabled", backups["schedule"]["enabled"] and backups["encryption"] == "AES-256-GCM")
        created = api_json("admin", "api/backups/create", {"name": "升级验收备份"})
        password = secrets.token_urlsafe(24)
        exported = api_json("admin", "api/backups/export", {"id": created["id"], "password": password})
        archive, headers = api("admin", "api/backups/download?token=" + exported["download_token"])
        check("Portable backup downloads as encrypted nvbackup", ".nvbackup" in headers.get("Content-Disposition", "") and
              all(item["url"].encode() not in archive for item in subscriptions.values()))
        encoded = base64.b64encode(archive).decode()
        api("admin", "api/backups/preview", {"data": encoded, "password": "incorrect-fixture-password"}, expected=400)
        preview = api_json("admin", "api/backups/preview", {"data": encoded, "password": password})
        check("Portable backup previews all existing accounts without restoring", len(preview["users"]) == len(sessions) and
              preview["changes"]["files"] >= len(sessions) * 3)
        report["backup_validation"] = {"encrypted": True, "downloaded": True, "previewed": True,
                                       "users": len(preview["users"]), "files": preview["changes"]["files"], "restore_executed": False}
        for identity, before in states.items():
            after = api_json(identity, "api/state")
            check("Acceptance preserves account exits and routing", fingerprint(after) == fingerprint(before))
        report["accounts"] = len(sessions)
        report["success"] = True
    finally:
        logout_sessions(sessions)
        (FOLDER / "operations-api-acceptance.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"success": report["success"], "checks": len(report["checks"]), "accounts": report["accounts"]}))


if __name__ == "__main__":
    main()
