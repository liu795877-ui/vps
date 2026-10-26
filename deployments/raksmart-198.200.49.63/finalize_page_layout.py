"""Record the layout release only after frozen and live evidence passes."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


FOLDER = Path(__file__).resolve().parent
ROOT = FOLDER.parents[1]


def read(name):
    return json.loads((FOLDER / name).read_text(encoding="utf-8"))


def write(path, value):
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def main():
    manifest = read("page-layout-release-manifest.json")
    update = read("page-layout-update.json")
    browser = read("page-layout-browser-verification.json")
    preservation = read("page-layout-preservation.json")
    regression_path = ROOT / ".validation/layout-ui/regression-manifest.json"
    regression = json.loads(regression_path.read_text(encoding="utf-8"))
    assert all(item.get("success") is True for item in [update, browser, preservation, regression])
    assert update["deployment_ip"] == preservation["deployment_ip"] == "198.200.49.63"
    assert len(browser["users"]) == 3 and browser["configuration_mutations"] == 0
    assert not browser["browser_errors"] and not browser["blocked_requests"]
    assert all(user["own_settings_preserved"] for user in browser["users"])
    assert all(preservation[key] for key in ["all_account_data_preserved", "all_service_processes_preserved",
                                          "layout_target_state_preserved", "public_assets_verified"])
    assert preservation["services_restarted"] is False and preservation["backend_changed"] is False
    for name, digest in manifest["source_sha256"].items():
        assert regression["frozen_assets"][name.split("/")[-1]] == digest
        assert browser["assets"][name]["sha256"] == digest
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest
    for run in regression["runs"]:
        assert run["success"] and run["frozen_asset_match"]
        assert hashlib.sha256(Path(run["report"]).read_bytes()).hexdigest() == run["report_sha256"]
    assert all((FOLDER / "page-layout-browser-ui" / name).is_file() for name in browser["screenshots"])
    now = datetime.now(timezone.utc).isoformat()
    report_names = ["page-layout-update.json", "page-layout-preservation.json",
                    "page-layout-browser-verification.json", "page-layout-release-manifest.json",
                    "../../.validation/layout-ui/regression-manifest.json"]
    result = {
        "success": True, "checked_at": now, "deployment_ip": "198.200.49.63",
        "url": "https://198-200-49-63.sslip.io:8443/node-console/",
        "asset_version": "layout-20261010-1", "deployment_scope": "frontend_only",
        "features": [
            "Exit management: status strip, connection path, exit cards, full-width health, visible traffic charts",
            "Routing: editable rules and save action first, URL diagnostic second, explanatory disclosures last",
            "Access: subscription and first import first, password and proxy identity disclosures, own audit history",
            "Users: capacity and optional creation, member cards with limits, whole-server usage",
            "Maintenance: schedule, create and download, separate restore preview, all audit history",
            "Responsive mobile order, keyboard disclosures, draft and error indicators",
            "Arrow guides reveal controls and restore disclosure states; logout clears account-specific UI"
        ],
        "local_browser_checks": {run["name"]: run["checks"] for run in regression["runs"]},
        "local_checks_total": regression["total_checks"], "production_accounts_verified": 3,
        "production_viewports": [1440, 1280, 390],
        "physical_wlan_and_trusted_https": browser["physical_wlan"] and browser["trusted_https"],
        "source_sha256": manifest["source_sha256"], "services_restarted": False, "backend_changed": False,
        "all_account_data_preserved": True, "all_service_processes_preserved": True,
        "protected_file_count": preservation["protected_file_count"],
        "protected_service_count": preservation["protected_service_count"],
        "configuration_mutations": 0, "reports": report_names,
        "screenshots_directory": "page-layout-browser-ui",
        "acceptance_adjustments": [
            "The initial mobile attempt used an unspecified 65%-of-viewport path threshold. Final acceptance checks the approved vertical order, single-column cards, touch controls and viewport fit; desktop still requires the complete path in its first viewport. No production source changed for this adjustment."
        ],
        "unfinished_requested_features": [], "secrets_included": False
    }
    write(FOLDER / "page-layout-final-acceptance.json", result)
    state = read("task-state.json")
    state["updated_at"] = now
    state["panel"]["page_layout"] = result
    state["panel"]["frontend_asset_version"] = result["asset_version"]
    for name in report_names[:4] + ["page-layout-final-acceptance.json"]:
        if name not in state["panel"]["reports"]:
            state["panel"]["reports"].append(name)
    write(FOLDER / "task-state.json", state)
    print(json.dumps({"recorded": True, "version": result["asset_version"],
                      "accounts": 3, "local_checks": regression["total_checks"], "secrets_included": False}))


if __name__ == "__main__":
    main()
