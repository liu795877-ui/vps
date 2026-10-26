"""Read-only post-install integrity check after AUTO initialization.

The first Xray identity, complete immutable inbound settings, REALITY and DNS
are compared with the locally saved preflight config. Added AUTO identities
and routing rules are expected; the whole Xray hash is allowed to change.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import traceback
from unittest.mock import patch

from ssh_access import connect, execute, HOST, HOST_KEYS

FOLDER = Path(__file__).resolve().parent
NO_WINDOW = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
CONFIG = "/usr/local/etc/xray/config.json"
PROTECTED = (
    "/usr/local/etc/raksmart-hy2/server.yaml",
    "/etc/systemd/system/xray.service",
    "/etc/systemd/system/raksmart-hy2.service",
    "/etc/resolv.conf",
)

REMOTE = r'''python3 - <<'PY'
import copy
import hashlib
import json
from pathlib import Path
import subprocess

def fingerprint(value):
    payload = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    return hashlib.sha256(payload).hexdigest()

def signature(config):
    inbound = copy.deepcopy(config['inbounds'][0])
    first = inbound['settings']['clients'][0]
    inbound['settings']['clients'] = [first]
    return {
        'first_identity': fingerprint(first),
        'immutable_inbound': fingerprint(inbound),
        'reality': fingerprint(inbound['streamSettings']['realitySettings']),
        'dns': fingerprint(config.get('dns')),
        'base_config': fingerprint(config),
    }

config_path = Path('/usr/local/etc/xray/config.json')
payload = config_path.read_bytes()
config = json.loads(payload)
manager = json.loads(Path('/var/lib/vps-panel/state.private.json').read_text(encoding='utf-8'))
paths = ['/usr/local/etc/raksmart-hy2/server.yaml', '/etc/systemd/system/xray.service',
         '/etc/systemd/system/raksmart-hy2.service', '/etc/resolv.conf']
services = {}
for name in ['xray.service', 'raksmart-hy2.service', 'vps-panel.service', 'caddy.service']:
    services[name] = {
        'active': subprocess.run(['systemctl', 'is-active', '--quiet', name],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10).returncode == 0,
        'enabled': subprocess.run(['systemctl', 'is-enabled', '--quiet', name],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10).returncode == 0,
    }
print(json.dumps({
    'services': services,
    'signature': signature(config),
    'protected_hashes': {path: hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in paths},
    'manager_base_signature': signature(manager['base']),
    'auto_ready': bool(manager.get('profile')),
    'active_target': 'server' if manager.get('active_id') in (None, 'server') else 'static',
    'static_exit_count': len(manager.get('exits', [])),
    'manager_tracks_current_config': manager.get('managed_hash') == hashlib.sha256(payload).hexdigest(),
    'auto_identity_installed': any(item.get('id') == manager.get('auto_id')
                                  for item in config['inbounds'][0]['settings']['clients'][1:]),
    'xray_whole_config_hash_changed': hashlib.sha256(payload).hexdigest() !=
        json.loads(Path('/root/raksmart-proxy-deploy-20261009/panel/install-state.json').read_text(encoding='utf-8'))
            ['protected_hashes']['/usr/local/etc/xray/config.json'],
}))
PY
'''


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode("utf-8")).hexdigest()


def baseline_signature(config):
    import copy
    inbound = copy.deepcopy(config["inbounds"][0])
    first = inbound["settings"]["clients"][0]
    inbound["settings"]["clients"] = [first]
    return {"first_identity": fingerprint(first), "immutable_inbound": fingerprint(inbound),
            "reality": fingerprint(inbound["streamSettings"]["realitySettings"]),
            "dns": fingerprint(config.get("dns")), "base_config": fingerprint(config)}


def main():
    client = None
    report = {"checked_at": datetime.now(timezone(timedelta(hours=8))).isoformat(timespec="seconds"),
              "server_ip": "198.200.49.63", "success": False, "checks": {}}
    stage = "local_preflight"
    with (FOLDER / "panel-preservation.private.log").open("w", encoding="utf-8") as log:
        try:
            require(HOST == "198.200.49.63" and HOST_KEYS.is_file(), "Pinned SSH identity for the 63 server is required")
            baseline_bytes = (FOLDER / "panel-adoption-server.private.json").read_bytes()
            baseline = json.loads(baseline_bytes)
            preflight = json.loads((FOLDER / "panel-preflight.json").read_text(encoding="utf-8"))
            install = json.loads((FOLDER / "panel-install-state.json").read_text(encoding="utf-8"))
            require(install.get("status") == "complete", "Local installer report is not complete")
            before = install["protected_hashes"]
            original_hash = hashlib.sha256(baseline_bytes).hexdigest()
            require(original_hash == preflight["xray_config_sha256"] == before[CONFIG],
                    "Local original config does not match preflight and installation snapshots")
            signature = baseline_signature(baseline)
            report["checks"]["baseline_matches_preflight"] = True
            stage = "read_only_remote_snapshot"
            original_run = subprocess.run

            def hidden_run(*args, **kwargs):
                kwargs.setdefault("creationflags", NO_WINDOW)
                return original_run(*args, **kwargs)

            with patch("subprocess.run", hidden_run):
                client = connect()
            code, output, error = execute(client, REMOTE, timeout=75)
            log.write(output + "\n" + error)
            log.flush()
            require(code == 0, "Read-only remote preservation snapshot failed")
            current = json.loads(output)
            report["services"] = current["services"]
            report["checks"]["four_services_active_and_enabled"] = all(
                item["active"] and item["enabled"] for item in current["services"].values())
            for key in ("first_identity", "immutable_inbound", "reality", "dns"):
                report["checks"]["xray_" + key + "_preserved"] = current["signature"][key] == signature[key]
            report["checks"]["panel_saved_original_base"] = current["manager_base_signature"] == signature
            for path, name in ((PROTECTED[0], "hy2_config"), (PROTECTED[1], "xray_unit"),
                               (PROTECTED[2], "hy2_unit"), (PROTECTED[3], "resolv_conf")):
                report["checks"][name + "_preserved"] = current["protected_hashes"][path] == before[path]
            report["checks"]["auto_profile_ready"] = current["auto_ready"]
            report["checks"]["auto_identity_installed"] = current["auto_identity_installed"]
            report["checks"]["manager_tracks_current_config"] = current["manager_tracks_current_config"]
            report["active_target"] = current["active_target"]
            report["static_exit_count"] = current["static_exit_count"]
            report["xray_config_changed_for_auto"] = current["xray_whole_config_hash_changed"]
            require(all(report["checks"].values()), "A service or protected original setting failed preservation verification")
            report["success"] = True
        except Exception:
            traceback.print_exc(file=log)
            report["failed_stage"] = stage
            report["error"] = "Preservation check failed; inspect the private diagnostic log."
        finally:
            if client:
                client.close()
    (FOLDER / "panel-preservation-verification.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
