"""Freeze and publish only the traffic-chart browser assets to server 63.

Preparation is local. Publishing never stops or restarts a service, never writes
account data, and preserves all users, routing lists and proxy process identities.
The frozen files pass both loopback and trusted physical-WLAN HTTPS hash checks.
Any failed acceptance rolls back only this release's three browser source files.
"""

import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import secrets
import shlex
import shutil
import subprocess
import tarfile
import traceback

from ssh_access import FOLDER, connect, execute
import frontend_motion_access as live
from update_routing_url import login_sessions, logout_sessions


ROOT = FOLDER.parents[1]
# HTML is published last, after the matching style and script are available.
FILES = ["panel/web/style.css", "panel/web/app.js", "panel/web/index.html"]
RELEASE = FOLDER / "traffic-charts-release"
ARCHIVE = FOLDER / "traffic-charts-release.tar.gz"
MANIFEST = FOLDER / "traffic-charts-release-manifest.json"
REPORT = FOLDER / "traffic-charts-update.json"
VERIFY_REPORT = FOLDER / "traffic-charts-preservation.json"
PREFIX = "/root/raksmart-proxy-deploy-20261009/traffic-charts-"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def clean_file(path):
    return (path.is_file() and not path.is_symlink() and "__pycache__" not in path.parts
            and path.suffix != ".pyc" and ".private." not in path.name)


def prepare():
    baseline = FOLDER / "panel-release"
    live.require(baseline.is_dir() and not baseline.is_symlink(), "Current compatible source baseline is unavailable")
    names = sorted(candidate.relative_to(baseline).as_posix()
                   for candidate in baseline.rglob("*") if clean_file(candidate))
    live.require(set(FILES).issubset(names) and "panel/server.py" in names and "configure_reality.py" in names,
                 "The deployed source baseline is incomplete")
    if RELEASE.exists():
        live.require(RELEASE.resolve().parent == FOLDER.resolve() and RELEASE.name == "traffic-charts-release"
                     and not RELEASE.is_symlink(), "Unsafe local release directory")
        shutil.rmtree(RELEASE)
    RELEASE.mkdir()
    baseline_hashes = {}
    for name in names:
        source = baseline / name
        destination = RELEASE / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes())
        baseline_hashes[name] = sha(source)
    for name in FILES:
        source = ROOT / name
        live.require(source.is_file() and not source.is_symlink(), "Unexpected local chart asset")
        (RELEASE / name).write_bytes(source.read_bytes())
    subprocess.run(["node", "--check", str(RELEASE / "panel/web/app.js")], check=True,
                   capture_output=True, timeout=15, creationflags=live.NO_WINDOW)
    ast.parse(PROGRAM, filename="traffic_charts_remote_publish.py", feature_version=(3, 6))
    with tarfile.open(ARCHIVE, "w:gz") as bundle:
        for name in names:
            bundle.add(RELEASE / name, arcname="release/" + name, recursive=False)
    manifest = {"deployment_ip": live.IP, "files": FILES, "release_files": names,
                "prepared_at": datetime.now(timezone.utc).isoformat(), "archive_sha256": sha(ARCHIVE),
                "source_sha256": {name: sha(RELEASE / name) for name in FILES},
                "release_sha256": {name: sha(RELEASE / name) for name in names},
                "baseline_sha256": baseline_hashes, "deployment_scope": "frontend_only",
                "services_restarted": False, "backend_and_adapters_unchanged": True,
                "remote_program_python_syntax": "3.6"}
    live.require(all(manifest["baseline_sha256"][name] == manifest["release_sha256"][name]
                     for name in names if name not in FILES), "An unchanged baseline file was modified")
    MANIFEST.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def frozen_manifest():
    live.require(MANIFEST.is_file(), "Prepare and review the frozen chart release first")
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    live.require(manifest.get("deployment_ip") == live.IP and manifest.get("files") == FILES
                 and manifest.get("deployment_scope") == "frontend_only", "Unexpected chart target or file scope")
    live.require(sha(ARCHIVE) == manifest["archive_sha256"], "Frozen chart archive changed")
    for name in manifest["release_files"]:
        live.require(isinstance(name, str) and not Path(name).is_absolute() and ".." not in Path(name).parts,
                     "Unsafe release file name")
        live.require(sha(RELEASE / name) == manifest["release_sha256"][name], "Frozen chart source changed")
    live.require(set(manifest["source_sha256"]) == set(FILES)
                 and all(manifest["source_sha256"][name] == manifest["release_sha256"][name] for name in FILES),
                 "Incomplete or inconsistent chart manifest")
    return manifest


PROGRAM = r'''
import hashlib, json, os, re, stat, subprocess, sys, tarfile, time, traceback
from pathlib import Path
from urllib.request import Request, urlopen

stage = Path(STAGE)
target = Path('/opt/vps-panel')
registry = Path('/var/lib/vps-panel/users.private.json')
files = ['panel/web/style.css', 'panel/web/app.js', 'panel/web/index.html']
manifest = json.loads((stage / 'manifest.json').read_text())
result = {'success': False, 'phase': 'preflight', 'deployment_ip': '198.200.49.63',
          'updated_files': files, 'backup': str(stage / 'before'), 'stage': str(stage),
          'services_restarted': False, 'backend_changed': False,
          'private_configuration_untouched': True, 'configuration_mutations': 0}
installed = []
baseline = None

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def private_json(path, value):
    path.write_text(json.dumps(value, indent=2))
    os.chmod(str(path), 0o600)

def record(phase):
    result['phase'] = phase
    private_json(stage / 'update-state.json', result)

def service_status(services):
    properties = ['ActiveState', 'SubState', 'UnitFileState', 'MainPID',
                  'ActiveEnterTimestampMonotonic', 'ExecMainStartTimestampMonotonic', 'NRestarts']
    snapshot = {}
    for service in services:
        # Read-only systemd inspection is the sole subprocess operation.
        response = subprocess.run(['systemctl', 'show', service], stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, timeout=8)
        with (stage / 'commands.private.log').open('ab') as log:
            log.write(response.stdout + b'\n' + response.stderr)
        require(response.returncode == 0, 'Could not inspect a protected service')
        fields = dict(line.split('=', 1) for line in response.stdout.decode().splitlines() if '=' in line)
        require(all(key in fields for key in properties[:6]), 'A service snapshot is incomplete')
        snapshot[service] = {key: fields[key] for key in properties if key in fields}
    require(snapshot['vps-panel.service']['ActiveState'] == 'active'
            and snapshot['vps-panel.service']['UnitFileState'] == 'enabled'
            and int(snapshot['vps-panel.service']['MainPID']) > 0,
            'The existing panel process is unavailable')
    return snapshot

def registry_records():
    require(registry.is_file() and not registry.is_symlink(), 'Existing account registry is unavailable')
    data = json.loads(registry.read_text())
    require(data.get('version') == 1 and isinstance(data.get('users'), list) and len(data['users']) <= 2,
            'Unexpected account registry')
    ids, ports = set(), set()
    for user in data['users']:
        require(isinstance(user, dict) and isinstance(user.get('id'), str)
                and re.fullmatch(r'[a-f0-9]{16}', user['id']) is not None
                and user['id'] not in ids and user.get('port') in [1443, 2443] and user['port'] not in ports
                and user.get('role') == 'member' and type(user.get('enabled')) is bool,
                'Unexpected member metadata')
        ids.add(user['id'])
        ports.add(user['port'])
    return data['users']

def inventory():
    users = registry_records()
    protected = [Path('/usr/local/etc/xray/config.json'), Path('/usr/local/etc/raksmart-hy2/server.yaml'),
                 Path('/etc/systemd/system/xray.service'), Path('/etc/systemd/system/raksmart-hy2.service'),
                 Path('/etc/systemd/system/vps-panel.service'), Path('/etc/systemd/system/caddy.service'),
                 Path('/etc/caddy/Caddyfile'), Path('/var/lib/vps-panel/auth.private.json'),
                 Path('/etc/resolv.conf'), Path('/var/lib/vps-panel/base.private.yaml'),
                 Path('/var/lib/vps-panel/state.private.json'), registry,
                 Path('/etc/systemd/system/xray-panel@.service'),
                 Path('/etc/systemd/system/vps-panel.service.d/multiuser-paths.conf')]
    protected.extend(target / name for name in manifest['release_files'] if name not in files)
    directories = [Path('/var/lib/vps-panel'), Path('/var/lib/vps-panel/users'), Path('/usr/local/etc/xray-members')]
    services = ['xray.service', 'raksmart-hy2.service', 'caddy.service', 'vps-panel.service']
    states = [('admin', Path('/var/lib/vps-panel/state.private.json'), Path('/usr/local/etc/xray/config.json'))]
    for user in users:
        data_dir = Path('/var/lib/vps-panel/users') / user['id']
        config_dir = Path('/usr/local/etc/xray-members') / user['id']
        state_path, config_path = data_dir / 'state.private.json', config_dir / 'config.json'
        protected.extend([state_path, config_path])
        directories.extend([data_dir, config_dir])
        services.append('xray-panel@' + user['id'] + '.service')
        states.append((user['id'], state_path, config_path))
    for service in services + ['xray-panel@.service']:
        directory = Path('/etc/systemd/system') / (service + '.d')
        if directory.exists():
            require(not directory.is_symlink(), 'Unexpected service drop-in symlink')
            protected.extend(path for path in directory.glob('*.conf') if path not in protected)
    return users, protected, directories, services, states

def attributes(path):
    info = path.stat()
    return {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}

def snapshot(check_coherence=True):
    users, protected, directories, services, states = inventory()
    for path in protected:
        require(path.is_file() and not path.is_symlink(), 'Unexpected protected source or configuration')
    for directory in directories:
        require(directory.is_dir() and not directory.is_symlink(), 'Unexpected private directory')
    for _, state_path, config_path in states:
        if check_coherence:
            require(json.loads(state_path.read_text()).get('managed_hash') == sha(config_path),
                    'An account state differs from its running config')
    # Chart targets read the administrator's existing lists, including any course
    # domain already saved. The chart must not modify those lists or identities.
    owner_path = Path('/var/lib/vps-panel/state.private.json')
    owner = json.loads(owner_path.read_text())
    chart_target = {'user_id': 'admin', 'state_sha256': sha(owner_path),
                    'routing_mode': owner.get('routing_mode'), 'domains': owner.get('domains'),
                    'direct_domains': owner.get('direct_domains'), 'active_id': owner.get('active_id')}
    return {'protected_sha256': {str(path): sha(path) for path in protected},
            'file_attributes': {str(path): attributes(path) for path in protected},
            'directory_attributes': {str(path): attributes(path) for path in directories},
            'services': service_status(services), 'chart_target_state': chart_target,
            'enabled_users': ['admin'] + sorted(user['id'] for user in users if user['enabled'])}

def preserved(expected):
    require(snapshot() == expected, 'Account data, source, permissions or service process changed')

def wait_idle():
    sessions = json.loads((stage / 'sessions.private.json').read_text())
    users = snapshot(False)['enabled_users']
    require(sorted(sessions) == sorted(users), 'Enabled account preflight sessions are incomplete')
    deadline = time.monotonic() + 45
    while True:
        idle = True
        for user_id, session in sessions.items():
            query = Request('http://127.0.0.1:18787/api/state', headers={'Cookie': session['cookie']})
            with urlopen(query, timeout=3) as response:
                state = json.loads(response.read().decode())
            require(state.get('server_ip') == '198.200.49.63' and state.get('user', {}).get('id') == user_id,
                    'An authenticated preflight session identifies another account')
            idle = idle and (state.get('job') or {}).get('status') != 'running'
        if idle:
            return
        require(time.monotonic() < deadline, 'An exit operation is running; chart release safely deferred')
        time.sleep(.4)

def safe_source(path, content, metadata):
    require(not path.is_symlink(), 'Unexpected source symlink')
    temporary = path.with_name('.' + path.name + '.traffic-charts-' + stage.name[-6:])
    try:
        with temporary.open('xb') as stream:
            os.fchmod(stream.fileno(), metadata['mode'])
            os.fchown(stream.fileno(), metadata['uid'], metadata['gid'])
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(str(temporary), str(path))
    finally:
        if temporary.exists():
            temporary.unlink()

def served_assets(expected):
    resources = {'panel/web/index.html': '/', 'panel/web/app.js': '/app.js', 'panel/web/style.css': '/style.css'}
    for name, resource in resources.items():
        with urlopen('http://127.0.0.1:18787' + resource + '?v=' + expected[name][:16], timeout=5) as response:
            require(response.status == 200 and hashlib.sha256(response.read()).hexdigest() == expected[name],
                    'Worker serves an unexpected chart asset')
            require('no-store' in response.headers.get('Cache-Control', ''), 'Chart asset cache policy changed')

def safe_extract():
    require(sha(stage / 'release.tar.gz') == manifest['archive_sha256'], 'Frozen archive hash mismatch')
    names = manifest['release_files']
    require(isinstance(names, list) and len(names) == len(set(names)), 'Duplicate release file names')
    require(set(manifest['release_sha256']) == set(names)
            and set(manifest['baseline_sha256']) == set(names) and set(files).issubset(names),
            'Incomplete release hash inventory')
    for name in names:
        require(isinstance(name, str) and not name.startswith('/') and '\\' not in name
                and '..' not in Path(name).parts and '.private.' not in name, 'Unsafe release file name')
    require(all(manifest['source_sha256'][name] == manifest['release_sha256'][name] for name in files),
            'Inconsistent chart source hashes')
    with tarfile.open(str(stage / 'release.tar.gz'), 'r:gz') as archive:
        entries = archive.getmembers()
        require(len(entries) == len(names) and {entry.name for entry in entries} == {'release/' + name for name in names}
                and all(entry.isfile() for entry in entries) and sum(entry.size for entry in entries) < 20000000,
                'Unexpected archive entries')
        for entry in entries:
            destination = stage / entry.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(entry) as source, destination.open('xb') as stream:
                stream.write(source.read())
            os.chmod(str(destination), 0o600)
    for name in names:
        require(sha(stage / 'release' / name) == manifest['release_sha256'][name], 'Candidate source hash mismatch')
        require((target / name).is_file() and not (target / name).is_symlink()
                and sha(target / name) == manifest['baseline_sha256'][name], 'Current deployed source baseline differs')
        if name not in files:
            require(manifest['release_sha256'][name] == manifest['baseline_sha256'][name], 'Backend or adapter candidate changed')

def rollback_sources():
    before = stage / 'before'
    metadata = json.loads((before / 'source-attributes.private.json').read_text())
    for name in reversed(files):
        path = target / name
        current_hash = sha(path)
        if current_hash == manifest['baseline_sha256'][name]:
            continue
        require(current_hash == manifest['source_sha256'][name], 'Concurrent source change prevents rollback')
        backup = before / name
        require(sha(backup) == manifest['baseline_sha256'][name], 'Private source backup differs')
        safe_source(path, backup.read_bytes(), metadata[name])
    served_assets(manifest['baseline_sha256'])

def rollback_preservation(expected):
    # Restoring the three sources and checking unrelated live state are separate
    # outcomes. A legitimate user edit must not be reported as a source failure.
    try:
        actual = snapshot()
        result.update(preservation_verified_after_rollback=actual == expected,
                      all_account_data_preserved=all(actual[key] == expected[key] for key in
                          ['protected_sha256', 'file_attributes', 'directory_attributes', 'enabled_users']),
                      all_service_processes_preserved=actual['services'] == expected['services'],
                      chart_target_state_preserved=actual['chart_target_state'] == expected['chart_target_state'])
        if actual != expected:
            private_json(stage / 'rollback-preservation-difference.private.json',
                         {'expected': expected, 'actual': actual})
    except BaseException:
        (stage / 'rollback-preservation-error.private.log').write_text(traceback.format_exc())
        result.update(preservation_verified_after_rollback=False, all_account_data_preserved=None,
                      all_service_processes_preserved=None, chart_target_state_preserved=None)

try:
    os.umask(0o077)
    require(manifest.get('deployment_ip') == '198.200.49.63' and manifest.get('files') == files
            and manifest.get('deployment_scope') == 'frontend_only'
            and set(manifest.get('source_sha256', {})) == set(files), 'Unexpected chart target or update scope')
    if ACTION == 'install':
        record('preflight')
        safe_extract()
        wait_idle()
        baseline = snapshot()
        before = stage / 'before'
        before.mkdir(mode=0o700)
        private_json(before / 'protected-snapshot.private.json', baseline)
        metadata = {}
        for name in files:
            source = target / name
            metadata[name] = attributes(source)
            destination = before / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
        private_json(before / 'source-attributes.private.json', metadata)
        preserved(baseline)
        record('install-reviewed-chart-assets')
        for name in files:
            source = target / name
            require(sha(source) == manifest['baseline_sha256'][name], 'A chart source changed concurrently')
            installed.append(name)
            safe_source(source, (stage / 'release' / name).read_bytes(), metadata[name])
        served_assets(manifest['source_sha256'])
        preserved(baseline)
        result.update(local_assets_verified=True, all_account_data_preserved=True,
                      all_service_processes_preserved=True, chart_target_state_preserved=True,
                      candidate_installed=True, protected_file_count=len(baseline['protected_sha256']),
                      protected_service_count=len(baseline['services']))
        record('awaiting-public-verification')
    elif ACTION in ['finalize', 'verify']:
        result = json.loads((stage / 'update-state.json').read_text())
        require(result.get('candidate_installed') is True, 'Chart candidate was not installed')
        baseline = json.loads((stage / 'before/protected-snapshot.private.json').read_text())
        preserved(baseline)
        for name in files:
            require(sha(target / name) == manifest['source_sha256'][name], 'Installed chart source differs')
        served_assets(manifest['source_sha256'])
        result.update(success=True, public_assets_verified=True, all_account_data_preserved=True,
                      all_service_processes_preserved=True, chart_target_state_preserved=True,
                      services_restarted=False)
        if ACTION == 'finalize':
            record('complete')
        else:
            result['phase'] = 'verified'
            private_json(stage / 'verify-state.json', result)
    elif ACTION == 'rollback':
        result = json.loads((stage / 'update-state.json').read_text())
        baseline = json.loads((stage / 'before/protected-snapshot.private.json').read_text())
        rollback_sources()
        result.update(success=False, source_rollback_succeeded=True, services_restarted=False,
                      phase='failed-public-verification')
        rollback_preservation(baseline)
        private_json(stage / 'update-state.json', result)
    else:
        raise RuntimeError('Unsupported chart release action')
except BaseException:
    (stage / (ACTION + '-error.private.log')).write_text(traceback.format_exc())
    if ACTION == 'install' and installed:
        try:
            rollback_sources()
            result['source_rollback_succeeded'] = True
            if baseline is not None:
                rollback_preservation(baseline)
        except BaseException:
            (stage / 'rollback-error.private.log').write_text(traceback.format_exc())
            result.update(source_rollback_succeeded=False, rollback_failed=True)
    result.update(success=False, phase='failed')
    private_json(stage / ('verify-state.json' if ACTION == 'verify' else 'update-state.json'), result)
    print(json.dumps(result))
    sys.exit(1)
print(json.dumps(result))
'''


def public_assets(expected):
    resources = {"panel/web/index.html": "", "panel/web/app.js": "app.js", "panel/web/style.css": "style.css"}
    for name, resource in resources.items():
        status, headers, payload = live.request("GET", resource + "?v=" + expected[name][:16])
        live.require(status == 200 and hashlib.sha256(payload).hexdigest() == expected[name],
                     "Trusted public HTTPS serves an unexpected chart asset")
        cache = next((value for key, value in headers.items() if key.lower() == "cache-control"), "")
        live.require("no-store" in cache, "Public chart asset cache policy changed")


def stage_from_report():
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    stage = report.get("stage", "")
    live.require(re.fullmatch(re.escape(PREFIX) + r"[0-9]{8}T[0-9]{6}-[a-f0-9]{6}", stage) is not None,
                 "Unexpected saved chart stage")
    return stage, report


def remote_action(client, stage, action):
    live.require(action in ("install", "finalize", "verify", "rollback"), "Unsupported chart action")
    program = "STAGE = " + repr(stage) + "\nACTION = " + repr(action) + "\n" + PROGRAM
    code, output, error = execute(client, "python3 - <<'USER_GUIDE_PUBLISH'\n" + program + "\nUSER_GUIDE_PUBLISH\n",
                                  timeout=130 if action == "install" else 90)
    (FOLDER / ("traffic-charts-" + action + ".private.log")).write_text(output + "\n" + error, encoding="utf-8")
    report_path = VERIFY_REPORT if action == "verify" else REPORT
    with client.open_sftp() as sftp:
        sftp.get(stage + ("/verify-state.json" if action == "verify" else "/update-state.json"), str(report_path))
        for name in ("commands.private.log", action + "-error.private.log", "rollback-error.private.log",
                     "rollback-preservation-error.private.log", "rollback-preservation-difference.private.json"):
            try:
                sftp.stat(stage + "/" + name)
            except OSError:
                continue
            sftp.get(stage + "/" + name, str(FOLDER / ("traffic-charts-" + name)))
    result = json.loads(report_path.read_text(encoding="utf-8"))
    live.require(code == 0, "Chart " + action + " failed; inspect its private report and log")
    return result


def deploy(manifest):
    sessions = login_sessions()
    sessions_file = FOLDER / "traffic-charts-sessions.private.json"
    sessions_file.write_text(json.dumps(sessions), encoding="utf-8")
    stage = PREFIX + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + secrets.token_hex(3)
    client = None
    candidate_installed = False
    try:
        client = connect()
        code, _, _ = execute(client, "install -d -m 0700 " + shlex.quote(stage))
        live.require(code == 0, "Could not create the private chart stage")
        with client.open_sftp() as sftp:
            for local, remote in ((ARCHIVE, "release.tar.gz"), (MANIFEST, "manifest.json"),
                                  (sessions_file, "sessions.private.json")):
                sftp.put(str(local), stage + "/" + remote)
                sftp.chmod(stage + "/" + remote, 0o600)
        result = remote_action(client, stage, "install")
        live.require(result.get("candidate_installed") and result.get("local_assets_verified"),
                     "Chart candidate did not pass its local acceptance")
        candidate_installed = True
        public_assets(manifest["source_sha256"])
        result = remote_action(client, stage, "finalize")
        live.require(result.get("success") and result.get("public_assets_verified"), "Chart final acceptance failed")
        candidate_installed = False
        for name in FILES:
            shutil.copyfile(str(RELEASE / name), str(FOLDER / "panel-release" / name))
        print(json.dumps(result))
        return result
    except BaseException:
        if candidate_installed and client is not None:
            try:
                rollback = remote_action(client, stage, "rollback")
                live.require(rollback.get("source_rollback_succeeded"), "Chart source rollback did not finish")
                public_assets(manifest["baseline_sha256"])
            except BaseException as rollback_error:
                raise RuntimeError("Chart acceptance failed and source rollback needs inspection; see private logs") from rollback_error
        raise
    finally:
        if client is not None:
            client.close()
        logout_sessions(sessions)
        if sessions_file.exists():
            sessions_file.unlink()


def verify_only():
    stage, update = stage_from_report()
    live.require(update.get("success") is True, "The latest chart release did not succeed")
    manifest = frozen_manifest()
    client = connect()
    try:
        public_assets(manifest["source_sha256"])
        report = remote_action(client, stage, "verify")
        live.require(report.get("success"), "Chart preservation failed")
        print(json.dumps(report))
    except BaseException:
        (FOLDER / "traffic-charts-verify-error.private.log").write_text(traceback.format_exc(), encoding="utf-8")
        failed = {"success": False, "phase": "failed-verification", "deployment_ip": live.IP,
                  "stage": stage, "services_restarted": False,
                  "error": "Chart public asset or preservation verification failed; inspect its private log."}
        VERIFY_REPORT.write_text(json.dumps(failed, indent=2), encoding="utf-8")
        raise
    finally:
        client.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--prepare-only", action="store_true")
    mode.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    if args.prepare_only:
        manifest = prepare()
        print(json.dumps({"prepared": True, "files": manifest["files"], "services_restarted": False,
                          "backend_and_adapters_unchanged": True, "remote_program_python_syntax": "3.6",
                          "archive_sha256": manifest["archive_sha256"], "deployment_executed": False}))
    elif args.verify_only:
        verify_only()
    else:
        deploy(frozen_manifest())
