"""Freeze and publish the routing URL input update to server 63.

Only four reviewed source files are installed. Every existing account, Xray
configuration, proxy process and rule identity is preserved. The old worker is
stopped only after all enabled users' jobs are idle; only vps-panel is restarted.
Preparation performs no network access. --verify-only reads the last release.
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

from ssh_access import FOLDER, connect, execute
import frontend_motion_access as live
from multiuser_update import compatible


ROOT = FOLDER.parents[1]
FILES = ["panel/server.py", "panel/test_panel.py", "panel/web/app.js", "panel/web/index.html"]
RELEASE = FOLDER / "routing-url-release"
ARCHIVE = FOLDER / "routing-url-release.tar.gz"
MANIFEST = FOLDER / "routing-url-release-manifest.json"
REPORT = FOLDER / "routing-url-update.json"
VERIFY_REPORT = FOLDER / "routing-url-preservation.json"
PREFIX = "/root/raksmart-proxy-deploy-20261009/routing-url-"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def clean_file(path):
    return (path.is_file() and not path.is_symlink() and "__pycache__" not in path.parts
            and path.suffix != ".pyc" and ".private." not in path.name)


def prepare():
    baseline = FOLDER / "panel-release"
    live.require(baseline.is_dir() and not baseline.is_symlink(), "The deployed compatible source baseline is missing")
    names = sorted(candidate.relative_to(baseline).as_posix()
                   for candidate in baseline.rglob("*") if clean_file(candidate))
    live.require(set(FILES).issubset(names) and "configure_reality.py" in names and "panel/accounts.py" in names,
                 "Deployed multi-user baseline is incomplete")
    if RELEASE.exists():
        # Clear only this tool's exact local staging directory, never the baseline.
        live.require(RELEASE.resolve().parent == FOLDER.resolve() and RELEASE.name == "routing-url-release"
                     and not RELEASE.is_symlink(), "Unsafe local release directory")
        shutil.rmtree(RELEASE)
    RELEASE.mkdir()
    baseline_hashes = {}
    for name in names:
        candidate = baseline / name
        destination = RELEASE / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(candidate.read_bytes())
        baseline_hashes[name] = sha(candidate)
    for name in FILES:
        text = (ROOT / name).read_text(encoding="utf-8")
        if name == "panel/test_panel.py":
            original = (baseline / name).read_text(encoding="utf-8")
            marker = "class ExistingRaksmartNodeTests"
            live.require(marker in original and "class PanelTests" in original, "Existing-node adoption tests are missing")
            adoption = original.split(marker, 1)[1].split("class PanelTests", 1)[0]
            text = "import base64\n" + text.replace("class PanelTests", marker + adoption + "class PanelTests", 1)
        if name.endswith(".py"):
            text = compatible(text, name)
            ast.parse(text, filename=name, feature_version=(3, 6))
        (RELEASE / name).write_text(text, encoding="utf-8")
    for name in names:
        if name.endswith(".py"):
            ast.parse((RELEASE / name).read_text(encoding="utf-8"), filename=name, feature_version=(3, 6))
    live.require((RELEASE / "configure_reality.py").read_bytes() == (baseline / "configure_reality.py").read_bytes(),
                 "The adopted configure_reality adapter must remain identical")
    subprocess.run(["node", "--check", str(RELEASE / "panel/web/app.js")],
                   check=True, capture_output=True, timeout=15, creationflags=live.NO_WINDOW)
    ast.parse(PROGRAM, filename="routing_url_remote_update.py", feature_version=(3, 6))
    with tarfile.open(ARCHIVE, "w:gz") as bundle:
        for name in names:
            bundle.add(RELEASE / name, arcname="release/" + name, recursive=False)
    manifest = {"deployment_ip": live.IP, "files": FILES, "release_files": names,
                "prepared_at": datetime.now(timezone.utc).isoformat(), "archive_sha256": sha(ARCHIVE),
                "source_sha256": {name: sha(RELEASE / name) for name in FILES},
                "release_sha256": {name: sha(RELEASE / name) for name in names},
                "baseline_sha256": baseline_hashes, "python_syntax": "3.6",
                "configure_reality_adapter_preserved": True}
    MANIFEST.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def frozen_manifest():
    live.require(MANIFEST.is_file(), "Prepare and review the frozen release before deployment")
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    live.require(manifest.get("deployment_ip") == live.IP and manifest.get("files") == FILES,
                 "Unexpected routing update target or scope")
    live.require(sha(ARCHIVE) == manifest["archive_sha256"], "Frozen archive changed")
    for name in manifest["release_files"]:
        live.require(isinstance(name, str) and not Path(name).is_absolute() and ".." not in Path(name).parts,
                     "Invalid frozen file name")
        live.require(sha(RELEASE / name) == manifest["release_sha256"][name], "Frozen release source changed")
    live.require(set(manifest["source_sha256"]) == set(FILES), "Incomplete changed-source manifest")
    live.require(all(manifest["source_sha256"][name] == manifest["release_sha256"][name] for name in FILES),
                 "Changed-source and complete-release hashes differ")
    return manifest


PROGRAM = r'''
import hashlib, json, os, py_compile, re, stat, subprocess, sys, tarfile, time, traceback
from pathlib import Path
from urllib.request import Request, urlopen

stage = Path(STAGE)
target = Path('/opt/vps-panel')
registry = Path('/var/lib/vps-panel/users.private.json')
files = ['panel/server.py', 'panel/test_panel.py', 'panel/web/app.js', 'panel/web/index.html']
result = {'success': False, 'phase': 'preflight', 'deployment_ip': '198.200.49.63',
          'updated_files': files, 'backup': str(stage / 'before'), 'stage': str(stage),
          'only_panel_restarted': False, 'proxy_processes_preserved': False,
          'private_configuration_untouched': True}
installed = []
originals = {}
stopped = False
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

def run(args, timeout=30, cwd=None, env=None):
    response = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, cwd=cwd, env=env)
    with (stage / 'commands.private.log').open('ab') as stream:
        stream.write(response.stdout + b'\n' + response.stderr)
    require(response.returncode == 0, 'Command failed during ' + result['phase'] + ': ' + Path(args[0]).name)
    return response

def registry_records():
    require(registry.is_file() and not registry.is_symlink(), 'Private multi-user registry is unavailable')
    data = json.loads(registry.read_text())
    require(data.get('version') == 1 and isinstance(data.get('users'), list) and len(data['users']) <= 2,
            'Unsupported account registry')
    ids, ports = set(), set()
    for record in data['users']:
        require(isinstance(record, dict) and isinstance(record.get('id'), str)
                and re.fullmatch(r'[a-f0-9]{16}', record['id']) is not None
                and record['id'] not in ids and record.get('port') in [1443, 2443]
                and record['port'] not in ports and record.get('role') == 'member'
                and type(record.get('enabled')) is bool, 'Unexpected member metadata')
        ids.add(record['id'])
        ports.add(record['port'])
    return data['users']

def inventory():
    members = registry_records()
    protected = [Path('/usr/local/etc/xray/config.json'),
                 Path('/usr/local/etc/raksmart-hy2/server.yaml'),
                 Path('/etc/systemd/system/xray.service'),
                 Path('/etc/systemd/system/raksmart-hy2.service'),
                 Path('/etc/systemd/system/vps-panel.service'),
                 Path('/etc/systemd/system/caddy.service'), Path('/etc/caddy/Caddyfile'),
                 Path('/var/lib/vps-panel/auth.private.json'), Path('/etc/resolv.conf'),
                 Path('/var/lib/vps-panel/base.private.yaml'),
                 Path('/var/lib/vps-panel/state.private.json'), registry,
                 Path('/etc/systemd/system/xray-panel@.service'),
                 Path('/etc/systemd/system/vps-panel.service.d/multiuser-paths.conf'),
                 target / 'configure_reality.py', target / 'configure_static_exits.py',
                 target / 'panel/accounts.py', target / 'panel/routing.py',
                 target / 'panel/smart-routing.json', target / 'panel/services-routing.json',
                 target / 'panel/web/style.css']
    directories = [Path('/var/lib/vps-panel'), Path('/var/lib/vps-panel/users'), Path('/usr/local/etc/xray-members')]
    services = ['xray.service', 'raksmart-hy2.service', 'caddy.service']
    pairs = [(Path('/var/lib/vps-panel/state.private.json'), Path('/usr/local/etc/xray/config.json'))]
    for member in members:
        data_dir = Path('/var/lib/vps-panel/users') / member['id']
        config_dir = Path('/usr/local/etc/xray-members') / member['id']
        state_path, config_path = data_dir / 'state.private.json', config_dir / 'config.json'
        protected.extend([state_path, config_path])
        directories.extend([data_dir, config_dir])
        services.append('xray-panel@' + member['id'] + '.service')
        pairs.append((state_path, config_path))
    # Preserve any additional installed drop-in, rather than replacing or
    # assuming the first multi-user template is the complete unit definition.
    for service in services + ['vps-panel.service', 'xray-panel@.service']:
        unit_dir = Path('/etc/systemd/system') / (service + '.d')
        if unit_dir.exists():
            require(not unit_dir.is_symlink(), 'Unexpected service drop-in symlink')
            protected.extend(path for path in unit_dir.glob('*.conf') if path not in protected)
    return members, protected, directories, services, pairs

def service_snapshot(services):
    properties = ['ActiveState', 'SubState', 'UnitFileState', 'MainPID',
                  'ActiveEnterTimestampMonotonic', 'ExecMainStartTimestampMonotonic', 'NRestarts']
    snapshot = {}
    for service in services:
        response = run(['systemctl', 'show', service])
        fields = dict(line.split('=', 1) for line in response.stdout.decode().splitlines() if '=' in line)
        require(all(key in fields for key in properties[:6]), 'Protected service snapshot is incomplete')
        snapshot[service] = {key: fields[key] for key in properties if key in fields}
    return snapshot

def snapshot(check_coherence=True):
    members, protected, directories, services, pairs = inventory()
    for path in protected:
        require(path.is_file() and not path.is_symlink(), 'Unexpected protected file')
    for directory in directories:
        require(directory.is_dir() and not directory.is_symlink(), 'Unexpected protected directory')
    if check_coherence:
        for state_path, config_path in pairs:
            state = json.loads(state_path.read_text())
            require(state.get('managed_hash') == sha(config_path), 'An account state differs from its running config')
    def attributes(path):
        info = path.stat()
        return {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
    return {'protected_sha256': {str(path): sha(path) for path in protected},
            'file_attributes': {str(path): attributes(path) for path in protected},
            'directory_attributes': {str(path): attributes(path) for path in directories},
            'services': service_snapshot(services),
            'enabled_users': ['admin'] + sorted(member['id'] for member in members if member['enabled'])}

def verify_unchanged(expected):
    require(snapshot() == expected, 'Account data, configuration, permissions or proxy process changed')

def wait_idle():
    sessions = json.loads((stage / 'sessions.private.json').read_text())
    deadline = time.monotonic() + 45
    expected_users = snapshot(False)['enabled_users']
    require(sorted(sessions) == sorted(expected_users), 'Enabled account sessions are incomplete')
    while True:
        idle = True
        for user_id, token in sessions.items():
            query = Request('http://127.0.0.1:18787/api/state', headers={'Cookie': token['cookie']})
            with urlopen(query, timeout=3) as response:
                state = json.loads(response.read().decode())
            require(state.get('server_ip') == '198.200.49.63' and state.get('user', {}).get('id') == user_id,
                    'Authenticated session identifies an unexpected account')
            idle = idle and (state.get('job') or {}).get('status') != 'running'
        if idle:
            return
        require(time.monotonic() < deadline, 'A user exit operation is running; update safely deferred')
        time.sleep(.4)

def start_panel():
    run(['systemctl', 'start', 'vps-panel.service'])
    for attempt in range(40):
        try:
            with urlopen('http://127.0.0.1:18787/api/session', timeout=1) as response:
                if response.status == 200 and not json.loads(response.read().decode())['authenticated']:
                    run(['systemctl', 'is-active', '--quiet', 'vps-panel.service'])
                    run(['systemctl', 'is-enabled', '--quiet', 'vps-panel.service'])
                    return
        except OSError:
            pass
        time.sleep(.25)
    raise RuntimeError('Updated management worker did not become ready')

def safe_source(destination, payload, mode):
    require(not destination.is_symlink(), 'Unexpected source symlink')
    temporary = destination.with_name('.' + destination.name + '.routing-url-' + stage.name[-6:])
    try:
        with temporary.open('xb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(str(temporary), str(destination))
    finally:
        if temporary.exists():
            temporary.unlink()

def served_sources(expected):
    resources = {'panel/web/index.html': '/', 'panel/web/app.js': '/app.js', 'panel/web/style.css': '/style.css'}
    for name, resource in resources.items():
        with urlopen('http://127.0.0.1:18787' + resource, timeout=5) as response:
            require(response.status == 200 and hashlib.sha256(response.read()).hexdigest() == expected[name],
                    'Published browser asset differs from reviewed source')
            require('no-store' in response.headers.get('Cache-Control', ''), 'Browser asset caching policy changed')

def safe_extract(manifest):
    require(sha(stage / 'release.tar.gz') == manifest['archive_sha256'], 'Frozen archive hash mismatch')
    names = manifest['release_files']
    require(isinstance(names, list) and len(names) == len(set(names)), 'Duplicate release entries')
    for name in names:
        require(isinstance(name, str) and not name.startswith('/') and '\\' not in name
                and '..' not in Path(name).parts and not '.private.' in name, 'Unsafe release file name')
    require(set(manifest['release_sha256']) == set(names)
            and set(manifest['baseline_sha256']) == set(names) and set(files).issubset(names),
            'Incomplete release hash inventory')
    require(all(manifest['source_sha256'][name] == manifest['release_sha256'][name] for name in files),
            'Changed-source and complete-release hashes differ')
    with tarfile.open(str(stage / 'release.tar.gz'), 'r:gz') as bundle:
        entries = bundle.getmembers()
        require(len(entries) == len(names) and {entry.name for entry in entries} == {'release/' + name for name in names}
                and all(entry.isfile() for entry in entries) and sum(entry.size for entry in entries) < 20000000,
                'Unexpected archive entries')
        for entry in entries:
            destination = stage / entry.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            with bundle.extractfile(entry) as source, destination.open('xb') as output:
                output.write(source.read())
            os.chmod(str(destination), 0o600)
    for name in names:
        require(sha(stage / 'release' / name) == manifest['release_sha256'][name], 'Candidate source hash mismatch')
        require((target / name).is_file() and not (target / name).is_symlink()
                and sha(target / name) == manifest['baseline_sha256'][name], 'Deployed source baseline differs')
        if name not in files:
            require(manifest['release_sha256'][name] == manifest['baseline_sha256'][name], 'Unchanged candidate source was modified')
        if name.endswith('.py'):
            py_compile.compile(str(stage / 'release' / name), doraise=True)

try:
    os.umask(0o077)
    manifest = json.loads((stage / 'manifest.json').read_text())
    require(manifest.get('deployment_ip') == '198.200.49.63' and manifest.get('files') == files
            and set(manifest.get('source_sha256', {})) == set(files), 'Unexpected update target or scope')
    if VERIFY_ONLY:
        expected = json.loads((stage / 'before/protected-snapshot.private.json').read_text())
        verify_unchanged(expected)
        for name in files:
            require(sha(target / name) == manifest['source_sha256'][name], 'Installed source differs from reviewed release')
        served_sources(manifest['release_sha256'])
        run(['systemctl', 'is-active', '--quiet', 'vps-panel.service'])
        run(['systemctl', 'is-enabled', '--quiet', 'vps-panel.service'])
        result.update(success=True, phase='verified', proxy_processes_preserved=True,
                      all_account_data_preserved=True, published_sources_verified=True,
                      protected_file_count=len(expected['protected_sha256']),
                      protected_proxy_service_count=len(expected['services']))
        private_json(stage / 'verify-state.json', result)
    else:
        record('preflight')
        run(['systemctl', 'is-active', '--quiet', 'vps-panel.service'])
        run(['systemctl', 'is-enabled', '--quiet', 'vps-panel.service'])
        safe_extract(manifest)
        wait_idle()
        initial = snapshot()
        record('linux-candidate-tests')
        environment = os.environ.copy()
        environment['XRAY_TEST_BINARY'] = '/usr/local/bin/xray'
        run([sys.executable, '-m', 'unittest', 'test_configure_reality', 'test_configure_static_exits',
             'panel.test_panel', 'panel.test_routing', 'panel.test_accounts', 'panel.test_multiuser_http'],
            timeout=240, cwd=str(stage / 'release'), env=environment)
        verify_unchanged(initial)
        wait_idle()
        require(snapshot() == initial, 'Live state changed while the candidate was checked; safely defer update')
        backup = stage / 'before'
        backup.mkdir(mode=0o700)
        for name in files:
            source = target / name
            originals[name] = {'payload': source.read_bytes(), 'mode': stat.S_IMODE(source.stat().st_mode)}
            destination = backup / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(originals[name]['payload'])
        record('stop-panel')
        run(['systemctl', 'stop', 'vps-panel.service'])
        stopped = True
        baseline = snapshot()
        require(baseline == initial, 'An account operation raced the stop; no source was changed')
        private_json(backup / 'protected-snapshot.private.json', baseline)
        # Save all private account/configuration files for diagnosis, but rollback
        # never writes any of these bytes back to the live service directories.
        for path in baseline['protected_sha256']:
            source = Path(path)
            destination = backup / 'protected' / path.lstrip('/')
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
        record('install-reviewed-source')
        for name in files:
            destination = target / name
            require(destination.read_bytes() == originals[name]['payload'], 'Source changed concurrently')
            safe_source(destination, (stage / 'release' / name).read_bytes(), originals[name]['mode'])
            installed.append(name)
        record('start-panel')
        start_panel()
        verify_unchanged(baseline)
        for name in files:
            require(sha(target / name) == manifest['source_sha256'][name], 'Installed source hash mismatch')
        served_sources(manifest['release_sha256'])
        result.update(success=True, only_panel_restarted=True, proxy_processes_preserved=True,
                      all_account_data_preserved=True, published_sources_verified=True,
                      protected_file_count=len(baseline['protected_sha256']),
                      protected_proxy_service_count=len(baseline['services']))
        record('complete')
except BaseException:
    (stage / ('verify-error.private.log' if VERIFY_ONLY else 'error.private.log')).write_text(traceback.format_exc())
    if stopped and not VERIFY_ONLY:
        try:
            run(['systemctl', 'stop', 'vps-panel.service'])
            for name in reversed(installed):
                destination = target / name
                require(sha(destination) == manifest['source_sha256'][name], 'Concurrent source change prevents rollback')
                safe_source(destination, originals[name]['payload'], originals[name]['mode'])
            start_panel()
            if baseline is not None:
                verify_unchanged(baseline)
            result['source_rollback_succeeded'] = True
        except BaseException:
            (stage / 'rollback-error.private.log').write_text(traceback.format_exc())
            result['source_rollback_succeeded'] = False
            result['rollback_failed'] = True
    result['phase'] = 'failed'
    private_json(stage / ('verify-state.json' if VERIFY_ONLY else 'update-state.json'), result)
    print(json.dumps(result))
    sys.exit(1)
print(json.dumps(result))
'''


def login_sessions():
    """Create read-only preflight sessions for every enabled account."""
    sessions = {}
    logins = [json.loads((FOLDER / "panel-login.private.json").read_text(encoding="utf-8"))]
    try:
        def authenticate(login):
            live.require(login.get("url") == live.ORIGIN + "/node-console/", "Account login belongs to another deployment")
            status, headers, body = live.request("POST", "api/login",
                {"username": login["username"], "password": login["password"]})
            live.require(status == 200, "An enabled account could not authenticate the deployment preflight")
            payload = json.loads(body)
            user = payload["user"]
            sessions[user["id"]] = {"cookie": headers["Set-Cookie"].split(";", 1)[0], "csrf": payload["csrf"]}
            return user
        admin = authenticate(logins[0])
        live.require(admin["role"] == "admin" and admin["id"] == "admin", "Preflight needs the existing administrator")
        status, _, body = live.request("GET", "api/users", headers={"Cookie": sessions["admin"]["cookie"]})
        live.require(status == 200, "Could not read the enabled account inventory")
        users = json.loads(body)["users"]
        for user in users:
            if user["id"] == "admin" or not user["enabled"]:
                continue
            live.require(re.fullmatch(r"[a-z][a-z0-9_-]{2,23}", user["username"]) is not None,
                         "Unexpected account username")
            path = FOLDER / ("multiuser-" + user["username"] + "-login.private.json")
            live.require(path.is_file(), "Missing current private login for an enabled account; update deferred")
            login = json.loads(path.read_text(encoding="utf-8"))
            logged_in = authenticate(login)
            live.require(logged_in["id"] == user["id"], "Member preflight session identifies another account")
        return sessions
    except BaseException:
        logout_sessions(sessions)
        raise


def logout_sessions(sessions):
    for session in sessions.values():
        try:
            live.request("POST", "api/logout", {},
                         {"Cookie": session["cookie"], "X-CSRF-Token": session["csrf"]})
        except Exception:
            pass


def private_log_download(client, stage):
    with client.open_sftp() as sftp:
        for remote in ("commands.private.log", "error.private.log", "verify-error.private.log", "rollback-error.private.log"):
            try:
                sftp.stat(stage + "/" + remote)
            except OSError:
                continue
            sftp.get(stage + "/" + remote, str(FOLDER / ("routing-url-" + remote)))


def deploy(manifest):
    sessions = login_sessions()
    sessions_file = FOLDER / "routing-url-sessions.private.json"
    sessions_file.write_text(json.dumps(sessions), encoding="utf-8")
    stage = PREFIX + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + secrets.token_hex(3)
    client = None
    try:
        client = connect()
        code, _, _ = execute(client, "install -d -m 0700 " + shlex.quote(stage))
        live.require(code == 0, "Could not create a private release stage")
        with client.open_sftp() as sftp:
            for local, remote in ((ARCHIVE, "release.tar.gz"), (MANIFEST, "manifest.json"),
                                  (sessions_file, "sessions.private.json")):
                sftp.put(str(local), stage + "/" + remote)
                sftp.chmod(stage + "/" + remote, 0o600)
        program = "STAGE = " + repr(stage) + "\nVERIFY_ONLY = False\n" + PROGRAM
        code, output, error = execute(client, "python3 - <<'ROUTING_URL_UPDATE'\n" + program + "\nROUTING_URL_UPDATE\n", timeout=390)
        (FOLDER / "routing-url-update.private.log").write_text(output + "\n" + error, encoding="utf-8")
        with client.open_sftp() as sftp:
            sftp.get(stage + "/update-state.json", str(REPORT))
        private_log_download(client, stage)
        result = json.loads(REPORT.read_text(encoding="utf-8"))
        live.require(code == 0 and result.get("success"), "Routing update failed; inspect its private report and logs")
        for name in FILES:
            shutil.copyfile(str(RELEASE / name), str(FOLDER / "panel-release" / name))
        print(json.dumps(result))
        return result
    finally:
        if client is not None:
            client.close()
        logout_sessions(sessions)
        if sessions_file.exists():
            sessions_file.unlink()


def verify_only():
    result = json.loads(REPORT.read_text(encoding="utf-8"))
    live.require(result.get("success") is True, "The latest routing update did not succeed")
    stage = result.get("stage", "")
    live.require(re.fullmatch(re.escape(PREFIX) + r"[0-9]{8}T[0-9]{6}-[a-f0-9]{6}", stage) is not None,
                 "Unexpected saved routing release stage")
    client = connect()
    try:
        program = "STAGE = " + repr(stage) + "\nVERIFY_ONLY = True\n" + PROGRAM
        code, output, error = execute(client, "python3 - <<'ROUTING_URL_VERIFY'\n" + program + "\nROUTING_URL_VERIFY\n", timeout=80)
        (FOLDER / "routing-url-verify.private.log").write_text(output + "\n" + error, encoding="utf-8")
        with client.open_sftp() as sftp:
            sftp.get(stage + "/verify-state.json", str(VERIFY_REPORT))
        private_log_download(client, stage)
        report = json.loads(VERIFY_REPORT.read_text(encoding="utf-8"))
        live.require(code == 0 and report.get("success"), "Routing preservation failed; inspect the private report")
        print(json.dumps(report))
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
        print(json.dumps({"prepared": True, "files": manifest["files"], "python_syntax": "3.6",
                          "archive_sha256": manifest["archive_sha256"], "deployment_executed": False}))
    elif args.verify_only:
        verify_only()
    else:
        deploy(frozen_manifest())
