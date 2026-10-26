"""Publish only three frontend assets; preserve all live configuration and state.

Preparation is local. Deployment requires an explicitly prepared, frozen manifest.
No service is stopped or restarted. Failed acceptance rolls back source files only.
"""

import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import secrets
import shlex
import subprocess
import tarfile
import traceback

from ssh_access import connect, execute, FOLDER
import frontend_motion_access as live

ROOT = FOLDER.parents[1]
IP = "198.200.49.63"
# Publish HTML last so a newly loaded document receives the matching assets.
FILES = ["panel/web/style.css", "panel/web/app.js", "panel/web/index.html"]
RELEASE = FOLDER / "frontend-motion-release"
ARCHIVE = FOLDER / "frontend-motion-release.tar.gz"
MANIFEST = FOLDER / "frontend-motion-release-manifest.json"
REPORT = FOLDER / "frontend-motion-update.json"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare():
    for name in FILES:
        source = ROOT / name
        live.require(source.is_file() and not source.is_symlink(), "Unexpected local source file")
        destination = RELEASE / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes())
    subprocess.run(["node", "--check", str(RELEASE / "panel/web/app.js")],
                   check=True, capture_output=True, timeout=15, creationflags=live.NO_WINDOW)
    ast.parse(PROGRAM, filename="remote_frontend_motion.py", feature_version=(3, 6))
    with tarfile.open(ARCHIVE, "w:gz") as bundle:
        for name in FILES:
            bundle.add(RELEASE / name, arcname="release/" + name, recursive=False)
    manifest = {"deployment_ip": IP, "files": FILES,
                "prepared_at": datetime.now(timezone.utc).isoformat(),
                "archive_sha256": sha(ARCHIVE),
                "source_sha256": {name: sha(RELEASE / name) for name in FILES}}
    MANIFEST.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def frozen_manifest():
    live.require(MANIFEST.is_file(), "Prepare and review the release before deployment")
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    live.require(manifest.get("deployment_ip") == IP and manifest.get("files") == FILES,
                 "Unexpected release target or file list")
    live.require(set(manifest.get("source_sha256", {})) == set(FILES), "Incomplete source manifest")
    live.require(sha(ARCHIVE) == manifest["archive_sha256"], "Frozen archive changed")
    for name in FILES:
        live.require(sha(RELEASE / name) == manifest["source_sha256"][name], "Frozen source changed")
    return manifest


PROGRAM = r'''
import hashlib, json, os, shutil, stat, subprocess, sys, tarfile, time, traceback
from pathlib import Path
from urllib.request import Request, urlopen

stage = Path(STAGE)
target = Path('/opt/vps-panel')
state_path = Path('/var/lib/vps-panel/state.private.json')
protected = [Path('/usr/local/etc/xray/config.json'), Path('/usr/local/etc/raksmart-hy2/server.yaml'),
             Path('/etc/systemd/system/xray.service'), Path('/etc/systemd/system/raksmart-hy2.service'),
             Path('/etc/systemd/system/vps-panel.service'), Path('/etc/systemd/system/caddy.service'),
             Path('/etc/caddy/Caddyfile'), Path('/var/lib/vps-panel/auth.private.json'),
             Path('/etc/resolv.conf'), Path('/var/lib/vps-panel/base.private.yaml')]
services = ['xray.service', 'raksmart-hy2.service', 'vps-panel.service', 'caddy.service']
files = ['panel/web/style.css', 'panel/web/app.js', 'panel/web/index.html']
manifest = json.loads((stage / 'manifest.json').read_text())
result = {'success': False, 'deployment_ip': '198.200.49.63', 'updated_files': files,
          'backup': str(stage / 'before'), 'services_restarted': False, 'phase': 'preflight'}
installed = []

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def write_json(path, value):
    path.write_text(json.dumps(value, indent=2))
    os.chmod(str(path), 0o600)

def record(phase):
    result['phase'] = phase
    write_json(stage / 'update-state.json', result)

def service_status():
    properties = ['ActiveState', 'SubState', 'UnitFileState', 'MainPID', 'InvocationID',
                  'ActiveEnterTimestampMonotonic', 'ExecMainStartTimestampMonotonic', 'NRestarts']
    snapshot = {}
    for service in services:
        # CentOS 7 systemd lacks newer properties and some property-filter syntax.
        # Read its supported fields, retain only this public process whitelist.
        command = ['systemctl', 'show', service]
        response = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
        require(response.returncode == 0, 'Could not inspect a protected service')
        supported = dict(line.split('=', 1) for line in response.stdout.decode().splitlines() if '=' in line)
        data = {key: supported[key] for key in properties if key in supported}
        required_fields = {'MainPID', 'ExecMainStartTimestampMonotonic', 'ActiveState', 'SubState',
                           'UnitFileState', 'ActiveEnterTimestampMonotonic'}
        require(required_fields.issubset(data), 'A protected service snapshot is incomplete')
        require(data.get('ActiveState') == 'active' and data.get('UnitFileState') == 'enabled',
                'A protected service is not active and enabled')
        require(data.get('MainPID', '').isdigit() and int(data['MainPID']) > 0 and
                data.get('ExecMainStartTimestampMonotonic') and data.get('ActiveEnterTimestampMonotonic'),
                'A protected service process identity is unavailable')
        snapshot[service] = data
    return snapshot

def snapshot():
    for path in protected + [state_path]:
        require(path.is_file() and not path.is_symlink(), 'Unexpected protected configuration file')
    return {'state_sha256': sha(state_path),
            'protected_sha256': {str(path): sha(path) for path in protected},
            'services': service_status()}

def preserved(before):
    require(snapshot() == before, 'Live state, configuration or service process changed')
    require(state_path.read_bytes() == (stage / 'before/state.private.json').read_bytes(),
            'Complete persistent state changed')

def local_sources(expected):
    paths = {'panel/web/index.html': '/', 'panel/web/app.js': '/app.js', 'panel/web/style.css': '/style.css'}
    for name in files:
        require(sha(target / name) == expected[name], 'Published source hash does not match')
        with urlopen('http://127.0.0.1:18787' + paths[name] + '?v=' + expected[name][:16], timeout=5) as response:
            require(response.status == 200, 'Published source HTTP request failed')
            require(hashlib.sha256(response.read()).hexdigest() == expected[name], 'Worker serves a different source')
            require('no-store' in response.headers.get('Cache-Control', ''), 'Worker cache policy changed')

def atomic_source(destination, content, mode, suffix):
    temporary = destination.with_name('.' + destination.name + '.' + suffix)
    try:
        with temporary.open('xb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(str(temporary), str(destination))
    finally:
        if temporary.exists():
            temporary.unlink()

def wait_idle():
    session = json.loads((stage / 'session.private.json').read_text())
    deadline = time.monotonic() + 45
    while True:
        query = Request('http://127.0.0.1:18787/api/state', headers={'Cookie': session['cookie']})
        with urlopen(query, timeout=4) as response:
            current = json.loads(response.read().decode())
        require(current.get('server_ip') == '198.200.49.63', 'Authenticated panel belongs to another VPS')
        if (current.get('job') or {}).get('status') != 'running':
            return
        require(time.monotonic() < deadline, 'Live exit operation did not finish; frontend update deferred')
        time.sleep(.5)

def rollback(names):
    source_before = json.loads((stage / 'before/source-hashes.json').read_text())
    for name in reversed(names):
        destination = target / name
        require(destination.is_file() and not destination.is_symlink(), 'Rollback target is unexpected')
        require(sha(destination) == manifest['source_sha256'][name], 'Source changed concurrently; rollback deferred')
        backup = stage / 'before' / name
        require(sha(backup) == source_before[name]['sha256'], 'Source backup hash changed')
        atomic_source(destination, backup.read_bytes(), source_before[name]['mode'], 'motion-rollback')
    local_sources({name: source_before[name]['sha256'] for name in files})

try:
    os.umask(0o077)
    require(manifest.get('deployment_ip') == '198.200.49.63' and manifest.get('files') == files,
            'Unexpected release manifest target or file list')
    require(set(manifest.get('source_sha256', {})) == set(files), 'Unexpected source manifest')
    require(sha(stage / 'release.tar.gz') == EXPECTED_ARCHIVE == manifest['archive_sha256'],
            'Uploaded archive hash mismatch')
    if RUN_MODE == 'verify':
        baseline = json.loads((stage / 'before/preservation.json').read_text())
        preserved(baseline)
        local_sources(manifest['source_sha256'])
        print(json.dumps({'success': True, 'deployment_ip': '198.200.49.63',
                          'complete_state_unchanged': True, 'protected_configuration_count': len(protected),
                          'all_protected_hashes_unchanged': True, 'four_service_processes_unchanged': True,
                          'published_sources_match': True, 'services_restarted': False}))
        sys.exit(0)
    if RUN_MODE == 'rollback':
        result = json.loads((stage / 'update-state.json').read_text())
        rollback(files)
        result.update(success=False, rolled_back=True, public_acceptance_failed=True)
        record('rolled-back')
        print(json.dumps(result))
        sys.exit(0)
    require(RUN_MODE == 'install', 'Unexpected release operation')
    record('validate-upload')
    with tarfile.open(str(stage / 'release.tar.gz'), 'r:gz') as bundle:
        members = bundle.getmembers()
        require(len(members) == len(files) and {item.name for item in members} == {'release/' + name for name in files},
                'Release archive contains unexpected paths')
        for item in members:
            require(item.isfile() and not item.issym() and not item.islnk(), 'Unexpected archive member type')
            name = item.name[len('release/'):]
            content = bundle.extractfile(item).read()
            require(hashlib.sha256(content).hexdigest() == manifest['source_sha256'][name], 'Uploaded source hash mismatch')
            destination = stage / item.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
    wait_idle()
    record('immediate-preflight-and-backup')
    baseline = snapshot()
    backup = stage / 'before'
    backup.mkdir(mode=0o700)
    (backup / 'state.private.json').write_bytes(state_path.read_bytes())
    write_json(backup / 'preservation.json', baseline)
    write_json(backup / 'protected-hashes.json', baseline['protected_sha256'])
    source_before = {}
    for name in files:
        destination = target / name
        require(destination.is_file() and not destination.is_symlink(), 'Unexpected live source file')
        source_before[name] = {'sha256': sha(destination), 'mode': stat.S_IMODE(destination.stat().st_mode)}
        saved = backup / name
        saved.parent.mkdir(parents=True, exist_ok=True)
        saved.write_bytes(destination.read_bytes())
    write_json(backup / 'source-hashes.json', source_before)
    preserved(baseline)
    record('replace-frontend-sources')
    for name in files:
        destination = target / name
        require(sha(destination) == source_before[name]['sha256'], 'Live source changed concurrently')
        atomic_source(destination, (stage / 'release' / name).read_bytes(), source_before[name]['mode'], 'motion-update')
        installed.append(name)
    record('verify-worker-and-preservation')
    local_sources(manifest['source_sha256'])
    preserved(baseline)
    result.update(success=True, complete_state_unchanged=True, all_protected_hashes_unchanged=True,
                  protected_configuration_count=len(protected), four_service_processes_unchanged=True,
                  worker_sources_match=True, source_sha256=manifest['source_sha256'])
    record('complete')
except SystemExit:
    raise
except BaseException:
    (stage / 'error.private.log').write_text(traceback.format_exc())
    if installed:
        try:
            rollback(installed)
            result['rolled_back'] = True
        except BaseException:
            (stage / 'rollback-error.private.log').write_text(traceback.format_exc())
            result.update(rolled_back=False, rollback_failed=True)
    result['success'] = False
    record('failed')
    print(json.dumps(result))
    sys.exit(1)
print(json.dumps(result))
'''


def remote_command(stage, manifest, mode):
    code = ("STAGE = " + repr(stage) + "\nEXPECTED_ARCHIVE = " + repr(manifest["archive_sha256"]) +
            "\nRUN_MODE = " + repr(mode) + "\n" + PROGRAM)
    return "python3 - <<'FRONTEND_MOTION_RELEASE'\n" + code + "\nFRONTEND_MOTION_RELEASE\n"


def public_sources(manifest):
    paths = {"panel/web/index.html": "", "panel/web/app.js": "app.js", "panel/web/style.css": "style.css"}
    for name in FILES:
        status, headers, body = live.request("GET", paths[name] + "?v=" + manifest["source_sha256"][name][:16])
        live.require(status == 200, "Trusted public source request failed")
        live.require(hashlib.sha256(body).hexdigest() == manifest["source_sha256"][name],
                     "Trusted public endpoint serves a different source")
        cache = next((value for key, value in headers.items() if key.lower() == "cache-control"), "")
        live.require("no-store" in cache, "Public source cache policy changed")


def deploy(manifest):
    session_path = FOLDER / "frontend-motion-session.private.json"
    client = None
    csrf = None
    stage = "/root/raksmart-proxy-deploy-20261009/frontend-motion-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + secrets.token_hex(3)
    try:
        login = json.loads((FOLDER / "panel-login.private.json").read_text(encoding="utf-8"))
        live.require(login.get("url") == live.ORIGIN + "/node-console/", "Unexpected login target")
        status, headers, body = live.request("POST", "api/login", {"username": login["username"], "password": login["password"]})
        live.require(status == 200, "Could not authenticate frontend release preflight")
        csrf = json.loads(body)["csrf"]
        live.cookie = headers["Set-Cookie"].split(";", 1)[0]
        session_path.write_text(json.dumps({"cookie": live.cookie}), encoding="utf-8")
        client = connect()
        code, _, _ = execute(client, "install -d -m 0700 " + shlex.quote(stage))
        live.require(code == 0, "Could not create frontend release stage")
        with client.open_sftp() as sftp:
            for local, remote in [(ARCHIVE, "release.tar.gz"), (MANIFEST, "manifest.json"), (session_path, "session.private.json")]:
                sftp.put(str(local), stage + "/" + remote)
                sftp.chmod(stage + "/" + remote, 0o600)
        session_path.unlink()
        code, output, error = execute(client, remote_command(stage, manifest, "install"), timeout=100)
        (FOLDER / "frontend-motion-update.private.log").write_text(output + "\n" + error, encoding="utf-8")
        with client.open_sftp() as sftp:
            sftp.get(stage + "/update-state.json", str(REPORT))
        live.require(code == 0, "Frontend release failed; inspect the private release log")
        result = json.loads(output)
        live.require(result.get("success"), "Frontend release did not complete")
        try:
            public_sources(manifest)
            code, output, error = execute(client, remote_command(stage, manifest, "verify"), timeout=45)
            live.require(code == 0 and json.loads(output).get("success"), "Immediate preservation acceptance failed")
        except Exception:
            with (FOLDER / "frontend-motion-update.private.log").open("a", encoding="utf-8") as log:
                traceback.print_exc(file=log)
            code, output, error = execute(client, remote_command(stage, manifest, "rollback"), timeout=45)
            with (FOLDER / "frontend-motion-update.private.log").open("a", encoding="utf-8") as log:
                log.write(output + "\n" + error)
            with client.open_sftp() as sftp:
                sftp.get(stage + "/update-state.json", str(REPORT))
            live.require(code == 0, "Public acceptance failed and frontend rollback requires attention")
            raise RuntimeError("Public acceptance failed; frontend source files were rolled back")
        result["trusted_public_sources_match"] = True
        result["accepted_at"] = datetime.now(timezone.utc).isoformat()
        REPORT.write_text(json.dumps(result, indent=2), encoding="utf-8")
        # Keep the frozen deployment source mirror current, without touching older release evidence.
        for name in FILES:
            destination = FOLDER / "panel-release" / name
            if destination.parent.is_dir():
                destination.write_bytes((RELEASE / name).read_bytes())
        print(json.dumps(result))
    finally:
        if session_path.exists():
            session_path.unlink()
        if client is not None:
            try:
                with client.open_sftp() as sftp:
                    sftp.remove(stage + "/session.private.json")
            except OSError:
                pass
            client.close()
        if live.cookie and csrf:
            try:
                live.request("POST", "api/logout", {}, {"X-CSRF-Token": csrf})
            except Exception:
                pass
        live.cookie = None


def verify_only(manifest):
    released = json.loads(REPORT.read_text(encoding="utf-8"))
    live.require(released.get("success"), "Frontend deployment has not completed")
    backup = released["backup"]
    live.require(backup.startswith("/root/raksmart-proxy-deploy-20261009/frontend-motion-") and
                 backup.endswith("/before") and ".." not in Path(backup).parts, "Unexpected preservation baseline path")
    stage = backup.rsplit("/", 1)[0]
    client = connect()
    try:
        code, output, error = execute(client, remote_command(stage, manifest, "verify"), timeout=45)
        (FOLDER / "frontend-motion-preservation.private.log").write_text(output + "\n" + error, encoding="utf-8")
        live.require(code == 0, "Frontend preservation check failed")
        result = json.loads(output)
        public_sources(manifest)
        result["trusted_public_sources_match"] = True
        result["checked_at"] = datetime.now(timezone.utc).isoformat()
        (FOLDER / "frontend-motion-preservation.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result))
    finally:
        client.close()


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--prepare-only", action="store_true")
    group.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    if args.prepare_only:
        manifest = prepare()
        print(json.dumps({"prepared": True, "deployment_ip": IP, "files": FILES,
                          "archive_sha256": manifest["archive_sha256"], "remote_python_syntax": "3.6"}))
    elif args.verify_only:
        verify_only(frozen_manifest())
    else:
        deploy(frozen_manifest())


if __name__ == "__main__":
    try:
        main()
    except Exception:
        with (FOLDER / "frontend-motion-tool-error.private.log").open("a", encoding="utf-8") as log:
            traceback.print_exc(file=log)
        print("Frontend motion release tool failed; inspect the private diagnostic log.")
        raise SystemExit(1)
