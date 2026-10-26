"""Reversible tuning of this Xray listener only; never changes the TCP default.

Creating/importing this helper has no remote effects. Explicit invocations:
  python tcp_tuning.py --algorithm westwood
  python tcp_tuning.py --algorithm hybla
  python tcp_tuning.py --restore
  python tcp_tuning.py --persist
  python tcp_tuning.py --status

Original configuration and policy are backed up once in a root-only directory.
Xray v26.3.27's exact JSON key is ``tcpCongestion`` (infra/conf/
transport_internet.go). Installed kernel modules are loaded only on a trial.
"""

import argparse
import base64
import json
from pathlib import Path

from ssh_access import FOLDER, connect, execute


REMOTE_PROGRAM = r'''
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import grp
import re
import subprocess
import tempfile
import time

CONFIG = Path('/usr/local/etc/xray/config.json')
STORE = Path('/root/raksmart-proxy-deploy-20261009/tcp-tuning')
STATE_PATH = STORE / 'state.json'
ORIGINAL_CONFIG = STORE / 'original-config.private.json'
POLICY_KEY = 'net.ipv4.tcp_allowed_congestion_control'
PERSIST_PATHS = (
    Path('/etc/modules-load.d/90-raksmart-xray-tcp.conf'),
    Path('/etc/sysctl.d/90-raksmart-xray-tcp.conf'),
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(args, timeout=20):
    result = subprocess.run(args, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        # Core diagnostics may contain configuration data. Keep them private.
        diagnostic = result.stdout + b'\n' + result.stderr
        write(STORE / 'last-command.private.log', diagnostic, 0o600)
        raise RuntimeError('Command failed: ' + Path(args[0]).name)
    return result.stdout.decode('utf-8', errors='replace').strip()


def read_policy():
    return run(['sysctl', '-n', POLICY_KEY])


def set_policy(value):
    run(['sysctl', '-q', '-w', POLICY_KEY + '=' + value])
    if read_policy() != value:
        raise RuntimeError('TCP allow policy did not match the requested value')


def snap(path):
    if path.is_symlink():
        raise RuntimeError('Refusing symbolic-link configuration: ' + str(path))
    if not path.exists():
        return {'exists': False}
    metadata = path.stat()
    data = path.read_bytes()
    return {'exists': True, 'sha256': digest(data), 'data': data,
            'mode': metadata.st_mode & 0o7777,
            'uid': metadata.st_uid, 'gid': metadata.st_gid}


def write(path, data, mode=0o640, uid=0, gid=None):
    if path.is_symlink():
        raise RuntimeError('Refusing symbolic-link configuration: ' + str(path))
    if gid is None:
        gid = 0
    descriptor, temporary = tempfile.mkstemp(prefix='.tcp-tuning-', dir=str(path.parent))
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            os.fchown(stream.fileno(), uid, gid)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, str(path))
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def put_snapshot(path, snapshot):
    if snapshot['exists']:
        write(path, snapshot['data'], snapshot['mode'], snapshot['uid'], snapshot['gid'])
    elif path.exists():
        if path.is_symlink():
            raise RuntimeError('Refusing symbolic-link configuration: ' + str(path))
        path.unlink()


def file_hash(path):
    return snap(path).get('sha256')


def save_state(state):
    write(STATE_PATH, (json.dumps(state, indent=2) + '\n').encode('utf-8'), 0o600)


def inbound(config):
    candidates = [entry for entry in config.get('inbounds', [])
                  if entry.get('protocol') == 'vless' and entry.get('port') == 443]
    if len(candidates) != 1:
        raise RuntimeError('Expected one VLESS inbound on TCP 443')
    settings = candidates[0].get('streamSettings', {})
    if settings.get('security') != 'reality' or settings.get('network', 'tcp') not in ('tcp', 'raw'):
        raise RuntimeError('The target inbound is not the expected REALITY TCP listener')
    return candidates[0]


def configured_algorithm(data):
    config = json.loads(data.decode('utf-8'))
    sockopt = inbound(config).get('streamSettings', {}).get('sockopt', {})
    for key, value in sockopt.items():
        if key.lower() == 'tcpcongestion':
            return value
    return None


def validate(data):
    descriptor, temporary = tempfile.mkstemp(prefix='.tcp-tuning-check-', suffix='.json',
                                              dir=str(CONFIG.parent))
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o640)
            os.fchown(stream.fileno(), 0, grp.getgrnam('xray').gr_gid)
            stream.write(data)
        run(['runuser', '-u', 'xray', '--', '/usr/local/bin/xray',
             'run', '-test', '-config', temporary], timeout=20)
    finally:
        os.unlink(temporary)


def healthy():
    active = subprocess.run(['systemctl', 'is-active', '--quiet', 'xray.service']).returncode == 0
    if not active:
        return False
    listeners = run(['ss', '-lntH'])
    return any(len(fields) > 3 and fields[3].endswith(':443')
               for fields in (line.split() for line in listeners.splitlines()))


def restart():
    run(['systemctl', 'restart', 'xray.service'], timeout=25)
    for attempt in range(10):
        if healthy():
            return
        time.sleep(0.5)
    raise RuntimeError('Xray did not return to active listening on TCP 443')


def check_guards(state):
    if file_hash(CONFIG) != state['active_config_sha256']:
        raise RuntimeError('Live Xray configuration changed outside this helper; refusing overwrite')
    if read_policy() != state['active_allowed_policy']:
        raise RuntimeError('TCP allow policy changed outside this helper; refusing overwrite')
    for path, expected in state.get('persisted_hashes', {}).items():
        if file_hash(Path(path)) != expected:
            raise RuntimeError('Persistence file changed outside this helper; refusing overwrite')


def initialize():
    if STATE_PATH.exists():
        state = json.loads(STATE_PATH.read_text())
        if digest(ORIGINAL_CONFIG.read_bytes()) != state['original_config_sha256']:
            raise RuntimeError('Original private backup no longer matches its recorded hash')
        return state
    if ORIGINAL_CONFIG.exists():
        raise RuntimeError('Found an original backup without its manifest; refusing to replace it')
    original = snap(CONFIG)
    if not original['exists']:
        raise RuntimeError('Xray configuration is missing')
    inbound(json.loads(original['data'].decode('utf-8')))
    policy = read_policy()
    write(ORIGINAL_CONFIG, original['data'], 0o600)
    state = {'version': 1, 'original_config_sha256': original['sha256'],
             'original_metadata': {key: original[key] for key in ('mode', 'uid', 'gid')},
             'original_allowed_policy': policy,
             'active_config_sha256': original['sha256'], 'active_allowed_policy': policy,
             'active_algorithm': configured_algorithm(original['data']),
             'persistent_originals': {}, 'persisted_hashes': {},
             'persistence_enabled': False}
    save_state(state)
    return state


def remember_persistent_original(state, path):
    key = str(path)
    if key not in state['persistent_originals']:
        previous = snap(path)
        backup = STORE / (path.parent.name + '-' + path.name + '.original')
        metadata = {name: value for name, value in previous.items() if name != 'data'}
        metadata['backup'] = str(backup)
        if previous['exists']:
            if backup.exists():
                raise RuntimeError('Found an untracked persistence backup; refusing to replace it')
            write(backup, previous['data'], 0o600)
        state['persistent_originals'][key] = metadata
        # Preserve this metadata before writing either persistent file.
        save_state(state)


def original_persistent(metadata):
    result = dict(metadata)
    if result['exists']:
        result['data'] = Path(result['backup']).read_bytes()
        if digest(result['data']) != result['sha256']:
            raise RuntimeError('A persistence-file backup hash changed')
    return result


def policy_conflicts(desired):
    paths = [Path('/etc/sysctl.conf')]
    for directory in ('/etc/sysctl.d', '/run/sysctl.d', '/usr/local/lib/sysctl.d', '/usr/lib/sysctl.d'):
        paths.extend(Path(directory).glob('*.conf'))
    for path in paths:
        if path == PERSIST_PATHS[1] or not path.exists():
            continue
        for line in path.read_text(errors='replace').splitlines():
            text = re.split(r'[#;]', line, maxsplit=1)[0].strip()
            if not text:
                continue
            match = re.match(r'^-?net[./]ipv4[./]tcp_allowed_congestion_control\s*(?:=|\s)\s*(.*?)\s*$', text)
            if match and ' '.join(match.group(1).split()) != desired:
                raise RuntimeError('Conflicting persistent TCP allow policy in ' + str(path))


def operation(request):
    if os.geteuid() != 0:
        raise RuntimeError('This helper requires the existing root SSH account')
    STORE.mkdir(mode=0o700, parents=True, exist_ok=True)
    if STORE.is_symlink():
        raise RuntimeError('Private backup directory is a symbolic link')
    os.chmod(str(STORE), 0o700)
    with (STORE / 'lock').open('a') as lock:
        os.chmod(str(STORE / 'lock'), 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        if request['mode'] == 'status':
            data = CONFIG.read_bytes()
            return {'success': True, 'mode': 'status', 'config_sha256': digest(data),
                    'algorithm': configured_algorithm(data), 'allowed_policy': read_policy(),
                    'tcp_default': run(['sysctl', '-n', 'net.ipv4.tcp_congestion_control']),
                    'xray_active_and_443_listening': healthy(),
                    'has_original_backup': STATE_PATH.exists()}
        state = initialize()
        check_guards(state)
        previous_config = snap(CONFIG)
        previous_policy = read_policy()
        expected_config_hash = previous_config['sha256']
        expected_policy = previous_policy
        touched_files = {}
        config_written = False
        policy_written = False
        previous_state = json.loads(json.dumps(state))
        try:
            if request['mode'] == 'algorithm':
                algorithm = request['algorithm']
                if algorithm not in ('cubic', 'westwood', 'hybla'):
                    raise RuntimeError('Unsupported trial algorithm')
                if algorithm not in run(['sysctl', '-n', 'net.ipv4.tcp_available_congestion_control']).split():
                    # Only a packaged kernel module; no download, kernel install, or reboot.
                    run(['modprobe', 'tcp_' + algorithm])
                after_load = read_policy()
                if after_load != previous_policy:
                    # Module registration may add the newly loaded algorithm.
                    if set(after_load.split()) - set(previous_policy.split()) != {algorithm}:
                        raise RuntimeError('TCP allow policy changed concurrently with module loading')
                    expected_policy = after_load
                    policy_written = True
                allowed = expected_policy.split()
                if algorithm not in allowed:
                    allowed.append(algorithm)
                    new_policy = ' '.join(allowed)
                    if read_policy() != expected_policy:
                        raise RuntimeError('TCP allow policy changed before the trial')
                    expected_policy = new_policy
                    policy_written = True
                    set_policy(new_policy)
                candidate = json.loads(previous_config['data'].decode('utf-8'))
                target = inbound(candidate)
                sockopt = target.setdefault('streamSettings', {}).setdefault('sockopt', {})
                # Remove a differently cased spelling to avoid duplicate JSON aliases.
                for key in list(sockopt):
                    if key.lower() == 'tcpcongestion':
                        del sockopt[key]
                sockopt['tcpCongestion'] = algorithm
                data = (json.dumps(candidate, indent=2) + '\n').encode('utf-8')
                validate(data)
                if file_hash(CONFIG) != expected_config_hash or read_policy() != expected_policy:
                    raise RuntimeError('Live state changed while validating the candidate')
                write(CONFIG, data, 0o640, 0, grp.getgrnam('xray').gr_gid)
                expected_config_hash = digest(data)
                config_written = True
                restart()
                state['active_algorithm'] = algorithm
            elif request['mode'] == 'persist':
                algorithm = state.get('active_algorithm')
                if algorithm not in ('westwood', 'hybla', 'cubic'):
                    raise RuntimeError('Run and verify an explicit algorithm trial first')
                if not healthy():
                    raise RuntimeError('Refusing persistence while Xray is unhealthy')
                policy_conflicts(expected_policy)
                contents = (
                    ('# Managed by the RAKsmart Xray TCP trial helper\ntcp_' + algorithm + '\n').encode(),
                    ('# Allow the tested algorithm for the unprivileged Xray listener\n' +
                     POLICY_KEY + ' = ' + expected_policy + '\n').encode(),
                )
                for path, data in zip(PERSIST_PATHS, contents):
                    path.parent.mkdir(mode=0o755, exist_ok=True)
                    remember_persistent_original(state, path)
                    previous = snap(path)
                    # Avoid replacing an unrelated file's substantive settings.
                    if previous['exists'] and not state.get('persistence_enabled', False):
                        lines = [line.strip() for line in previous['data'].decode('utf-8', errors='replace').splitlines()
                                 if line.strip() and not line.lstrip().startswith('#')]
                        acceptable = (all(line == 'tcp_' + algorithm for line in lines) if path == PERSIST_PATHS[0]
                                      else all(re.sub(r'\s+', '', line) ==
                                               re.sub(r'\s+', '', POLICY_KEY + '=' + expected_policy) for line in lines))
                        if not acceptable:
                            raise RuntimeError('Dedicated persistence path contains unrelated settings: ' + str(path))
                    write(path, data, 0o644)
                    touched_files[str(path)] = {'snapshot': previous, 'expected': digest(data)}
                    state['persisted_hashes'][str(path)] = digest(data)
                state['persistence_enabled'] = True
            elif request['mode'] == 'restore':
                data = ORIGINAL_CONFIG.read_bytes()
                validate(data)
                # Check all concurrency guards before restoring any files or policy.
                check_guards(state)
                for filename, metadata in state['persistent_originals'].items():
                    path = Path(filename)
                    original = original_persistent(metadata)
                    previous = snap(path)
                    put_snapshot(path, original)
                    touched_files[filename] = {'snapshot': previous, 'expected': original.get('sha256')}
                    state['persisted_hashes'][filename] = original.get('sha256')
                if expected_policy != state['original_allowed_policy']:
                    expected_policy = state['original_allowed_policy']
                    policy_written = True
                    set_policy(expected_policy)
                if file_hash(CONFIG) != expected_config_hash:
                    raise RuntimeError('Live Xray config changed before restoration')
                metadata = state['original_metadata']
                write(CONFIG, data, metadata['mode'], metadata['uid'], metadata['gid'])
                expected_config_hash = digest(data)
                config_written = True
                restart()
                state['active_algorithm'] = configured_algorithm(data)
                state['persistence_enabled'] = False
            else:
                raise RuntimeError('Unknown operation')
            state['active_config_sha256'] = expected_config_hash
            state['active_allowed_policy'] = expected_policy
            save_state(state)
            return {'success': True, 'mode': request['mode'], 'algorithm': state['active_algorithm'],
                    'config_sha256': expected_config_hash, 'allowed_policy': expected_policy,
                    'tcp_default': run(['sysctl', '-n', 'net.ipv4.tcp_congestion_control']),
                    'xray_active_and_443_listening': healthy(),
                    'persistent': state.get('persistence_enabled', False),
                    'original_restored': request['mode'] == 'restore'}
        except Exception as error:
            rollback_errors = []
            # Restore only values written by this operation. Outside changes win.
            for filename, transaction in touched_files.items():
                try:
                    path = Path(filename)
                    if file_hash(path) != transaction['expected']:
                        raise RuntimeError('Persistence file changed during rollback')
                    put_snapshot(path, transaction['snapshot'])
                except Exception as rollback_error:
                    rollback_errors.append(str(rollback_error))
            if config_written:
                try:
                    if file_hash(CONFIG) != expected_config_hash:
                        raise RuntimeError('Live Xray config changed during rollback')
                    put_snapshot(CONFIG, previous_config)
                except Exception as rollback_error:
                    rollback_errors.append(str(rollback_error))
            if policy_written:
                try:
                    if read_policy() != expected_policy:
                        raise RuntimeError('TCP allow policy changed during rollback')
                    set_policy(previous_policy)
                except Exception as rollback_error:
                    rollback_errors.append(str(rollback_error))
            if config_written and not rollback_errors:
                try:
                    restart()
                except Exception as rollback_error:
                    rollback_errors.append(str(rollback_error))
            if not rollback_errors:
                # Keep once-only file backups even when persistence was aborted.
                # Guard their restored/original paths on later invocations too.
                for filename, metadata in state['persistent_originals'].items():
                    if filename not in previous_state['persistent_originals']:
                        previous_state['persistent_originals'][filename] = metadata
                        previous_state['persisted_hashes'][filename] = metadata.get('sha256')
                save_state(previous_state)
            return {'success': False, 'mode': request['mode'], 'error': str(error),
                    'rollback_complete': not rollback_errors, 'rollback_errors': rollback_errors}


try:
    result = operation(REQUEST)
except Exception as error:
    result = {'success': False, 'error': str(error)}
print(json.dumps(result, sort_keys=True))
raise SystemExit(0 if result['success'] else 1)
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--algorithm', choices=('cubic', 'westwood', 'hybla'))
    modes.add_argument('--restore', action='store_true')
    modes.add_argument('--persist', action='store_true')
    modes.add_argument('--status', action='store_true')
    args = parser.parse_args()
    mode = ('algorithm' if args.algorithm else 'restore' if args.restore
            else 'persist' if args.persist else 'status')
    request = {'mode': mode, 'algorithm': args.algorithm}
    encoded = base64.b64encode(json.dumps(request).encode('utf-8')).decode('ascii')
    program = ('import base64, json\nREQUEST = json.loads(base64.b64decode(' +
               repr(encoded) + '))\n' + REMOTE_PROGRAM)
    command = "python3 - <<'RAKSMART_TCP_TUNING_PY'\n" + program + '\nRAKSMART_TCP_TUNING_PY\n'
    client = connect()
    try:
        code, output, error = execute(client, command, timeout=90)
        try:
            result = json.loads(output.strip())
        except ValueError:
            # Transport/interpreter diagnostics remain in the private folder.
            (FOLDER / 'tcp-tuning-transport.private.log').write_text(output + '\n' + error, encoding='utf-8')
            result = {'success': False, 'error': 'No structured result; inspect the private transport log'}
        result['remote_exit_code'] = code
        (FOLDER / 'tcp-tuning-last-result.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(result, indent=2))
        if code or not result.get('success'):
            raise SystemExit(1)
    finally:
        client.close()


if __name__ == '__main__':
    main()
