"""Explicit, root-only UDP buffer maintenance for the adopted HY2 host.

Python 3.6 compatible; no action runs on import. snapshot is read only.
apply/rollback change only two sysctls, their dedicated persistent file and
the lifecycle of the original panel/HY2 services. Proxy identities and files
are verified by hashes. The live traffic ledger is never copied or restored.
Final sampling follows the panel lifecycle contract: business counters are
sampled immediately before restart. A tiny sample-to-stop interval remains;
there is no atomic sample-and-stop API and no firewall isolation is added.
"""
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading
import time
from urllib.request import ProxyHandler, Request, build_opener


PORTS = (443, 1443, 2443)
PANEL = 'vps-panel.service'
CONF = Path('/etc/sysctl.d/90-vps-hy2-udp-buffers.conf')
TARGET = 7340032
KEYS = ('net.core.rmem_max', 'net.core.wmem_max')
LOCK = Path('/run/lock/vps-hy2-udp-buffers.lock')
FORMAT = 'vps-hy2-udp-buffers-v1'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(args, check=True, timeout=25):
    environment = os.environ.copy()
    environment['LC_ALL'] = 'C'
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, env=environment)
    require(not check or result.returncode == 0, 'Host command failed')
    return result


def output(args, check=True):
    return run(args, check).stdout.decode('utf-8', 'replace')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def digest_json(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
        separators=(',', ':')).encode('utf-8')).hexdigest()


def attributes(path):
    item = path.stat()
    return {'mode': stat.S_IMODE(item.st_mode), 'uid': item.st_uid,
            'gid': item.st_gid, 'atime_ns': item.st_atime_ns,
            'mtime_ns': item.st_mtime_ns}


def safe_file(path):
    path = Path(path)
    require(path.is_absolute() and path.is_file() and not path.is_symlink(),
            'Expected regular host file is unavailable: ' + str(path))
    return path


def atomic(path, data, info=None):
    path = Path(path)
    require(not path.is_symlink() and path.parent.is_dir()
            and not path.parent.is_symlink(), 'Unsafe maintenance destination')
    temporary = path.with_name('.' + path.name + '.udp-maintenance-' + str(os.getpid()))
    fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            if info:
                os.fchown(stream.fileno(), info['uid'], info['gid'])
                os.fchmod(stream.fileno(), info['mode'])
        if info and 'mtime_ns' in info:
            os.utime(str(temporary), ns=(info['atime_ns'], info['mtime_ns']))
        os.replace(str(temporary), str(path))
        directory_fd = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary.exists():
            temporary.unlink()


def private_json(path, value):
    atomic(path, (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8'))


def service(name):
    text = output(['systemctl', 'show', name, '--property=ActiveState',
        '--property=SubState', '--property=UnitFileState', '--property=MainPID',
        '--property=ExecMainStartTimestampMonotonic'])
    result = dict(line.split('=', 1) for line in text.splitlines() if '=' in line)
    require(all(key in result for key in ('ActiveState', 'MainPID',
            'ExecMainStartTimestampMonotonic', 'UnitFileState')), 'Incomplete service identity')
    return result


def active(value):
    return value['ActiveState'] == 'active'


def epoch(value):
    return '\n'.join(key + '=' + value[key] for key in
                     ('MainPID', 'ExecMainStartTimestampMonotonic'))


def sysctls():
    return {key: int(output(['sysctl', '-n', key]).strip()) for key in KEYS}


def set_sysctls(values, journal=None, backup=None):
    require(set(values) == set(KEYS) and all(type(values[key]) is int
            and values[key] > 0 for key in KEYS), 'Invalid saved UDP buffer values')
    for key in KEYS:
        if journal is not None:
            journal['runtime_writes'].append(key)
            private_json(backup / 'rollback.private.json', journal)
        run(['sysctl', '-w', key + '=' + str(values[key])])
    require(sysctls() == values, 'UDP buffer values did not apply')


def launch_context(package_root):
    status = service(PANEL)
    require(active(status) and int(status['MainPID']) > 0,
            'The panel must be running before maintenance preparation')
    argv = Path('/proc/' + status['MainPID'] + '/cmdline').read_bytes().decode('utf-8').split('\0')
    scripts = [Path(value) for value in argv if value.endswith('/panel/server.py')]
    require(len(scripts) == 1, 'Unexpected panel launch script')
    actual = scripts[0].parent.parent
    require(actual.is_absolute() and actual.resolve() == package_root.resolve()
            and not package_root.is_symlink(), 'Package root differs from the running panel')
    def argument(name, default=None):
        require(argv.count(name) <= 1, 'Repeated panel launch option')
        if name in argv:
            index = argv.index(name)
            require(index + 1 < len(argv) and argv[index + 1], 'Incomplete panel launch option')
            return argv[index + 1]
        require(default is not None, 'Required panel launch option is absent')
        return default
    context = {'package_root': str(actual),
        'directory': argument('--directory', '/var/lib/vps-panel'),
        'config': argument('--config', '/usr/local/etc/xray/config.json'),
        'public_ip': argument('--public-ip'), 'origin': argument('--origin'),
        'base_path': argument('--base-path', '/node-console/'),
        'port': int(argument('--port', '18787'))}
    require(context['public_ip'] == '198.200.49.63'
            and context['directory'] == '/var/lib/vps-panel'
            and context['config'] == '/usr/local/etc/xray/config.json'
            and context['base_path'] == '/node-console/' and context['port'] == 18787,
            'Unexpected adopted host paths or private listener')
    return context


def inventory(context):
    directory = Path(context['directory'])
    registry = json.loads(safe_file(directory / 'users.private.json').read_text())
    require(registry.get('version') == 1 and isinstance(registry.get('users'), list)
            and len(registry['users']) <= 2, 'Invalid account registry')
    result = [{'id': 'admin', 'port': 443, 'enabled': True,
        'state': str(directory / 'state.private.json'), 'config': context['config'],
        'xray': 'xray.service', 'hy2': 'raksmart-hy2@443.service'}]
    identities, ports = set(), set()
    for record in registry['users']:
        identity, port = record.get('id'), record.get('port')
        require(isinstance(identity, str) and re.fullmatch(r'[a-f0-9]{16}', identity)
            and identity not in identities and type(port) is int and port in (1443, 2443)
            and port not in ports and type(record.get('enabled')) is bool, 'Invalid member identity')
        identities.add(identity)
        ports.add(port)
        result.append({'id': identity, 'port': port, 'enabled': record['enabled'],
            'state': str(directory / 'users' / identity / 'state.private.json'),
            'config': '/usr/local/etc/xray-members/' + identity + '/config.json',
            'xray': 'xray-panel@' + identity + '.service',
            'hy2': 'raksmart-hy2@' + str(port) + '.service'})
    return result


def identity(context):
    directory = Path(context['directory'])
    records = inventory(context)
    paths = {directory / name for name in ('auth.private.json', 'users.private.json',
        'hy2.private.json', 'base.private.yaml', 'hy2-server.crt.pem', 'hy2-server.key.pem')}
    paths.update(Path(name) for name in ('/usr/local/bin/raksmart-hysteria2',
        '/etc/systemd/system/raksmart-hy2@.service', '/etc/systemd/system/vps-panel.service',
        '/etc/systemd/system/xray.service', '/etc/systemd/system/xray-panel@.service'))
    paths.update(Path(context['package_root']) / name for name in
                 ('panel/server.py', 'panel/accounts.py', 'panel/hy2.py', 'panel/telemetry.py'))
    applied = {}
    for record in records:
        state_path = safe_file(record['state'])
        config_path = safe_file(record['config'])
        state_data = json.loads(state_path.read_text())
        require(state_data.get('managed_hash') == sha(config_path)
                and state_data['base']['inbounds'][0]['port'] == record['port'],
                'Account state differs from its running configuration')
        paths.update((state_path, config_path,
                      Path('/usr/local/etc/raksmart-hy2/accounts/' + str(record['port']) + '.yaml')))
        # The applied client profile is YAML text inside the private state,
        # already covered by the state file hash and applied digest below.
        require(isinstance(state_data.get('profile', ''), str), 'Invalid applied profile text')
        applied[str(record['port'])] = digest_json({key: value for key, value in state_data.items()
            if key.startswith('applied_') or key in ('active_id', 'profile', 'profile_hash', 'profile_version')})
    for name in (PANEL, 'raksmart-hy2@.service', 'xray.service', 'xray-panel@.service'):
        dropins = Path('/etc/systemd/system') / (name + '.d')
        if dropins.exists():
            require(dropins.is_dir() and not dropins.is_symlink(), 'Unsafe service drop-in directory')
            paths.update(dropins.glob('*.conf'))
    files = {}
    for path in sorted(paths, key=str):
        safe_file(path)
        info = attributes(path)
        files[str(path)] = {'sha256': sha(path), **{key: info[key] for key in ('mode', 'uid', 'gid')}}
    services = {name: service(name) for name in [PANEL, 'caddy.service', 'raksmart-hy2.service']
                + [record['xray'] for record in records]
                + ['raksmart-hy2@' + str(port) + '.service' for port in PORTS]}
    require(not active(services['raksmart-hy2.service']), 'Legacy HY2 ingress must stay retired')
    return {'records': records, 'files': files, 'applied_hashes': applied, 'services': services}


def ledger(context):
    from panel.telemetry import validate_store
    data = json.loads(safe_file(Path(context['directory']) / 'traffic.private.json').read_text())
    validate_store(data)
    return {identity: {'limits': {key: item[key] for key in ('quota_bytes', 'rate_bps')},
        'months': item['months']} for identity, item in data['users'].items()}


def check_ledger(before, after):
    require(set(before) == set(after), 'Traffic account identities changed')
    for identity, item in before.items():
        require(item['limits'] == after[identity]['limits'], 'Traffic limits changed')
        for month, totals in item['months'].items():
            require(month in after[identity]['months'] and all(
                after[identity]['months'][month][key] >= totals[key]
                for key in ('up_bytes', 'down_bytes')), 'Monthly traffic total moved backwards')


def import_package(context):
    package = Path(context['package_root'])
    sys.path.insert(0, str(package))
    sys.path.insert(0, str(package / 'vendor'))


def traffic_context(context):
    from panel import server
    from panel.accounts import Accounts
    from panel.hy2 import Integration
    from panel.telemetry import Telemetry
    require(not active(service(PANEL)), 'Panel traffic writer is still running')
    # Manager.__init__ can migrate state and chmod the data directory. This
    # maintenance-only owner needs the already validated applied state, not a
    # new manager's initialization or any draft application.
    manager = object.__new__(server.Manager)
    manager.directory = Path(context['directory'])
    manager.state_path = manager.directory / 'state.private.json'
    manager.state = json.loads(safe_file(manager.state_path).read_text())
    manager.config_path = Path(context['config'])
    manager.public_ip = context['public_ip']
    manager.origin = context['origin']
    manager.base_path = context['base_path']
    manager.demo = False
    manager.lock = threading.RLock()
    manager.operation = threading.Lock()
    accounts = Accounts(manager, Path(context['directory']) / 'auth.private.json')
    integration = Integration(accounts)
    accounts.acceleration = integration
    require(integration.enabled, 'Adopted HY2 integration is unavailable')
    traffic = Telemetry(accounts, hy2=integration)
    accounts.telemetry = traffic
    return accounts, integration, traffic


def sample(traffic, identity):
    record = traffic.accounts._record(identity)
    before_epoch = epoch(service(traffic.hy2.service(record)))
    result = traffic.sample_user(identity)
    require(result.get('sources', {}).get('hy2', {}).get('available') is True,
            'HY2 final traffic sample is unavailable')
    require(result.get('sources', {}).get('xray', {}).get('available') is True,
            'Xray traffic sample is unavailable')
    source = traffic.data['users'][identity]['sources']['hy2']
    after_epoch = epoch(service(traffic.hy2.service(record)))
    fields = dict(line.split('=', 1) for line in source['epoch'].splitlines() if '=' in line)
    normalized_epoch = '\n'.join(key + '=' + fields.get(key, '') for key in
                                ('MainPID', 'ExecMainStartTimestampMonotonic'))
    require(before_epoch == after_epoch and normalized_epoch == after_epoch,
            'HY2 changed epoch during final sampling')
    return {'epoch': source['epoch'], 'counters': dict(source['counters']),
            'total_bytes': result['total_bytes'], 'sample_completed_at_unix': time.time()}


def prepare_restart(accounts, integration, traffic, record):
    actual = accounts._record(record['id'])
    previous, unused_online, previous_epoch = integration.query(actual)
    time.sleep(1)
    current, unused_online, current_epoch = integration.query(actual)
    require(current_epoch == previous_epoch, 'HY2 instance restarted during preparation')
    final = sample(traffic, record['id'])
    require(final['epoch'] == current_epoch, 'HY2 changed epoch before restart')
    final['business_counters_stable_before_restart'] = previous == current == final['counters']
    final['tail_accounting_limitation'] = (
        'Final counters are persisted before restart; business bytes produced in the sample-to-stop interval may be unrecorded.')
    return final


def wait_hy2(integration, actual):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        try:
            if active(service(integration.service(actual))):
                integration.query(actual)
                return
        except Exception:
            pass
        time.sleep(.2)
    raise RuntimeError('HY2 private statistics did not become ready')


def wait_panel(context):
    deadline = time.monotonic() + 12
    # Caddy removes /node-console before forwarding to this private backend.
    # /api/session intentionally returns 200 without authentication.
    url = 'http://127.0.0.1:' + str(context['port']) + '/api/session'
    while time.monotonic() < deadline:
        try:
            if active(service(PANEL)):
                with build_opener(ProxyHandler({})).open(url, timeout=1) as response:
                    payload = json.loads(response.read().decode('utf-8'))
                    if response.status == 200 and isinstance(payload, dict) and 'authenticated' in payload:
                        return
        except Exception:
            pass
        time.sleep(.2)
    raise RuntimeError('The original panel did not become ready')


def sockets():
    lines = output(['ss', '-H', '-u', '-a', '-n', '-m', '-p']).splitlines()
    result, current = {}, None
    for line in lines:
        fields = line.split()
        if fields and fields[0] == 'udp':
            fields = fields[1:]
        if fields and not line.lstrip().startswith('skmem:'):
            current = None
            if len(fields) >= 5:
                match = re.search(r':(443|1443|2443)$', fields[3])
                if match:
                    current = match.group(1)
                    require(current not in result, 'Duplicate public HY2 socket')
                    pids = [int(value) for value in re.findall(r'pid=(\d+)', line)]
                    main_pid = int(service('raksmart-hy2@' + current + '.service')['MainPID'])
                    require(pids and main_pid > 0 and set(pids) == {main_pid}
                            and Path('/proc/' + str(main_pid) + '/exe').resolve()
                            == Path('/usr/local/bin/raksmart-hysteria2'),
                            'Public UDP socket does not belong to the official HY2 instance')
                    result[current] = {'recv_queue': int(fields[1]), 'send_queue': int(fields[2]),
                                       'service_main_pid': main_pid}
        if current and 'skmem:(' in line:
            block = re.search(r'skmem:\(([^)]*)\)', line).group(1)
            values = {}
            for token in block.split(','):
                match = re.fullmatch(r'([a-z]+)([0-9]+)', token.strip())
                if match:
                    values[match.group(1)] = int(match.group(2))
            result[current].update({'rb': values.get('rb'), 'tb': values.get('tb'),
                'drops': values.get('d'), 'memory': values})
    return result


def check_sockets(before, after, port):
    key = str(port)
    require(key in before and key in after, 'Expected HY2 UDP socket is absent')
    for name in ('rb', 'tb'):
        old, new = before[key].get(name), after[key].get(name)
        require(type(old) is int and type(new) is int and new > 0,
                'Actual HY2 socket buffer is unavailable')
        if old < TARGET:
            require(new > old, 'Actual HY2 socket buffer did not increase')


def udp_counters():
    lines = Path('/proc/net/snmp').read_text().splitlines()
    for index, line in enumerate(lines[:-1]):
        if line.startswith('Udp:') and lines[index + 1].startswith('Udp:'):
            return dict(zip(line.split()[1:], [int(value) for value in lines[index + 1].split()[1:]]))
    raise RuntimeError('UDP counters are unavailable')


def cpu_sample():
    def read():
        return [int(value) for value in Path('/proc/stat').read_text().splitlines()[0].split()[1:9]]
    first = read()
    time.sleep(1)
    delta = [new - old for old, new in zip(first, read())]
    total = sum(delta)
    return {key: round(value * 100.0 / total, 2) if total else 0.0
            for key, value in (('busy', total - delta[3] - delta[4]),
                               ('iowait', delta[4]), ('steal', delta[7]))}


def qdisc_snapshot():
    plain = output(['tc', 'qdisc', 'show'])
    # Reference counts can change independently of network semantics.
    normalized = re.sub(r'\s+refcnt\s+\d+', '', plain)
    return {'semantic_sha256': hashlib.sha256(normalized.encode('utf-8')).hexdigest(),
            'description': plain.strip(), 'statistics': output(['tc', '-s', 'qdisc', 'show']).strip()}


def runtime_snapshot(context):
    memory = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        name, value = line.split(':', 1)
        if name in ('MemTotal', 'MemAvailable', 'MemFree', 'SwapTotal', 'SwapFree'):
            memory[name] = value.strip()
    records = inventory(context)
    names = [PANEL, 'caddy.service', 'raksmart-hy2.service'] + [r['xray'] for r in records]
    names += ['raksmart-hy2@' + str(port) + '.service' for port in PORTS]
    return {'sysctls': sysctls(), 'hy2_udp_sockets': sockets(),
        'udp_cumulative_counters': udp_counters(), 'cpu_one_second_percent': cpu_sample(),
        'cpu_count': os.cpu_count(), 'load_averages': list(os.getloadavg()),
        'memory': memory, 'qdisc': qdisc_snapshot(),
        'services': {name: service(name) for name in names},
        'scope': 'UDP counters and socket drops are cumulative; one-second CPU is an idle sample.'}


def compare_identity(before, after, panel_running, recoverable=None):
    require(before['records'] == after['records'] and before['files'] == after['files']
            and before['applied_hashes'] == after['applied_hashes'],
            'An account identity, profile or protected file changed')
    for name, old in before['services'].items():
        new = after['services'][name]
        require(old['UnitFileState'] == new['UnitFileState'], 'Service enablement changed')
        if name == PANEL:
            require(active(new) == panel_running, 'Unexpected panel lifecycle state')
        elif name.startswith('raksmart-hy2@'):
            if name not in (recoverable or []):
                require(active(old) == active(new), 'HY2 account lifecycle state changed')
        else:
            require(old == new, 'A protected service or Xray epoch changed')


def config_backup():
    require(CONF.parent.is_dir() and not CONF.parent.is_symlink()
            and not CONF.is_symlink(), 'Unsafe dedicated sysctl file')
    if CONF.exists():
        safe_file(CONF)
        info = attributes(CONF)
        data = CONF.read_bytes()
        return {'existed': True, 'attributes': info,
                'data': base64.b64encode(data).decode('ascii'),
                'sha256': hashlib.sha256(data).hexdigest()}
    return {'existed': False}


def check_original_config(saved):
    current = config_backup()
    require(current['existed'] == saved['existed'], 'Dedicated sysctl file changed concurrently')
    if saved['existed']:
        require(current['sha256'] == saved['sha256'] and all(
            current['attributes'][key] == saved['attributes'][key]
            for key in ('mode', 'uid', 'gid', 'mtime_ns')),
            'Dedicated sysctl file changed concurrently')


def restore_config(saved):
    require(not CONF.is_symlink(), 'The dedicated sysctl file became linked')
    if saved['existed']:
        data = base64.b64decode(saved['data'], validate=True)
        require(hashlib.sha256(data).hexdigest() == saved['sha256'], 'Private sysctl backup differs')
        atomic(CONF, data, saved['attributes'])
    elif CONF.exists():
        safe_file(CONF)
        CONF.unlink()


def backup_directory(value, create):
    path = Path(value)
    require(path.is_absolute() and path.parent == Path('/root')
            and path.name.startswith('vps-udp-buffer-optimization-') and not path.is_symlink(),
            'Backup directory must be a dedicated absolute root directory')
    if create:
        require(not path.exists(), 'Private rollback directory already exists')
        path.mkdir(mode=0o700)
    require(path.is_dir() and path.stat().st_uid == 0
            and stat.S_IMODE(path.stat().st_mode) == 0o700, 'Private rollback directory permissions differ')
    return path


def restart_one(accounts, integration, traffic, record, journal, backup, rollback=False):
    final = prepare_restart(accounts, integration, traffic, record)
    actual = accounts._record(record['id'])
    name = record['hy2']
    require(active(service(name)), 'Originally active HY2 instance stopped unexpectedly')
    if not rollback and name not in journal['attempted']:
        journal['attempted'].append(name)
        private_json(backup / 'rollback.private.json', journal)
    sampled_at = final['sample_completed_at_unix']
    restart_at = time.time()
    run(['systemctl', 'restart', name])
    wait_hy2(integration, actual)
    after = sample(traffic, record['id'])
    require(after['epoch'] != final['epoch'] and after['total_bytes'] >= final['total_bytes'],
            'HY2 restart epoch or cumulative accounting did not synchronize')
    return {'port': record['port'], 'final_sample_persisted': True,
            'epoch_changed': True, 'total_bytes_non_decreasing': True,
            'business_counters_stable_before_restart': final['business_counters_stable_before_restart'],
            'tail_accounting_limitation': final['tail_accounting_limitation'],
            'final_sample_completed_at_unix': sampled_at,
            'restart_requested_at_unix': restart_at,
            'sample_to_restart_request_ms': round((restart_at - sampled_at) * 1000, 3)}


def recover(journal, backup, traffic_objects=None):
    context = journal['context']
    baseline = journal['identity']
    if active(service(PANEL)):
        run(['systemctl', 'stop', PANEL])
    infrastructure_failures = []
    try:
        if journal.get('persistent_write_started'):
            current, saved = config_backup(), journal['sysctl_file']
            original = current['existed'] == saved['existed'] and (not saved['existed']
                or current['sha256'] == saved['sha256'])
            written = current['existed'] and current['sha256'] == journal['written_sysctl_sha256']
            require(original or written,
                    'Dedicated sysctl file has unrelated changes; restoration deferred')
            restore_config(saved)
    except Exception:
        infrastructure_failures.append('Persistent sysctl file restoration failed')
    try:
        current = sysctls()
        for key in journal.get('runtime_writes', []):
            require(current[key] in (journal['sysctls'][key], TARGET),
                    'Runtime sysctl changed concurrently; restoration deferred')
            run(['sysctl', '-w', key + '=' + str(journal['sysctls'][key])])
        require(sysctls() == journal['sysctls'], 'Runtime sysctl values did not recover')
    except Exception:
        infrastructure_failures.append('Runtime sysctl restoration failed')
    failures, restarted = [], []
    try:
        accounts, integration, traffic = traffic_objects or traffic_context(context)
        # The panel might have persisted newer samples before a later failure.
        # Discard our old in-memory baselines before any more ledger writes.
        traffic.reload()
        for record in baseline['records']:
            name = record['hy2']
            original = baseline['services'][name]
            try:
                if active(original) and name in journal['attempted']:
                    if not active(service(name)):
                        # No native counters remain after a failed start. Keep
                        # the written final sample, start, then sync new epoch.
                        run(['systemctl', 'start', name])
                        wait_hy2(integration, accounts._record(record['id']))
                        sample(traffic, record['id'])
                        restarted.append({'port': record['port'], 'recovered_failed_start': True})
                    else:
                        try:
                            integration.query(accounts._record(record['id']))
                        except Exception:
                            # A failed startup can look active while its API is
                            # unavailable. Final pre-restart sample is already
                            # persisted; do not restore an old traffic ledger.
                            run(['systemctl', 'restart', name])
                            wait_hy2(integration, accounts._record(record['id']))
                            sample(traffic, record['id'])
                            restarted.append({'port': record['port'],
                                'recovered_unavailable_api': True,
                                'unavailable_process_tail_accounting': 'unknown'})
                            continue
                        restarted.append(restart_one(accounts, integration, traffic,
                            record, journal, backup, rollback=True))
                elif not active(original) and active(service(name)):
                    run(['systemctl', 'stop', name])
            except Exception:
                failures.append({'port': record['port'], 'error': 'HY2 rollback lifecycle did not complete'})
    except Exception:
        infrastructure_failures.append('Traffic sampling context recovery failed')
    finally:
        if active(baseline['services'][PANEL]):
            run(['systemctl', 'start', PANEL])
            wait_panel(context)
    check_ledger(journal['ledger'], ledger(context))
    compare_identity(baseline, identity(context), active(baseline['services'][PANEL]))
    require(qdisc_snapshot()['semantic_sha256'] == journal['qdisc_sha256'],
            'Network queue semantics changed during maintenance')
    journal['rolled_back'] = not failures and not infrastructure_failures
    private_json(backup / 'rollback.private.json', journal)
    return {'success': journal['rolled_back'],
            'sysctls_restored': 'Runtime sysctl restoration failed' not in infrastructure_failures,
            'persistent_file_restored': 'Persistent sysctl file restoration failed' not in infrastructure_failures,
            'traffic_ledger_restored': False, 'ledger_totals_non_decreasing': True,
            'restarted': restarted, 'failures': failures,
            'infrastructure_failures': infrastructure_failures}


def apply(context, backup):
    import_package(context)
    baseline = identity(context)
    require(active(baseline['services'][PANEL]), 'Original panel is not active')
    for record in baseline['records']:
        require(active(baseline['services'][record['hy2']]) == record['enabled']
                and active(baseline['services'][record['xray']]) == record['enabled'],
                'Account service state differs from enablement')
    journal = {'format': FORMAT, 'context': context, 'identity': baseline,
        'sysctls': sysctls(), 'sysctl_file': config_backup(), 'ledger': ledger(context),
        'qdisc_sha256': qdisc_snapshot()['semantic_sha256'],
        'attempted': [], 'rolled_back': False, 'persistent_write_started': False,
        'runtime_writes': []}
    require(all(0 < value <= TARGET for value in journal['sysctls'].values()),
            'Current UDP buffer ceiling exceeds the requested target; refusing to lower it')
    private_json(backup / 'rollback.private.json', journal)
    before_sockets = sockets()
    traffic_objects = None
    try:
        run(['systemctl', 'stop', PANEL])
        compare_identity(baseline, identity(context), False)
        traffic_objects = traffic_context(context)
        accounts, integration, traffic = traffic_objects
        compare_identity(baseline, identity(context), False)
        data = ('# Dedicated HY2 UDP socket buffer ceilings.\n' +
                ''.join(key + ' = ' + str(TARGET) + '\n' for key in KEYS)).encode('ascii')
        check_original_config(journal['sysctl_file'])
        require(sysctls() == journal['sysctls'], 'UDP buffer sysctls changed concurrently')
        journal.update(persistent_write_started=True,
                       written_sysctl_sha256=hashlib.sha256(data).hexdigest())
        private_json(backup / 'rollback.private.json', journal)
        atomic(CONF, data, {'uid': 0, 'gid': 0, 'mode': 0o644})
        set_sysctls({key: TARGET for key in KEYS}, journal, backup)
        restarted = []
        for record in baseline['records']:
            if active(baseline['services'][record['hy2']]):
                restarted.append(restart_one(accounts, integration, traffic, record, journal, backup))
                check_sockets(before_sockets, sockets(), record['port'])
        check_ledger(journal['ledger'], ledger(context))
        compare_identity(baseline, identity(context), False)
        run(['systemctl', 'start', PANEL])
        wait_panel(context)
        compare_identity(baseline, identity(context), True)
        check_ledger(journal['ledger'], ledger(context))
        require(qdisc_snapshot()['semantic_sha256'] == journal['qdisc_sha256'],
                'Network queue semantics changed during maintenance')
        journal['applied'] = True
        private_json(backup / 'rollback.private.json', journal)
        return {'success': True, 'action': 'apply', 'backup_dir': str(backup),
            'identity_preserved': True, 'xray_epochs_preserved': True,
            'ledger_totals_non_decreasing': True, 'limits_preserved': True,
            'qdisc_preserved': True, 'restarted': restarted,
            'final_sample_limitation': 'Final counters are persisted before restart; a tiny sample-to-stop interval remains.',
            'panel_session_notice': 'The panel worker restarts; existing browser sessions require login again.',
            'runtime': runtime_snapshot(context)}
    except BaseException as error:
        result = {'success': False, 'action': 'apply', 'error_type': type(error).__name__,
            'failure': str(error) if isinstance(error, RuntimeError) else 'Maintenance did not complete',
            'backup_dir': str(backup)}
        try:
            result['rollback'] = recover(journal, backup, traffic_objects)
        except BaseException as rollback_error:
            result['rollback'] = {'success': False, 'error_type': type(rollback_error).__name__,
                'failure': 'Automatic rollback requires host inspection'}
            # Restore original panel availability even if an instance needs inspection.
            if active(baseline['services'][PANEL]):
                try:
                    run(['systemctl', 'start', PANEL])
                    wait_panel(context)
                except Exception:
                    result['rollback']['panel_ready'] = False
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--action', required=True, choices=('snapshot', 'apply', 'rollback'))
    parser.add_argument('--package-root', required=True)
    parser.add_argument('--backup-dir')
    args = parser.parse_args()
    require(os.name == 'posix' and os.geteuid() == 0, 'Root Linux maintenance process is required')
    package_root = Path(args.package_root)
    require(package_root.is_absolute() and package_root.is_dir()
            and not package_root.is_symlink(), 'Invalid deployed package root')
    if args.action == 'snapshot':
        context = launch_context(package_root)
        return {'success': True, 'action': 'snapshot', 'package_root': context['package_root'],
                'runtime': runtime_snapshot(context)}
    require(args.backup_dir is not None, 'A dedicated private rollback directory is required')
    require(not LOCK.is_symlink() and LOCK.parent.is_dir(), 'Unsafe maintenance lock')
    fd = os.open(str(LOCK), os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.action == 'apply':
            context = launch_context(package_root)
            backup = backup_directory(args.backup_dir, True)
            return apply(context, backup)
        backup = backup_directory(args.backup_dir, False)
        journal_path = safe_file(backup / 'rollback.private.json')
        require(journal_path.stat().st_uid == 0 and stat.S_IMODE(journal_path.stat().st_mode) == 0o600,
                'Private rollback metadata permissions differ')
        journal = json.loads(journal_path.read_text())
        require(journal.get('format') == FORMAT
                and Path(journal['context']['package_root']).resolve() == package_root.resolve(),
                'Private rollback metadata belongs to a different maintenance target')
        import_package(journal['context'])
        current = identity(journal['context'])
        compare_identity(journal['identity'], current, active(current['services'][PANEL]),
                         recoverable=journal['attempted'])
        if journal.get('rolled_back'):
            require(sysctls() == journal['sysctls'], 'Already rolled-back sysctls changed')
            return {'success': True, 'action': 'rollback', 'already_rolled_back': True}
        result = recover(journal, backup)
        result.update(action='rollback', backup_dir=str(backup), runtime=runtime_snapshot(journal['context']))
        return result
    finally:
        os.close(fd)


if __name__ == '__main__':
    try:
        result = main()
    except BaseException as error:
        result = {'success': False, 'error_type': type(error).__name__,
            'failure': str(error) if isinstance(error, RuntimeError) else 'Maintenance process did not complete'}
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    raise SystemExit(0 if result.get('success') else 1)
