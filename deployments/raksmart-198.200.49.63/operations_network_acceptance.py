"""Exercise real kernel quota/shaping controls in disposable network namespaces.

Production interfaces, netfilter rules, proxy configuration and services are
read only. Every listener, private directory and network object belongs to this
fixture and is removed in finally. Reports contain no account credentials.
"""

import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import secrets
import shlex

from ssh_access import FOLDER, connect, execute


ROOT = FOLDER.parents[1]
REPORT = FOLDER / "operations-network-acceptance.json"

CAPABILITIES = r'''
import hashlib, json, os, subprocess
from pathlib import Path
result=subprocess.run(['systemctl','show','vps-panel.service','--property=MainPID',
    '--property=ActiveState','--property=RestrictAddressFamilies','--property=NeedDaemonReload',
    '--property=DropInPaths','--property=FragmentPath'],stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,timeout=15)
if result.returncode:
    raise RuntimeError('Panel unit could not be read')
properties=dict(line.split('=',1) for line in result.stdout.decode().splitlines() if '=' in line)
pid=int(properties.get('MainPID','0'))
if pid <= 0:
    raise RuntimeError('Panel process is not running')
status=dict(line.split(':',1) for line in Path('/proc/'+str(pid)+'/status').read_text().splitlines() if ':' in line)
effective=int(status['CapEff'].strip(),16)
bounding=int(status['CapBnd'].strip(),16)
families=properties.get('RestrictAddressFamilies','').split()
unit_paths=[Path(properties['FragmentPath'])]+[Path(name) for name in properties.get('DropInPaths','').split()]
configured=[]
merged_families=set()
family_parse_valid=True
for unit_path in unit_paths:
    for line in unit_path.read_text().splitlines():
        if line.startswith('RestrictAddressFamilies='):
            value=line.split('=',1)[1].strip()
            configured.append({'path':str(unit_path),'value':value})
            if not value:
                merged_families.clear()
            elif value.startswith('~'):
                family_parse_valid=False
            else:
                # systemd combines repeated allowlists across the fragment and
                # drop-ins. A blank assignment is the explicit reset operation.
                merged_families.update(value.split())
# An empty setting permits every family. Otherwise AF_NETLINK must be allowed
# so tc and iproute can communicate with the kernel network subsystem.
families_readable='[unprintable]' not in families
if families_readable:
    family_allowed=not families or 'AF_NETLINK' in families
    family_evidence='systemctl loaded property'
else:
    # CentOS 7 systemd exposes this set property as [unprintable]. Its installed
    # fragment plus drop-ins are authoritative only when systemd has loaded
    # them and the current process was launched after all files were written.
    boot_time=int(next(line.split()[1] for line in Path('/proc/stat').read_text().splitlines()
                       if line.startswith('btime ')))
    process_fields=Path('/proc/'+str(pid)+'/stat').read_text().split(') ',1)[1].split()
    process_started=boot_time+int(process_fields[19])/os.sysconf('SC_CLK_TCK')
    unit_current=(properties.get('NeedDaemonReload')=='no'
                  and process_started+1 >= max(path.stat().st_mtime for path in unit_paths))
    family_allowed=unit_current and family_parse_valid and (not merged_families or 'AF_NETLINK' in merged_families)
    family_evidence='merged fragment and drop-ins, no pending reload, process started after all unit changes'
telemetry=Path('/opt/vps-panel/panel/telemetry.py').read_bytes()
normalized=telemetry.decode('utf-8').replace('\r\n','\n')
output={'main_pid':pid,'active':properties.get('ActiveState')=='active',
        'net_admin_effective':bool(effective & (1<<12)),
        'net_admin_bounding':bool(bounding & (1<<12)),
        'net_raw_effective':bool(effective & (1<<13)),
        'net_raw_bounding':bool(bounding & (1<<13)),
        'effective_capabilities_hex':status['CapEff'].strip(),
        'af_netlink_allowed':family_allowed,
        'configured_address_families':configured,
        'merged_address_families':sorted(merged_families),
        'address_family_evidence':family_evidence,
        'systemctl_family_property_readable':families_readable,
        'telemetry_sha256':hashlib.sha256(telemetry).hexdigest(),
        'telemetry_normalized_sha256':hashlib.sha256(normalized.encode('utf-8')).hexdigest(),
        'quota_reset_return_present':'"--tcp-flags", "RST", "RST", "-j", "RETURN"' in normalized,
        'restrict_address_families':families,'read_only':True}
output['success']=(output['active'] and output['net_admin_effective'] and output['net_admin_bounding']
                   and output['net_raw_effective'] and output['net_raw_bounding'] and family_allowed)
print(json.dumps(output))
'''

STUB = r'''
import json, os, secrets
from pathlib import Path
class PanelError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status
def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
def atomic_write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.tmp-' + secrets.token_hex(4))
    descriptor = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(data)
    os.replace(str(tmp), str(path))
'''

SERVER = r'''
import socket, threading, time
def serve(connection):
    try:
        connection.settimeout(80)
        stream = connection.makefile('rb')
        while True:
            line = stream.readline(100)
            if not line:
                return
            operation, count = line.decode().strip().split()
            count = int(count)
            if not 0 <= count <= 16 * 1024 * 1024:
                return
            if operation == 'H':
                connection.sendall(b'READY\n')
            elif operation == 'D':
                chunk = b'x' * 65536
                while count:
                    part = min(count, len(chunk))
                    connection.sendall(chunk[:part])
                    count -= part
            elif operation == 'U':
                while count:
                    data = stream.read(min(count, 65536))
                    if not data:
                        return
                    count -= len(data)
                connection.sendall(b'OK\n')
            else:
                return
    except Exception:
        pass
    finally:
        connection.close()
def listen(port):
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('192.0.2.1', port))
    sock.listen(16)
    while True:
        connection, address = sock.accept()
        threading.Thread(target=serve, args=(connection,), daemon=True).start()
for port in (443, 1443, 2443, 27443):
    threading.Thread(target=listen, args=(port,), daemon=True).start()
while True:
    time.sleep(1)
'''

CLIENT = r'''
import json, socket, sys, time
from pathlib import Path
mode, port = sys.argv[1], int(sys.argv[2])
result = {'mode': mode, 'port': port}
try:
    connection = socket.create_connection(('192.0.2.1', port), timeout=4)
    connection.settimeout(75)
    if mode == 'probe':
        connection.sendall(b'H 0\n')
        result['reachable'] = connection.recv(32) == b'READY\n'
    elif mode == 'hold':
        ready, release = Path(sys.argv[3]), Path(sys.argv[4])
        connection.sendall(b'H 0\n')
        if connection.recv(32) != b'READY\n':
            raise RuntimeError('hold handshake failed')
        ready.write_text('ready')
        deadline = time.monotonic() + 25
        while not release.exists():
            if time.monotonic() > deadline:
                raise RuntimeError('hold release timed out')
            time.sleep(.02)
        connection.settimeout(4)
        try:
            connection.sendall(b'H 0\n')
            result['reset'] = connection.recv(32) != b'READY\n'
        except OSError as error:
            result['reset'] = not isinstance(error, socket.timeout)
            result['blocked'] = True
    else:
        count = int(sys.argv[3])
        started = time.monotonic()
        connection.sendall((mode + ' ' + str(count) + '\n').encode())
        remaining = count
        if mode == 'D':
            while remaining:
                data = connection.recv(min(remaining, 65536))
                if not data:
                    raise RuntimeError('incomplete download')
                remaining -= len(data)
        else:
            chunk = b'x' * 4096
            connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            while remaining:
                part = min(remaining, len(chunk))
                connection.sendall(chunk[:part])
                remaining -= part
            if connection.recv(8) != b'OK\n':
                raise RuntimeError('upload acknowledgment missing')
        elapsed = time.monotonic() - started
        result.update(bytes=count, seconds=elapsed, measured_bps=int(count * 8 / elapsed), completed=True)
    connection.close()
except Exception as error:
    if mode == 'probe':
        result['reachable'] = False
    else:
        result['error'] = type(error).__name__ + ': ' + str(error)[:160]
print(json.dumps(result))
'''

CONTROL = r'''
import json, sys
from pathlib import Path
from panel.telemetry import LinuxControls
request = json.loads(sys.argv[1])
control = LinuxControls(Path(__file__).parent / 'controls')
control.apply(set(request['blocked']), {int(port): rate for port, rate in request['rates'].items()})
print(json.dumps({'applied':True,'state':control.state}))
'''

PROGRAM = r'''
import hashlib, json, os, re, shutil, subprocess, sys, time
from pathlib import Path

root = Path(sys.argv[1])
prefix = sys.argv[2]
if not re.fullmatch(r'vpnacc[a-f0-9]{8}', prefix) or str(root) != '/tmp/' + prefix:
    raise RuntimeError('Fixture paths are invalid')
server_ns, client_ns = prefix + 's', prefix + 'c'
server_link, client_link = prefix + 'a', prefix + 'b'
processes = []
created_namespaces = []
created_link = False
report = {'success':False, 'isolation':'two disposable network namespaces',
          'production_mutations':False,'checks':{}}

def run(args, timeout=20, check=True):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError('Fixture command failed: ' + args[0] + ' ' +
                           result.stderr.decode('utf-8','replace')[:250])
    return result

def ns(namespace, args, timeout=20):
    return run(['ip','netns','exec',namespace] + args,timeout)

def client(mode,port,count=0):
    result = ns(client_ns,['python3',str(root/'client.py'),mode,str(port),str(count)],timeout=90)
    data=json.loads(result.stdout.decode())
    if data.get('error'):
        raise RuntimeError(data['error'])
    return data

def control(blocked=None,rates=None):
    result=ns(server_ns,['python3',str(root/'control.py'),json.dumps({
        'blocked':blocked or [],'rates':rates or {}})],timeout=30)
    return json.loads(result.stdout.decode())

def production_baseline():
    protected=['/usr/local/etc/xray/config.json','/var/lib/vps-panel/state.private.json',
               '/var/lib/vps-panel/auth.private.json','/var/lib/vps-panel/users.private.json']
    protected += [str(path) for path in Path('/usr/local/etc/xray-members').glob('*/config.json')]
    return {'qdisc':run(['tc','qdisc','show']).stdout.decode(),
            'iptables':run(['iptables','-S']).stdout.decode(),
            'routes':run(['ip','route','show']).stdout.decode(),
            'files':{path:hashlib.sha256(Path(path).read_bytes()).hexdigest()
                     for path in protected if Path(path).is_file()}}

baseline=production_baseline()
try:
    for namespace in (server_ns,client_ns):
        run(['ip','netns','add',namespace])
        created_namespaces.append(namespace)
    run(['ip','link','add',server_link,'type','veth','peer','name',client_link])
    created_link=True
    run(['ip','link','set',server_link,'netns',server_ns])
    run(['ip','link','set',client_link,'netns',client_ns])
    for namespace,link,address in ((server_ns,server_link,'192.0.2.1'),(client_ns,client_link,'192.0.2.2')):
        ns(namespace,['ip','link','set',link,'name','eth0'])
        ns(namespace,['ip','addr','add',address+'/24','dev','eth0'])
        ns(namespace,['ip','link','set','eth0','up'])
        ns(namespace,['ip','link','set','lo','up'])
        ns(namespace,['ethtool','-K','eth0','gro','off','gso','off','tso','off'])
    ns(server_ns,['ip','route','add','default','via','192.0.2.2','dev','eth0'])
    ns(client_ns,['ip','route','add','default','via','192.0.2.1','dev','eth0'])
    server=subprocess.Popen(['ip','netns','exec',server_ns,'python3',str(root/'server.py')],
                            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    processes.append(server)
    deadline=time.monotonic()+8
    while not client('probe',1443)['reachable']:
        if time.monotonic()>deadline:
            raise RuntimeError('Fixture listeners did not start')
        time.sleep(.05)
    report['checks']['all_ports_initially_reachable']=all(client('probe',p)['reachable']
                                                        for p in (443,1443,2443,27443))
    baseline_down=client('D',1443,1048576)
    baseline_up=client('U',1443,262144)
    report['baseline']={'download':baseline_down,'upload':baseline_up}
    ready,release=root/'hold-ready',root/'hold-release'
    held=subprocess.Popen(['ip','netns','exec',client_ns,'python3',str(root/'client.py'),
                           'hold','1443',str(ready),str(release)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    processes.append(held)
    deadline=time.monotonic()+8
    while not ready.exists():
        if time.monotonic()>deadline:
            raise RuntimeError('Existing connection fixture did not start')
        time.sleep(.02)
    control(blocked=[1443])
    report['checks']['quota_blocks_new_connections']=not client('probe',1443)['reachable']
    report['checks']['quota_preserves_other_ports']=all(client('probe',p)['reachable']
                                                      for p in (443,2443,27443))
    release.write_text('release')
    held_output,held_error=held.communicate(timeout=10)
    report['checks']['quota_resets_existing_connection']=bool(json.loads(held_output.decode()).get('reset'))
    report['checks']['quota_preserves_loopback_chain_return']=all(
        'lo -j RETURN' in ns(server_ns,['iptables','-S',chain]).stdout.decode()
        for chain in ('VPS_PANEL_QUOTA_IN','VPS_PANEL_QUOTA_OUT'))
    control()
    report['checks']['quota_zero_restores_access']=client('probe',1443)['reachable']
    configured_rate=4000000
    control(rates={'1443':configured_rate})
    qdisc=ns(server_ns,['tc','qdisc','show','dev','eth0']).stdout.decode()
    egress=ns(server_ns,['tc','filter','show','dev','eth0','parent','7a00:']).stdout.decode()
    ingress=ns(server_ns,['tc','filter','show','dev','eth0','parent','ffff:']).stdout.decode()
    report['checks']['real_htb_and_ingress_installed']='htb 7a00:' in qdisc and 'ingress ffff:' in qdisc
    report['checks']['real_filters_installed']='u32' in egress and 'police' in ingress
    limited_down=client('D',1443,1048576)
    limited_up=client('U',1443,262144)
    other_down=client('D',443,1048576)
    report['limited']={'configured_bps':configured_rate,'download':limited_down,'upload':limited_up,
                       'other_port_download':other_down}
    report['checks']['download_rate_actually_limited']=(limited_down['measured_bps'] < configured_rate*1.4
        and limited_down['seconds'] > baseline_down['seconds']*4)
    report['checks']['upload_rate_actually_limited']=(limited_up['measured_bps'] < configured_rate*1.7
        and limited_up['seconds'] > baseline_up['seconds']*4)
    report['checks']['other_port_not_shaped']=other_down['measured_bps'] > configured_rate*3
    control()
    cleared_qdisc=ns(server_ns,['tc','qdisc','show','dev','eth0']).stdout.decode()
    restored_down=client('D',1443,1048576)
    restored_up=client('U',1443,262144)
    report['restored']={'download':restored_down,'upload':restored_up}
    report['checks']['zero_removes_owned_qdiscs']='7a00:' not in cleared_qdisc and 'ffff:' not in cleared_qdisc
    report['checks']['zero_restores_speed']=(restored_down['measured_bps'] > configured_rate*3
                                            and restored_up['measured_bps'] > configured_rate*3)
    report['success']=all(report['checks'].values())
except Exception as error:
    report['error']=type(error).__name__+': '+str(error)[:500]
finally:
    cleanup=[]
    for process in processes:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=4)
    for namespace in reversed(created_namespaces):
        # Kill only processes explicitly inside namespaces created by this run.
        result=run(['ip','netns','pids',namespace],check=False)
        for token in result.stdout.decode().split():
            if token.isdigit():
                run(['kill','-KILL',token],check=False)
        result=run(['ip','netns','del',namespace],check=False)
        cleanup.append(result.returncode==0)
    if created_link:
        # If link creation succeeded but a move failed, its host fixture endpoint
        # remains. Exact names only; never select or mutate a production link.
        for link in (server_link,client_link):
            run(['ip','link','delete',link],check=False)
    remaining=run(['ip','netns','list']).stdout.decode()
    report['cleanup_complete']=all(cleanup) and server_ns not in remaining and client_ns not in remaining
    after=production_baseline()
    report['production_unchanged']=after==baseline
    report['success']=report['success'] and report['cleanup_complete'] and report['production_unchanged']
    if root.is_symlink() or root.parent!=Path('/tmp') or root.name!=prefix:
        raise RuntimeError('Refused unsafe fixture cleanup')
    shutil.rmtree(str(root))
    report['temporary_files_removed']=not root.exists()
print(json.dumps(report))
'''


def verify_capabilities():
    ast.parse(CAPABILITIES, feature_version=(3, 6))
    client = connect()
    try:
        code, output, error = execute(client,
            "python3 - <<'PANEL_CAPABILITIES'\n" + CAPABILITIES + "\nPANEL_CAPABILITIES\n", timeout=25)
        if code:
            raise RuntimeError("Read-only panel capability inspection failed")
        result = json.loads(output)
        result["checked_at"] = datetime.now(timezone.utc).isoformat()
        report = json.loads(REPORT.read_text(encoding="utf-8")) if REPORT.exists() else {}
        from multiuser_update import compatible
        manifest = json.loads((FOLDER / "operations-release-manifest.json").read_text(encoding="utf-8"))
        prepared_hash = manifest["source_sha256"]["panel/telemetry.py"]
        normalized_source = compatible((ROOT / "panel" / "telemetry.py").read_text(encoding="utf-8"),
                                       "panel/telemetry.py").encode("utf-8")
        normalized_hash = hashlib.sha256(normalized_source).hexdigest()
        result["matches_prepared_manifest"] = result["telemetry_sha256"] == prepared_hash
        result["compatible_source_matches_tested_semantics"] = result["telemetry_normalized_sha256"] == normalized_hash
        result["tested_source_deployed"] = (result["matches_prepared_manifest"] and
            result["compatible_source_matches_tested_semantics"] and result["quota_reset_return_present"])
        from update_routing_url import login_sessions, logout_sessions
        import frontend_motion_access as live
        sessions = {}
        try:
            sessions = login_sessions()
            samples = []
            for identity, session in sessions.items():
                status, unused, body = live.request("GET", "api/traffic", headers={"Cookie": session["cookie"]})
                if status != 200:
                    raise RuntimeError("Could not inspect an enabled user's real statistics")
                traffic = json.loads(body)
                samples.append({"id": identity, "available": traffic.get("available"),
                                "connections": traffic.get("connections"), "sampled_at": traffic.get("sampled_at"),
                                "enforcement_error": traffic.get("enforcement_error")})
            result["traffic_samples"] = samples
            result["all_enabled_accounts_sampled"] = bool(samples) and all(item["available"] for item in samples)
            result["live_af_netlink_observed"] = result["all_enabled_accounts_sampled"]
        finally:
            logout_sessions(sessions)
        result["success"] = result["success"] and result["all_enabled_accounts_sampled"]
        result["success"] = result["success"] and result["tested_source_deployed"]
        report["network_fixture_success"] = report.get("network_fixture_success", report.get("success", False))
        report["production_panel_capabilities"] = result
        report["success"] = bool(report["network_fixture_success"] and result["success"])
        REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(result, ensure_ascii=False))
        if not result["success"]:
            raise RuntimeError("Panel process lacks a required kernel network permission")
    finally:
        client.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--capability-only", action="store_true",
                        help="Read the published panel process permissions without creating a fixture")
    args = parser.parse_args()
    if args.capability_only:
        return verify_capabilities()
    for text, label in ((PROGRAM, "orchestrator"), (SERVER, "server"), (CLIENT, "client"),
                        (CONTROL, "control"), (STUB, "server-stub")):
        ast.parse(text, filename=label, feature_version=(3, 6))
    prefix = "vpnacc" + secrets.token_hex(4)
    remote = "/tmp/" + prefix
    telemetry_source = (ROOT / "panel" / "telemetry.py").read_bytes()
    client = connect()
    report = None
    try:
        sftp = client.open_sftp()
        try:
            sftp.mkdir(remote, mode=0o700)
            sftp.mkdir(remote + "/panel", mode=0o700)
            files = {"panel/__init__.py": b"", "panel/telemetry.py": telemetry_source,
                     "panel/server.py": STUB.encode(), "server.py": SERVER.encode(),
                     "client.py": CLIENT.encode(), "control.py": CONTROL.encode(),
                     "orchestrator.py": PROGRAM.encode()}
            for name, data in files.items():
                with sftp.file(remote + "/" + name, "wb") as stream:
                    stream.write(data)
                sftp.chmod(remote + "/" + name, 0o600)
        finally:
            sftp.close()
        command = "python3 " + shlex.quote(remote + "/orchestrator.py") + " " + shlex.quote(remote) + " " + prefix
        code, output, error = execute(client, command, timeout=240)
        if code:
            raise RuntimeError("Isolated fixture failed before producing its report: " + error[:500])
        report = json.loads(output)
        report.update(checked_at=datetime.now(timezone.utc).isoformat(),
                      telemetry_source_sha256=hashlib.sha256(telemetry_source).hexdigest())
        REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(report, ensure_ascii=False))
        if not report["success"]:
            raise RuntimeError("Isolated kernel verification did not pass")
    finally:
        # An interrupted SSH run may not reach the remote finally. Reconcile
        # only our exact fixture resources, independently of report creation.
        cleanup = "python3 - <<'FIXTURE_CLEANUP'\n" + (
            "import os, re, shutil, subprocess\nfrom pathlib import Path\n"
            "prefix = " + repr(prefix) + "\nroot = Path(" + repr(remote) + ")\n"
            "if not re.fullmatch(r'vpnacc[a-f0-9]{8}', prefix) or str(root) != '/tmp/' + prefix:\n"
            " raise RuntimeError('Invalid fixture cleanup')\n"
            "for namespace in (prefix+'s', prefix+'c'):\n"
            " result=subprocess.run(['ip','netns','pids',namespace],stdout=subprocess.PIPE,stderr=subprocess.PIPE)\n"
            " for pid in result.stdout.decode().split():\n"
            "  if pid.isdigit(): subprocess.run(['kill','-KILL',pid],stdout=subprocess.PIPE,stderr=subprocess.PIPE)\n"
            " subprocess.run(['ip','netns','del',namespace],stdout=subprocess.PIPE,stderr=subprocess.PIPE)\n"
            "for link in (prefix+'a',prefix+'b'):\n"
            " subprocess.run(['ip','link','delete',link],stdout=subprocess.PIPE,stderr=subprocess.PIPE)\n"
            "if root.exists() and not root.is_symlink(): shutil.rmtree(str(root))\n"
            "print('fixture-cleanup-complete')\n"
        ) + "FIXTURE_CLEANUP\n"
        try:
            cleanup_code, cleanup_output, cleanup_error = execute(client, cleanup, timeout=20)
            if cleanup_code:
                raise RuntimeError("Fixture cleanup needs attention")
        finally:
            client.close()


if __name__ == "__main__":
    main()
