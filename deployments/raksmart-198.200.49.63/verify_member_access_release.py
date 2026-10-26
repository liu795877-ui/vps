"""Read-only post-deployment source and collector verification, without destinations."""
import argparse
import base64
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys

from validate_console_optimization import strict_connect, remote_command
import ssh_access as ssh


FOLDER = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("release")
    parser.add_argument("--report-name", default="member-access-post-deployment-20261023.json")
    args = parser.parse_args()
    release = args.release
    if not re.fullmatch(r"console-optimization-release-\d{8}-[A-Za-z0-9_-]+", release):
        raise SystemExit("Use a frozen release name")
    if not re.fullmatch(r"member-(?:access|nickname)-post-deployment-[A-Za-z0-9_-]+\.json", args.report_name):
        raise SystemExit("Use a named post-deployment report")
    manifest = json.loads((FOLDER / release / "manifest.json").read_text(encoding="utf-8"))
    encoded = base64.b64encode(json.dumps(manifest["release_sha256"]).encode("utf-8")).decode("ascii")
    program = '''import base64,hashlib,json,os,sqlite3,stat,subprocess,time
from pathlib import Path
hashes=json.loads(base64.b64decode(HASHES))
mismatches=[name for name,value in hashes.items()
    if hashlib.sha256((Path('/opt/vps-panel')/name).read_bytes()).hexdigest()!=value]
assert not mismatches, 'source mismatch'
path=Path('/var/lib/vps-panel/member-access.private.sqlite3')
assert path.is_file() and not path.is_symlink()
db=sqlite3.connect('file:'+str(path)+'?mode=ro',uri=True,timeout=3)
try:
    count=db.execute('SELECT count(*) FROM connections').fetchone()[0]
    admin=db.execute("SELECT count(*) FROM connections WHERE member_id='admin'").fetchone()[0]
    protocols=dict(db.execute('SELECT protocol,count(*) FROM connections GROUP BY protocol'))
    members=db.execute('SELECT count(DISTINCT member_id) FROM connections').fetchone()[0]
    oldest=db.execute('SELECT min(at_us) FROM connections').fetchone()[0]
    last_scan=float(db.execute("SELECT value FROM metadata WHERE key='scanned_at'").fetchone()[0])
finally:
    db.close()
mode=stat.S_IMODE(path.stat().st_mode)
assert 0<count<=100000 and admin==0 and mode==0o600
assert time.time()-last_scan<45
assert oldest>=int((time.time()-7*86400-60)*1000000)
records=json.loads(Path('/var/lib/vps-panel/users.private.json').read_text(encoding='utf-8'))['users']
units=['vps-panel.service','xray.service','raksmart-hy2.service','caddy.service']
units+=['xray-panel@'+record['id']+'.service' for record in records]
units+=['raksmart-hy2@'+str(record['port'])+'.service' for record in records]
services={}
for unit in units:
    process=subprocess.Popen(['systemctl','is-active',unit],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    output=process.communicate(timeout=5)[0].decode('ascii','replace').strip()
    services[unit]=output
assert services['vps-panel.service']=='active'
result={'success':True,'source_files_verified':len(hashes),'source_mismatches':mismatches,
    'records':count,'recorded_members':members,'administrator_records':admin,'protocol_counts':protocols,
    'database_mode':oct(mode),'database_bytes':path.stat().st_size,'last_scan_age_seconds':round(time.time()-last_scan,3),
    'retention_days':7,'max_records':100000,'services':services,
    'members':[{'id':record['id'],'enabled':record['enabled'],'port':record['port']} for record in records],
    'production_configuration_changed_by_verification':False,'private_values_included':False}
print(json.dumps(result))
'''.replace("HASHES", repr(encoded), 1)
    client = strict_connect(ssh)
    try:
        code, output, unused = ssh.execute(client, remote_command(program), timeout=60)
    finally:
        client.close()
    if code:
        raise SystemExit("Post-deployment verification failed; private diagnostics suppressed")
    result = json.loads(output)
    result.update(release=release, checked_at=datetime.now(timezone.utc).isoformat())
    report = FOLDER / args.report_name
    if report.is_symlink():
        raise SystemExit("Linked report paths are rejected")
    report.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
