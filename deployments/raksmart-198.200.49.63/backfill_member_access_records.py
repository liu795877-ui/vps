"""Finish initial journal import in bounded batches using the deployed collector.

SQLite serializes this worker with normal collection. Only the private access
database is written; no account, proxy, firewall or service state is changed.
"""
from datetime import datetime, timezone
import json
from pathlib import Path

from validate_console_optimization import strict_connect, remote_command
import ssh_access as ssh


FOLDER = Path(__file__).resolve().parent
PROGRAM = '''import json,sys,threading,time
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,'/opt/vps-panel')
from panel.access_records import AccessRecords
registry=json.loads(Path('/var/lib/vps-panel/users.private.json').read_text(encoding='utf-8'))
accounts=SimpleNamespace(owner_manager=SimpleNamespace(directory='/var/lib/vps-panel'),
    records=registry['users'],lock=threading.RLock(),demo=False)
collector=AccessRecords(accounts)
started=time.monotonic()
batches=0
while time.monotonic()-started<20:
    collector.tick()
    assert collector.error is None, 'collector import incomplete'
    batches+=1
    if not collector.backlog:
        break
with collector._db() as db:
    count=db.execute('SELECT count(*) FROM connections').fetchone()[0]
    admin=db.execute("SELECT count(*) FROM connections WHERE member_id='admin'").fetchone()[0]
    newest=db.execute('SELECT max(at_us) FROM connections').fetchone()[0]
    source=float(collector._meta(db,'source_time','0'))/1000000
assert admin==0 and count<=100000
print(json.dumps({'batches':batches,'records':count,'administrator_records':admin,
    'catching_up':collector.backlog,'latest_record_age_seconds':round(time.time()-newest/1000000,3) if newest else None,
    'source_scan_lag_seconds':round(time.time()-source,3),'elapsed_seconds':round(time.monotonic()-started,3)}))
'''


def main():
    client = strict_connect(ssh)
    runs = []
    try:
        for unused in range(8):
            code, output, error = ssh.execute(client, remote_command(PROGRAM), timeout=45)
            if code:
                raise SystemExit("Bounded initial import stopped; private diagnostics suppressed")
            result = json.loads(output)
            runs.append(result)
            print(json.dumps(result), flush=True)
            if not result["catching_up"]:
                break
    finally:
        client.close()
        report = {"success":bool(runs) and not runs[-1]["catching_up"],
                  "time_utc":datetime.now(timezone.utc).isoformat(),"runs":runs,
                  "proxy_or_account_configuration_changed":False,"private_values_included":False}
        (FOLDER / "member-access-initial-backfill-20261023.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0 if report["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
