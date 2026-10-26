"""Exercise the candidate collector against real journals using disposable storage.

Only aggregate results leave the server. Production code, data and services are
not changed, and the temporary database is removed before returning.
"""
import base64
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

from validate_console_optimization import strict_connect, remote_command
import ssh_access as ssh


FOLDER = Path(__file__).resolve().parent
ROOT = FOLDER.parents[1]


def main():
    source = (ROOT / "panel" / "access_records.py").read_bytes()
    program = '''import base64,json,os,shutil,sqlite3,stat,tempfile,threading,time
from pathlib import Path
from types import SimpleNamespace
namespace = {}
exec(compile(base64.b64decode(SOURCE), 'candidate_access_records.py', 'exec'), namespace)
registry = json.loads(Path('/var/lib/vps-panel/users.private.json').read_text(encoding='utf-8'))
temporary = tempfile.mkdtemp(prefix='member-access-validation-', dir='/tmp')
started = time.monotonic()
try:
    accounts = SimpleNamespace(owner_manager=SimpleNamespace(directory=temporary),
        records=registry['users'], lock=threading.RLock(), demo=False)
    collector = namespace['AccessRecords'](accounts)
    for batch in range(5):
        collector.tick()
        assert collector.error is None, 'collector status error'
        if not collector.backlog:
            break
    with collector._db() as db:
        count = db.execute('SELECT count(*) FROM connections').fetchone()[0]
        protocols = dict(db.execute('SELECT protocol,count(*) FROM connections GROUP BY protocol'))
        invalid = db.execute("SELECT count(*) FROM connections WHERE member_id='admin' "
            "OR member_id NOT IN (" + ','.join('?' for unused in registry['users']) + ')',
            [item['id'] for item in registry['users']]).fetchone()[0]
        columns = [item[1] for item in db.execute('PRAGMA table_info(connections)')]
    assert count > 0 and invalid == 0
    assert not {'message','source_ip','url','password'}.intersection(columns)
    assert stat.S_IMODE(os.stat(str(collector.path)).st_mode) == 0o600
    result = {'success':True, 'python_version':list(__import__('sys').version_info[:3]),
        'sqlite_version':sqlite3.sqlite_version, 'batches':batch+1, 'connections':count,
        'protocol_counts':protocols, 'administrator_records':invalid,
        'catching_up':collector.backlog, 'database_mode':'0600',
        'elapsed_seconds':round(time.monotonic()-started,3), 'production_changed':False}
finally:
    shutil.rmtree(temporary)
print(json.dumps(result))
'''.replace("SOURCE", repr(base64.b64encode(source).decode("ascii")), 1)
    client = strict_connect(ssh)
    try:
        code, output, unused = ssh.execute(client, remote_command(program), timeout=75)
    finally:
        client.close()
    if code:
        raise SystemExit("Candidate journal validation failed; private diagnostics suppressed")
    result = json.loads(output)
    result["time_utc"] = datetime.now(timezone.utc).isoformat()
    report = FOLDER / "member-access-real-journal-validation-20261023.json"
    report.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
