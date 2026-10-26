"""Read-only .63 verification of the exact successful source transaction."""
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys

import ssh_access as ssh
from validate_console_optimization import remote_command, strict_connect

folder = Path(__file__).resolve().parent
release = sys.argv[1] if len(sys.argv) == 2 else ""
if not re.fullmatch(r"console-optimization-release-\d{8}-[A-Za-z0-9_-]+", release):
    raise SystemExit("Use a frozen release name")
suffix = release[len("console-optimization-release-"):]
deployment = json.loads((folder / ("console-optimization-deployment-" + suffix + ".json")).read_text())
manifest = json.loads((folder / release / "manifest.json").read_text())
assert deployment["success"] and deployment["archive_sha256"] == manifest["archive_sha256"]
configuration = {"stage": deployment["remote_stage"], "helper_sha256": deployment["remote_helper_sha256"],
                 "release_sha256": manifest["release_sha256"], "archive_sha256": manifest["archive_sha256"]}
program = '''import hashlib,importlib.util,json,sys
from pathlib import Path
sys.dont_write_bytecode=True
configuration=CONFIGURATION
stage=Path(configuration['stage'])
helper_file=stage/'deploy_remote.py'
assert hashlib.sha256(helper_file.read_bytes()).hexdigest()==configuration['helper_sha256']
spec=importlib.util.spec_from_file_location('membership_deployment_observer',str(helper_file))
helper=importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
before=json.loads(helper.safe(stage/'protected-before.private.json',True).read_text())
after=helper.snapshot()
helper.compare_snapshot(before,after,True)
helper.compare_ledger(json.loads((stage/'ledger-before.private.json').read_text()),helper.ledger())
for name,wanted in configuration['release_sha256'].items():
    assert helper.sha(helper.safe(helper.APP/name,True).read_bytes())==wanted
registry=json.loads((helper.DATA/'users.private.json').read_text())['users']
assert all(record['enabled'] and 'membership' not in record for record in registry)
assert after['services'][helper.PANEL]['ActiveState']=='active'
helper.ready()
print(json.dumps({'success':True,'source_files_verified':len(configuration['release_sha256']),
 'accounts_checked':len(after['records']),'existing_members_without_deadlines':len(registry),
 'protected_bytes_preserved':True,'proxy_epochs_preserved':True,'network_policy_preserved':True,
 'traffic_cumulative_non_decreasing':True,'panel_active':True,'service_control_performed':False,
 'account_login_performed':False,'production_mutated':False}))
'''.replace("CONFIGURATION", repr(configuration))
client = strict_connect(ssh)
try:
    code, output, error = ssh.execute(client, remote_command(program), timeout=90)
    if code:
        raise RuntimeError("Read-only post-deployment verification failed; no raw private values printed")
    result = json.loads(output)
    result.update(release=release, checked_at=datetime.now(timezone.utc).isoformat(),
                  archive_sha256=manifest["archive_sha256"], remote_checkpoint=deployment["remote_stage"])
    report = folder / ("membership-post-deployment-" + suffix + ".json")
    with report.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps(result))
finally:
    client.close()
