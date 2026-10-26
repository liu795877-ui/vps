"""Validate candidate console sources on the VPS in an isolated directory."""
from datetime import datetime, timezone
import json
from ssh_access import connect, execute, FOLDER

stage = '/root/raksmart-proxy-deploy-20261009/features-validation-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')
program = r'''
import hashlib, json, os, re, subprocess, sys, tarfile
from pathlib import Path
root = Path(STAGE)
source = root / 'release'
source.mkdir(mode=0o700)
live = [Path('/usr/local/etc/xray/config.json'), Path('/var/lib/vps-panel/state.private.json')]
before = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in live}
with tarfile.open(str(root / 'release.tar.gz')) as bundle:
    for member in bundle.getmembers():
        resolved = (source / member.name).resolve()
        if source.resolve() not in resolved.parents or not member.isfile():
            raise RuntimeError('Unexpected validation archive entry')
    bundle.extractall(str(source))
environment = os.environ.copy()
environment['XRAY_TEST_BINARY'] = '/usr/local/bin/xray'
tests = subprocess.run([sys.executable, '-m', 'unittest', 'test_configure_reality',
                        'test_configure_static_exits', 'panel.test_panel'], cwd=str(source),
                       env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
log = tests.stdout + b'\n' + tests.stderr
(root / 'linux-tests.private.log').write_bytes(log)
os.chmod(str(root / 'linux-tests.private.log'), 0o600)
after = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in live}
match = re.search(r'Ran (\d+) tests', log.decode('utf-8', errors='replace'))
result = {'success': tests.returncode == 0 and before == after,
          'test_count': int(match.group(1)) if match else None,
          'runtime': sys.version.split()[0], 'official_xray_core': True,
          'configuration_and_exit_state_preserved': before == after,
          'stage': str(root)}
print(json.dumps(result))
'''

client = connect()
try:
    code, _, _ = execute(client, 'install -d -m 0700 ' + stage)
    if code:
        raise RuntimeError('Could not create isolated validation directory')
    with client.open_sftp() as transfer:
        transfer.put(str(FOLDER / 'panel-features-validation.tar.gz'), stage + '/release.tar.gz')
        transfer.chmod(stage + '/release.tar.gz', 0o600)
    command = "python3 - <<'FEATURES_VALIDATE_PY'\nSTAGE=" + repr(stage) + '\n' + program + '\nFEATURES_VALIDATE_PY\n'
    code, output, error = execute(client, command, timeout=150)
    (FOLDER / 'panel-features-validation.private.log').write_text(output + '\n' + error, encoding='utf-8')
    if code:
        raise SystemExit('Candidate validation failed; inspect private log')
    result = json.loads(output)
    (FOLDER / 'panel-features-validation.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result))
    if not result['success']:
        raise SystemExit(1)
finally:
    client.close()
