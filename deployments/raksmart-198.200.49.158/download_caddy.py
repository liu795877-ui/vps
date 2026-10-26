"""Download and verify Caddy on the target VPS from its official release."""
import json
from ssh_access import connect, execute, FOLDER

PROGRAM = r'''
import hashlib, json, os, tarfile
from pathlib import Path
from urllib.request import Request, urlopen

def fetch(url):
    if not url.startswith('https://'):
        raise RuntimeError('HTTPS download required')
    with urlopen(Request(url, headers={'User-Agent':'Private-Node-Deployment'}), timeout=30) as response:
        if not response.geturl().startswith('https://'):
            raise RuntimeError('Non-HTTPS redirect refused')
        return response.read()

release = json.loads(fetch('https://api.github.com/repos/caddyserver/caddy/releases/latest'))
version = release['tag_name'].lstrip('v')
assets = {entry['name']:entry for entry in release['assets']}
names = ['caddy_' + version + '_checksums.txt', 'caddy_' + version + '_linux_amd64.tar.gz']
stage = Path('/root/raksmart-proxy-deploy-20261009/caddy')
stage.mkdir(mode=0o700, parents=True, exist_ok=True)
payloads = []
for name in names:
    content = (stage/name).read_bytes() if (stage/name).exists() else fetch(assets[name]['browser_download_url'])
    sha = hashlib.sha256(content).hexdigest()
    if assets[name].get('digest') != 'sha256:' + sha:
        raise RuntimeError('Official API SHA256 mismatch: ' + name)
    (stage/name).write_bytes(content)
    payloads.append(content)
checksums = {line.split()[1].lstrip('*'):line.split()[0].lower() for line in payloads[0].decode().splitlines() if line.strip()}
expected = checksums.get(names[1], '')
hasher = hashlib.sha256 if len(expected) == 64 else hashlib.sha512 if len(expected) == 128 else None
if hasher is None or expected != hasher(payloads[1]).hexdigest():
    raise RuntimeError('Official checksum mismatch')
with tarfile.open(str(stage/names[1]), 'r:gz') as archive:
    member = archive.getmember('caddy')
    if not member.isfile():
        raise RuntimeError('Unexpected binary member')
    content = archive.extractfile(member).read()
(stage/'caddy').write_bytes(content)
os.chmod(str(stage/'caddy'), 0o700)
result = {'version':release['tag_name'], 'archive_sha256':hashlib.sha256(payloads[1]).hexdigest(),
          'binary_sha256':hashlib.sha256(content).hexdigest(), 'official_checksums_verified':True,
          'release_url':release['html_url'], 'binary':str(stage/'caddy')}
(stage/'verification.json').write_text(json.dumps(result, indent=2))
print(json.dumps(result))
'''

client = connect()
try:
    code, output, error = execute(client, "python3 - <<'CADDY_DOWNLOAD_PY'\n" + PROGRAM + '\nCADDY_DOWNLOAD_PY\n', timeout=150)
    (FOLDER/'caddy-download.private.log').write_text(output+'\n'+error, encoding='utf-8')
    if code:
        raise SystemExit('Caddy download failed; inspect private log')
    result = json.loads(output)
    (FOLDER/'caddy-verification.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result))
finally:
    client.close()
