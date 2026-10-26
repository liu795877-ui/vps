set -eu
python3 - <<'PY'
from pathlib import Path
import hashlib, json
folder=Path('/root/raksmart-proxy-deploy-20261009/caddy')
for path in folder.glob('*checksums.txt'):
    print(path.name)
    for line in path.read_text().splitlines():
        if 'linux_amd64.tar.gz' in line:
            print(line)
for path in folder.glob('*linux_amd64.tar.gz'):
    print(json.dumps({'file':path.name,'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'bytes':path.stat().st_size}))
PY
