import hashlib
import json
import argparse
from pathlib import Path
from ssh_access import connect, execute, FOLDER

STAGE = "/root/raksmart-proxy-deploy-20261009"
binary = FOLDER / "artifacts/linux-64/xray"
expected = hashlib.sha256(binary.read_bytes()).hexdigest()
parser = argparse.ArgumentParser()
parser.add_argument("--skip-upload", action="store_true")
args = parser.parse_args()
client = connect()
try:
    code, output, error = execute(client, "mkdir -p -m 700 " + STAGE)
    if code:
        raise RuntimeError("Could not create remote staging directory")
    if not args.skip_upload:
        with client.open_sftp() as sftp:
            sftp.put(str(binary), STAGE + "/xray", confirm=True)
            sftp.chmod(STAGE + "/xray", 0o755)
        print("Official binary uploaded.", flush=True)
    command = """set -eu
printf 'Binary checksum: '
sha256sum /root/raksmart-proxy-deploy-20261009/xray
install -m 755 /root/raksmart-proxy-deploy-20261009/xray /root/raksmart-proxy-deploy-20261009/xray-ready
/root/raksmart-proxy-deploy-20261009/xray-ready version
printf '\\nSystem dependencies\\n'
python3 --version
openssl version
systemctl --version | head -n 1
command -v setcap || true
command -v useradd || true
getenforce || true
printf '\\nOutbound TLS target responses\\n'
for host in www.microsoft.com www.cloudflare.com www.apple.com; do
  printf '%s ' "$host"
  curl -I -sS --connect-timeout 5 --max-time 12 "https://$host/" -o /dev/null -w 'HTTP %{http_code} TLS verify %{ssl_verify_result} remote %{remote_ip}\\n' || true
done
"""
    code, output, error = execute(client, command, timeout=55)
    if expected not in output:
        raise RuntimeError("Remote binary checksum mismatch")
    print(output)
    if error:
        print(error)
    if code:
        raise RuntimeError("Remote binary/dependency check failed")
    (FOLDER / "server-inspection.txt").write_text(output, encoding="utf-8")
finally:
    client.close()
