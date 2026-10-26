"""Package the panel and deploy through the already authorized private SSH key."""

import argparse
import json
from pathlib import Path
import secrets
import shlex
import subprocess
import sys
import tarfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from panel.server import atomic_write, json_bytes, password_record


def run(args, timeout=180):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError("Remote operation failed: " + result.stderr.strip()[-800:])
    return result.stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-ip")
    parser.add_argument("--host", default="43.130.238.204")
    parser.add_argument("--origin", default="https://api.aiuzh.icu")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    ssh = r"C:\Windows\System32\OpenSSH\ssh.exe"
    scp = r"C:\Windows\System32\OpenSSH\scp.exe"
    common = ["-i", str(root / "vps-login.key"), "-o", "BatchMode=yes",
              "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10"]
    if args.source_ip:
        common.extend(["-o", "BindAddress=" + args.source_ip])
    temporary = root / ".validation" / "panel-deploy"
    temporary.mkdir(parents=True, exist_ok=True)
    login_path = root / "panel-login.private.json"
    if login_path.exists():
        login = json.loads(login_path.read_text(encoding="utf-8"))
        password = login["password"]
    else:
        password = secrets.token_urlsafe(24)
        login = {"url": args.origin + "/node-console/", "username": "admin", "password": password}
        atomic_write(login_path, json_bytes(login))
    seed = temporary / "auth-seed.private.json"
    atomic_write(seed, json_bytes(password_record(password)))
    archive = temporary / "panel-release.private.tar.gz"
    paths = ["configure_reality.py", "configure_static_exits.py", "test_configure_reality.py",
             "test_configure_static_exits.py", "panel/__init__.py", "panel/server.py",
             "panel/test_panel.py", "panel/install.py", "panel/web/index.html",
             "panel/web/style.css", "panel/web/app.js", "panel/web/mark.svg",
             "panel/routing.py", "panel/node_info.py", "panel/services-routing.json", "panel/rules/domestic-dns.yaml"]
    with tarfile.open(archive, "w:gz") as bundle:
        for relative in paths:
            bundle.add(root / relative, arcname=relative)
        bundle.add(seed, arcname="auth-seed.private.json")
    remote = "/home/ubuntu/.cache/node-panel-deploy-" + secrets.token_hex(6)
    destination = "ubuntu@" + args.host
    run([ssh] + common + [destination, "umask 077; mkdir -p " + shlex.quote(remote)])
    run([scp] + common + [str(archive), destination + ":" + remote + "/release.tar.gz"])
    command = " && ".join([
        "tar -xzf " + shlex.quote(remote + "/release.tar.gz") + " -C " + shlex.quote(remote),
        "sudo python3 " + shlex.quote(remote + "/panel/install.py") +
        " --public-ip " + shlex.quote(args.host) + " --origin " + shlex.quote(args.origin),
    ])
    print(run([ssh] + common + [destination, command], timeout=240))
    print("Initial login details are saved in the local private login file; not printed.")


if __name__ == "__main__":
    main()
