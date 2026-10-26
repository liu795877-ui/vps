"""Read-only SSH helper for the second RAKsmart VPS."""
import argparse
import base64
import hashlib
import importlib.util
import getpass
from pathlib import Path

HERE = Path(__file__).resolve().parent
OLD = HERE.parent / "raksmart-198.200.49.63" / "ssh_access.py"
spec = importlib.util.spec_from_file_location("old_ssh_access", str(OLD))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.HOST = "198.200.49.158"
mod.PORT = 62970
mod.USER = "root"
mod.FOLDER = HERE
mod.PASSWORD_FILE = HERE / "ssh-password.dpapi"
mod.HOST_KEYS = HERE / "ssh-known-hosts"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["init", "inspect"])
    args = parser.parse_args()
    if args.mode == "init":
        password = getpass.getpass("SSH password (input hidden): ")
        if not password:
            raise RuntimeError("Empty password")
        mod.PASSWORD_FILE.write_bytes(mod.dpapi(password.encode("utf-8")))
        print("Encrypted SSH credential stored for the current Windows account.")
    client = mod.connect()
    try:
        key = client.get_transport().get_remote_server_key()
        fp = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        print("CONNECTED", mod.HOST, "port", mod.PORT, "hostkey", key.get_name(), "SHA256:" + fp)
        command = r'''set -u
printf '%s\n' '--- OS ---'; cat /etc/os-release
printf '%s\n' '--- KERNEL/HOST ---'; uname -a; hostnamectl 2>/dev/null || true
printf '%s\n' '--- ID/TIME/UPTIME ---'; id; date -u; uptime
printf '%s\n' '--- MEMORY/DISK ---'; free -m; df -h /
printf '%s\n' '--- LISTENING SOCKETS ---'; ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null || true
printf '%s\n' '--- INTERFACES/ROUTES ---'; ip -br addr 2>/dev/null || true; ip route 2>/dev/null || route -n 2>/dev/null || true
printf '%s\n' '--- AVAILABLE TOOLS ---'; for tool in python3 python python2 curl wget openssl unzip tar systemctl firewall-cmd iptables nft getenforce; do command -v "$tool" || true; done
printf '%s\n' '--- FIREWALL ---'; systemctl is-active firewalld 2>/dev/null || true; systemctl is-enabled firewalld 2>/dev/null || true; iptables -S 2>/dev/null || true; firewall-cmd --state 2>/dev/null || true
printf '%s\n' '--- SYSTEMD ---'; systemctl --version 2>/dev/null | head -n 1 || true
printf '%s\n' '--- EXISTING PROXY FILES ---'; for path in /usr/local/bin/xray /usr/local/etc/xray/config.json /etc/systemd/system/xray.service /usr/local/bin/sing-box /etc/sing-box/config.json /usr/local/bin/hysteria /etc/hysteria/config.yaml; do if test -e "$path"; then ls -ld "$path"; fi; done
'''
        code, output, error = mod.execute(client, command, timeout=55)
        print(output)
        if error:
            print(error)
        if code:
            raise SystemExit(code)
    finally:
        client.close()


if __name__ == "__main__":
    main()
