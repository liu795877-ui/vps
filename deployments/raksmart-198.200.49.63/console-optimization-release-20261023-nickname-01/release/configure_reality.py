"""Configure a fresh official Xray installation without touching other services."""

import base64
import ipaddress
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

PORT = 443
TARGET = "www.microsoft.com"
XRAY = Path("/usr/local/bin/xray")
CONFIG = Path("/usr/local/etc/xray/config.json")
PRIVATE_RANGES = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
    "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
    "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
]


def command(args, *, timeout=30, check=True):
    result = subprocess.run(
        args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True, timeout=timeout, check=False
    )
    if check and result.returncode:
        # Do not echo command output: it could contain generated credentials.
        raise RuntimeError(f"Command failed: {Path(args[0]).name} {args[1]}")
    return result


def unlink_if_exists(path):
    """Python 3.6 equivalent of Path.unlink(missing_ok=True)."""
    try:
        Path(path).unlink()
    except FileNotFoundError:
        pass


def parse_keys(output):
    fields = {}
    for line in output.splitlines():
        label, separator, value = line.partition(":")
        if separator:
            fields[re.sub(r"[^A-Za-z0-9]", "", label).lower()] = value.strip()
    private = fields.get("privatekey")
    public = (
        fields.get("password")
        or fields.get("passwordpublickey")
        or fields.get("publickey")
    )
    for value in (private, public):
        if not value or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
            raise RuntimeError("Unrecognized Xray x25519 output; nothing installed.")
        try:
            decoded = base64.urlsafe_b64decode(value + "=")
        except ValueError as error:
            raise RuntimeError("Invalid X25519 key format.") from error
        if len(decoded) != 32:
            raise RuntimeError("Invalid X25519 key length.")
    return private, public


def validate_ip(value):
    address = ipaddress.IPv4Address(value.strip())
    if not address.is_global:
        raise ValueError("Enter the VPS public IPv4 address, not a private address.")
    return str(address)


def server_config(user_id, private, short_id, *, target=TARGET):
    return {
        "log": {"loglevel": "warning"},
        "dns": {
            "queryStrategy": "UseIPv4",
            "servers": ["https+local://1.1.1.1/dns-query", "https+local://1.0.0.1/dns-query"],
        },
        "inbounds": [{
            "tag": "reality-in",
            "listen": "0.0.0.0",
            "port": PORT,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": user_id, "flow": "xtls-rprx-vision"}],
                "decryption": "none",
            },
            "streamSettings": {
                "network": "raw",
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "target": f"{target}:443",
                    "xver": 0,
                    "serverNames": [target],
                    "privateKey": private,
                    "shortIds": [short_id],
                },
            },
        }],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [{
                "type": "field",
                "ip": PRIVATE_RANGES,
                "outboundTag": "block",
            }],
        },
    }


def client_profile(server_ip, user_id, public, short_id, *, target=TARGET):
    # JSON-quoted strings are also valid YAML strings.
    quote = json.dumps
    return f"""# PRIVATE FILE: contains a usable node credential.
# Example rules only: GitHub and the IP check use VPS; other sites are direct.
mixed-port: 7890
allow-lan: false
mode: rule
log-level: warning
ipv6: false
proxies:
  - name: TOKYO-VPS
    type: vless
    server: {quote(server_ip)}
    port: {PORT}
    uuid: {quote(user_id)}
    network: tcp
    udp: true
    tls: true
    flow: xtls-rprx-vision
    servername: {quote(target)}
    client-fingerprint: chrome
    reality-opts:
      public-key: {quote(public)}
      short-id: {quote(short_id)}
proxy-groups:
  - name: VPS-SELECT
    type: select
    proxies:
      - TOKYO-VPS
      - DIRECT
rules:
  - DOMAIN,api.ipify.org,VPS-SELECT
  - DOMAIN-SUFFIX,github.com,VPS-SELECT
  - DOMAIN-SUFFIX,githubusercontent.com,VPS-SELECT
  - DOMAIN-SUFFIX,githubassets.com,VPS-SELECT
  - MATCH,DIRECT
"""


def write_private(path, content, uid, gid, mode=0o600):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, mode)
    try:
        os.fchmod(fd, mode)
        os.fchown(fd, uid, gid)
        with os.fdopen(fd, "wb") as stream:
            fd = None
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if fd is not None:
            os.close(fd)


def main():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Run this on the VPS through sudo, not on Windows.")

    import grp
    import pwd

    os.umask(0o077)
    server_ip = validate_ip(os.environ.get("VPS_PUBLIC_IP", ""))
    if not XRAY.is_file() or not CONFIG.parent.is_dir():
        raise RuntimeError("The official Xray installation was not found.")
    if CONFIG.is_symlink():
        raise RuntimeError("Refusing to replace a symbolic-link configuration.")
    original = CONFIG.read_bytes() if CONFIG.exists() else None
    original_stat = CONFIG.stat() if CONFIG.exists() else None
    if original and original.strip() not in (b"", b"{}"):
        raise RuntimeError("Existing Xray configuration detected; refusing overwrite.")

    user_name = os.environ.get("SUDO_USER", "")
    if not user_name or user_name == "root":
        raise RuntimeError("Run sudo from your regular Ubuntu login account.")
    owner = pwd.getpwnam(user_name)
    profile = Path(owner.pw_dir) / "clash-reality.yaml"
    if profile.exists() or profile.is_symlink():
        raise RuntimeError("clash-reality.yaml already exists; refusing overwrite.")

    exec_start = command(
        ["systemctl", "show", "xray.service", "-p", "ExecStart", "--value"]
    ).stdout
    if str(CONFIG) not in exec_start or "-confdir" in exec_start:
        raise RuntimeError("Unexpected Xray service configuration; refusing changes.")
    service_user = command(
        ["systemctl", "show", "xray.service", "-p", "User", "--value"]
    ).stdout.strip()
    service_group = command(
        ["systemctl", "show", "xray.service", "-p", "Group", "--value"]
    ).stdout.strip()
    service_gid = (
        grp.getgrnam(service_group).gr_gid if service_group
        else pwd.getpwnam(service_user or "root").pw_gid
    )
    was_active = command(
        ["systemctl", "is-active", "--quiet", "xray.service"], check=False
    ).returncode == 0

    # This only probes whether 443 is free; no firewall rule is changed.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("0.0.0.0", PORT))

    private, public = parse_keys(command([str(XRAY), "x25519"]).stdout)
    user_id, short_id = str(uuid.uuid4()), secrets.token_hex(8)
    payload = json.dumps(
        server_config(user_id, private, short_id), indent=2
    ).encode("utf-8") + b"\n"
    descriptor, name = tempfile.mkstemp(
        prefix=".reality-check-", suffix=".json", dir=CONFIG.parent
    )
    candidate = Path(name)
    backup = None
    installed = False
    profile_created = False
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o640)
            os.fchown(stream.fileno(), 0, service_gid)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        command([str(XRAY), "run", "-test", "-config", str(candidate)])
        if original is not None:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            backup = CONFIG.with_name(f"config.before-reality-{stamp}.json")
            write_private(backup, original, 0, 0)
        write_private(
            profile, client_profile(server_ip, user_id, public, short_id).encode(),
            owner.pw_uid, owner.pw_gid,
        )
        profile_created = True
        os.replace(candidate, CONFIG)
        installed = True
        command(["systemctl", "restart", "xray.service"])
        for attempt in range(20):
            active = command(
                ["systemctl", "is-active", "--quiet", "xray.service"], check=False
            ).returncode == 0
            if active:
                try:
                    with socket.create_connection(("127.0.0.1", PORT), timeout=0.5):
                        break
                except OSError:
                    pass
            time.sleep(0.25)
        else:
            raise RuntimeError("Xray did not start listening; restoring old config.")
        command(["systemctl", "enable", "xray.service"])
    except BaseException:
        if installed:
            if backup is not None:
                os.replace(backup, CONFIG)
                os.chmod(CONFIG, original_stat.st_mode & 0o777)
                os.chown(CONFIG, original_stat.st_uid, original_stat.st_gid)
            else:
                unlink_if_exists(CONFIG)
            command(
                ["systemctl", "restart" if was_active else "stop", "xray.service"],
                check=False,
            )
        if profile_created:
            unlink_if_exists(profile)
        raise
    finally:
        unlink_if_exists(candidate)

    print("SUCCESS: Xray is active and listening on TCP 443 locally.")
    print("This is NOT an end-to-end client connection test.")
    print("Private client profile:", profile)
    print("Credentials were NOT printed. Do not post the YAML in chat.")
    print("Caddy, Docker and firewall settings were NOT changed.")
    print("Next: allow inbound TCP 443 in the cloud firewall, then import YAML.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"STOPPED: {error}", file=sys.stderr)
        sys.exit(1)
