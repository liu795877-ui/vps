"""Private SSH access for this VPS; password is stored with Windows DPAPI."""

import argparse
import base64
import ctypes
from ctypes import wintypes
import getpass
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / ".runtime" / "ssh"))
import paramiko

HOST = "198.200.49.158"
PORT = 62970
USER = "root"
FOLDER = Path(__file__).resolve().parent
PASSWORD_FILE = FOLDER / "ssh-password.dpapi"
HOST_KEYS = FOLDER / "ssh-known-hosts"


class DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def dpapi(data, *, decrypt=False):
    buffer = ctypes.create_string_buffer(data)
    source = DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte)))
    target = DataBlob()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    if decrypt:
        ok = crypt32.CryptUnprotectData(ctypes.byref(source), None, None, None,
                                      None, 1, ctypes.byref(target))
    else:
        ok = crypt32.CryptProtectData(ctypes.byref(source), "RAKsmart SSH", None,
                                    None, None, 1, ctypes.byref(target))
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(target.pbData, target.cbData)
    finally:
        kernel32.LocalFree(target.pbData)


def connect():
    if not PASSWORD_FILE.exists():
        raise RuntimeError("SSH password has not been initialized")
    password = dpapi(PASSWORD_FILE.read_bytes(), decrypt=True).decode("utf-8")
    client = paramiko.SSHClient()
    if HOST_KEYS.exists():
        client.load_host_keys(str(HOST_KEYS))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    network_info = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command",
         "Get-NetIPAddress -InterfaceAlias WLAN -AddressFamily IPv4 | "
         "Where-Object AddressState -eq Preferred | Select-Object -First 1 "
         "IPAddress,InterfaceIndex | ConvertTo-Json -Compress"],
        capture_output=True, timeout=15, check=True,
    )
    wifi = json.loads(network_info.stdout.decode("utf-8-sig"))
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.settimeout(15)
    connection.setsockopt(socket.IPPROTO_IP, 31, socket.htonl(wifi["InterfaceIndex"]))
    connection.bind((wifi["IPAddress"], 0))
    connection.connect((HOST, PORT))
    client.connect(HOST, port=PORT, username=USER, password=password, sock=connection,
                   allow_agent=False, look_for_keys=False, timeout=15,
                   auth_timeout=15, banner_timeout=15)
    client.get_transport().set_keepalive(20)
    if not HOST_KEYS.exists():
        client.save_host_keys(str(HOST_KEYS))
    return client


def execute(client, command, *, timeout=30):
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    stdin.close()
    output = stdout.read().decode("utf-8", errors="replace")
    error = stderr.read().decode("utf-8", errors="replace")
    return stdout.channel.recv_exit_status(), output, error


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["init", "inspect", "exec"])
    parser.add_argument("--command-file")
    args = parser.parse_args()
    if args.mode == "init":
        password = getpass.getpass("SSH password (input hidden): ")
        if not password:
            raise RuntimeError("Empty password")
        PASSWORD_FILE.write_bytes(dpapi(password.encode("utf-8")))
        print("Encrypted SSH credential stored for the current Windows account.")
    client = connect()
    try:
        key = client.get_transport().get_remote_server_key()
        fingerprint = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        print("CONNECTED", HOST, "port", PORT, "hostkey", key.get_name(), "SHA256:" + fingerprint)
        if args.mode == "init":
            return
        if args.mode == "exec":
            if not args.command_file:
                parser.error("exec requires --command-file")
            command = Path(args.command_file).read_text(encoding="utf-8-sig")
        else:
            command = """set -u
cat /etc/os-release
uname -a
id
date -u
uptime
free -m
df -h /
ss -lntup
printf '\\nAvailable commands\\n'
for tool in python3 python curl wget openssl unzip tar systemctl firewall-cmd iptables getenforce; do command -v "$tool" || true; done
printf '\\nFirewall state\\n'
systemctl is-active firewalld || true
systemctl is-enabled firewalld || true
iptables -S || true
printf '\\nExisting proxy files\\n'
for path in /usr/local/bin/xray /usr/local/etc/xray/config.json /etc/systemd/system/xray.service /usr/local/bin/sing-box /etc/sing-box/config.json; do if test -e "$path"; then ls -ld "$path"; fi; done
printf '\\nTLS target checks\\n'
for host in www.microsoft.com www.cloudflare.com www.apple.com; do printf '%s ' "$host"; timeout 12 openssl s_client -connect "$host:443" -servername "$host" -tls1_3 </dev/null 2>/dev/null | awk '/Protocol|Cipher|Verify return code/ {print}'; done
"""
        code, output, error = execute(client, command, timeout=55)
        print(output)
        if error:
            print(error, file=sys.stderr)
        if code:
            print("REMOTE_EXIT", code)
            raise SystemExit(code)
    finally:
        client.close()


if __name__ == "__main__":
    main()
