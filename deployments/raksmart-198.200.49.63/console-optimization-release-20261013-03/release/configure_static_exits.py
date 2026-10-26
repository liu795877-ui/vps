"""Add tested SOCKS5 exits to the existing private REALITY deployment."""

import copy
import getpass
import ipaddress
import json
import os
import re
import shutil
import socket
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import configure_reality as base


def validate_label(value):
    label = value.strip().upper()
    if not re.fullmatch(r"[A-Z0-9][A-Z0-9_-]{0,23}", label):
        raise ValueError("Use 1-24 letters, digits, underscores or hyphens for a label.")
    return label


def validate_endpoint(address, port, resolver=socket.getaddrinfo):
    address = address.strip()
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        if len(address) > 253 or not all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
            for part in address.split(".")
        ):
            raise ValueError("Enter a hostname or public IP, without a URL or credentials.")
    else:
        if not parsed.is_global:
            raise ValueError("The SOCKS5 endpoint must use public addresses.")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("The SOCKS5 port must be between 1 and 65535.")
    try:
        resolved = resolver(address, port, type=socket.SOCK_STREAM)
    except OSError as error:
        raise ValueError("The SOCKS5 endpoint could not be resolved.") from error
    if not resolved or any(
        not ipaddress.ip_address(item[4][0].split("%", 1)[0]).is_global
        for item in resolved
    ):
        raise ValueError("The SOCKS5 endpoint resolved to a non-public address.")
    return address


def validate_credentials(username, password):
    if bool(username) != bool(password):
        raise ValueError("Supply both SOCKS5 username and password, or leave both empty.")
    if ":" in username:
        raise ValueError("The curl preflight does not support a colon in the username.")
    for value in (username, password):
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("SOCKS5 credentials cannot contain control characters.")
        if len(value.encode("utf-8")) > 255:
            raise ValueError("SOCKS5 credentials exceed the protocol length limit.")


def curl_probe_config(exit_spec):
    validate_credentials(exit_spec["username"], exit_spec["password"])

    def quote(value):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'

    address = exit_spec["address"]
    if ":" in address:
        address = f"[{address}]"
    lines = [
        "proxy = " + quote(f"socks5h://{address}:{exit_spec['port']}"),
        'noproxy = ""',
        'url = "https://api.ipify.org"',
        "fail", "silent", "connect-timeout = 8", "max-time = 20",
    ]
    if exit_spec["username"]:
        lines.append("proxy-user = " + quote(
            exit_spec["username"] + ":" + exit_spec["password"]
        ))
    return "\n".join(lines) + "\n"


def probe_exit(exit_spec):
    import subprocess

    curl = shutil.which("curl")
    if not curl:
        raise RuntimeError("curl is required for the SOCKS5 preflight; nothing changed.")
    # Credentials go through stdin, never through argv or shell history.
    try:
        result = subprocess.run(
            [curl, "--disable", "--config", "-"],
            input=curl_probe_config(exit_spec), stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
            timeout=25, check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("SOCKS5 preflight timed out; nothing changed.") from error
    if result.returncode:
        raise RuntimeError(
            "SOCKS5 preflight failed. Check endpoint, credentials, IP allowlist "
            "and VPS connectivity; nothing changed."
        )
    try:
        observed = ipaddress.ip_address(result.stdout.strip())
    except ValueError as error:
        raise RuntimeError("SOCKS5 preflight did not return an IP; nothing changed.") from error
    if not observed.is_global:
        raise RuntimeError("SOCKS5 preflight did not return a public IP; nothing changed.")
    return str(observed)


def inspect_base(config, profile_text, server_ip):
    try:
        inbound = config["inbounds"][0]
        old_client = inbound["settings"]["clients"][0]
        user_id = old_client["id"]
        uuid.UUID(user_id)
        reality = inbound["streamSettings"]["realitySettings"]
        short_id = reality["shortIds"][0]
        server_name = reality["serverNames"][0]
        if (not isinstance(server_name, str) or len(server_name) > 253
                or "." not in server_name or not all(
                    re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
                    for part in server_name.split("."))):
            raise ValueError
        expected = base.server_config(user_id, reality["privateKey"], short_id, target=server_name)
        if config != expected:
            raise ValueError
        match = re.search(r'^\s+public-key: ("[^"\n]+")\s*$', profile_text, re.M)
        public = json.loads(match.group(1)) if match else ""
        base.parse_keys(f"PrivateKey: {reality['privateKey']}\nPublicKey: {public}\n")
        if profile_text.strip() != base.client_profile(
            server_ip, user_id, public, short_id, target=server_name
        ).strip():
            raise ValueError
    except (KeyError, IndexError, TypeError, ValueError, RuntimeError) as error:
        raise RuntimeError(
            "The existing server/client files do not match this workspace's base "
            "REALITY setup. Refusing to replace an unknown configuration."
        ) from error
    return public, short_id


def extend_config(config, exits):
    if not 1 <= len(exits) <= 8:
        raise ValueError("Configure between 1 and 8 exits.")
    candidate = copy.deepcopy(config)
    nodes = []
    labels = set()
    for exit_spec in exits:
        label = validate_label(exit_spec["label"])
        if label in labels:
            raise ValueError("Exit labels must be unique.")
        labels.add(label)
        validate_credentials(exit_spec["username"], exit_spec["password"])
        identity = str(uuid.uuid4())
        email = f"static-{label.lower()}@exits.invalid"
        tag = f"static-{label}"
        candidate["inbounds"][0]["settings"]["clients"].append({
            "id": identity, "email": email, "flow": "xtls-rprx-vision",
        })
        server = {"address": exit_spec["address"], "port": exit_spec["port"]}
        if exit_spec["username"]:
            server["users"] = [{
                "user": exit_spec["username"], "pass": exit_spec["password"],
            }]
        # This schema is supported by the already validated Xray 26.3.27 core.
        candidate["outbounds"].append({
            "tag": tag, "protocol": "socks", "settings": {"servers": [server]},
        })
        candidate["routing"]["rules"].extend([
            {"type": "field", "user": [email], "network": "udp", "outboundTag": "block"},
            {"type": "field", "user": [email], "network": "tcp", "outboundTag": tag},
        ])
        nodes.append({"name": f"STATIC-{label}", "id": identity})
    return candidate, nodes


def client_profile(server_ip, public, short_id, nodes, *, server_name=base.TARGET, server_port=None):
    fragments = []
    header = None
    for node in nodes:
        profile = base.client_profile(server_ip, node["id"], public, short_id, target=server_name)
        if server_port is not None:
            if isinstance(server_port, bool) or not isinstance(server_port, int) or not 1 <= server_port <= 65535:
                raise ValueError("Invalid client entry port.")
            profile = profile.replace("\n    port: " + str(base.PORT) + "\n",
                                      "\n    port: " + str(server_port) + "\n", 1)
        prefix, remaining = profile.split("\nproxies:\n", 1)
        fragment, _ = remaining.split("\nproxy-groups:\n", 1)
        header = prefix
        fragments.append(fragment.replace(
            "name: TOKYO-VPS", "name: " + json.dumps(node["name"]), 1
        ).replace("udp: true", "udp: false", 1))
    if not fragments:
        raise ValueError("At least one exit is required.")
    selection = "\n".join("      - " + json.dumps(node["name"]) for node in nodes)
    return header + "\nproxies:\n" + "\n".join(fragments) + f"""
proxy-groups:
  - name: STATIC-SELECT
    type: select
    proxies:
{selection}
rules:
  - DOMAIN,api.ipify.org,STATIC-SELECT
  - DOMAIN-SUFFIX,github.com,STATIC-SELECT
  - DOMAIN-SUFFIX,githubusercontent.com,STATIC-SELECT
  - DOMAIN-SUFFIX,githubassets.com,STATIC-SELECT
  - MATCH,DIRECT
"""


def wait_for_listener(runner=base.command, *, service_name="xray.service", port=base.PORT):
    for _ in range(20):
        active = runner(
            ["systemctl", "is-active", "--quiet", service_name], check=False
        ).returncode == 0
        if active:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    return
            except OSError:
                pass
        time.sleep(0.25)
    raise RuntimeError("The selected Xray instance did not become active and listen on its entry port.")


def apply_update(config_path, original, payload, profile_path, profile_text,
                 uid, gid, service_gid, runner=base.command, *, service_name="xray.service", port=base.PORT,
                 config_mode=0o640):
    if config_path.is_symlink() or profile_path.exists() or profile_path.is_symlink():
        raise RuntimeError("A destination is unsafe or already exists; nothing changed.")
    original_stat = config_path.stat()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    candidate = config_path.with_name(f"config.static-candidate-{stamp}.private.json")
    backup = config_path.with_name(f"config.before-static-{stamp}.private.json")
    restore = config_path.with_name(f"config.static-restore-{stamp}.private.json")
    client_bytes = profile_text.encode("utf-8")
    installed = False
    profile_created = False
    try:
        base.write_private(candidate, payload, 0, service_gid, config_mode)
        runner([str(base.XRAY), "run", "-test", "-config", str(candidate)])
        if config_path.is_symlink() or config_path.read_bytes() != original:
            raise RuntimeError("Existing config changed during preparation; nothing replaced.")
        base.write_private(backup, original, 0, 0)
        base.write_private(profile_path, client_bytes, uid, gid)
        profile_created = True
        if config_path.is_symlink() or config_path.read_bytes() != original:
            raise RuntimeError("Existing config changed during preparation; nothing replaced.")
        os.replace(candidate, config_path)
        installed = True
        runner(["systemctl", "restart", service_name])
        wait_for_listener(runner, service_name=service_name, port=port)
    except BaseException:
        try:
            if installed:
                if config_path.is_symlink() or config_path.read_bytes() != payload:
                    raise RuntimeError(
                        "Concurrent config change detected; automatic restore stopped. "
                        "Private backup: " + str(backup)
                    )
                base.write_private(
                    restore, original, original_stat.st_uid, original_stat.st_gid,
                    original_stat.st_mode & 0o777,
                )
                os.replace(restore, config_path)
                try:
                    runner(["systemctl", "restart", service_name])
                    wait_for_listener(runner, service_name=service_name, port=port)
                except Exception as error:
                    raise RuntimeError(
                        "Original config restored but Xray recovery failed. "
                        "Private backup: " + str(backup)
                    ) from error
        finally:
            if profile_created and not profile_path.is_symlink():
                if profile_path.exists() and profile_path.read_bytes() == client_bytes:
                    profile_path.unlink()
        raise
    finally:
        _unlink_if_exists(candidate)
        _unlink_if_exists(restore)
    return backup


def prompt(text, default=None, hidden=False):
    if hidden:
        return getpass.getpass(text)
    with open("/dev/tty", "r+", encoding="utf-8") as terminal:
        terminal.write(text)
        terminal.flush()
        answer = terminal.readline()
    if not answer:
        raise RuntimeError("Interactive terminal input ended; stopped.")
    answer = answer.strip()
    return default if not answer and default is not None else answer


def main():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Run this on the VPS through sudo, not on Windows.")
    import grp
    import pwd

    os.umask(0o077)
    try:
        server_ip = base.validate_ip(os.environ.get("VPS_PUBLIC_IP", ""))
    except ValueError as error:
        raise ValueError("Enter the VPS public IPv4 address, not a password.") from error
    user_name = os.environ.get("SUDO_USER", "")
    if not user_name or user_name == "root":
        raise RuntimeError("Run sudo from the regular Ubuntu login account.")
    owner = pwd.getpwnam(user_name)
    old_profile = Path(owner.pw_dir) / "clash-reality.yaml"
    new_profile = Path(owner.pw_dir) / "clash-static-exits.yaml"
    if not base.XRAY.is_file() or not base.CONFIG.is_file() or not old_profile.is_file():
        raise RuntimeError("Base REALITY server/client files are missing; configure the base first.")
    if base.CONFIG.is_symlink() or old_profile.is_symlink():
        raise RuntimeError("Refusing symbolic-link base files.")
    if new_profile.exists() or new_profile.is_symlink():
        raise RuntimeError("Static exit profile already exists; refusing a duplicate setup.")
    original = base.CONFIG.read_bytes()
    try:
        config = json.loads(original)
    except (ValueError, UnicodeError) as error:
        raise RuntimeError("The base config could not be parsed; nothing changed.") from error
    public, short_id = inspect_base(config, old_profile.read_text(), server_ip)
    exec_start = base.command([
        "systemctl", "show", "xray.service", "-p", "ExecStart", "--value",
    ]).stdout
    if str(base.CONFIG) not in exec_start or "-confdir" in exec_start:
        raise RuntimeError("Unexpected Xray service configuration; refusing changes.")
    if base.command([
        "systemctl", "is-active", "--quiet", "xray.service",
    ], check=False).returncode:
        raise RuntimeError("The base Xray service is not active; fix the base first.")
    service_user = base.command([
        "systemctl", "show", "xray.service", "-p", "User", "--value",
    ]).stdout.strip()
    service_group = base.command([
        "systemctl", "show", "xray.service", "-p", "Group", "--value",
    ]).stdout.strip()
    service_gid = (
        grp.getgrnam(service_group).gr_gid if service_group
        else pwd.getpwnam(service_user or "root").pw_gid
    )
    try:
        count = int(prompt("Number of static SOCKS5 exits [1] (1-8): ", "1"))
    except ValueError as error:
        raise ValueError("The exit count must be a number between 1 and 8.") from error
    if not 1 <= count <= 8:
        raise ValueError("Configure between 1 and 8 exits.")
    exits = []
    seen = set()
    for index in range(1, count + 1):
        print(f"Configuring SOCKS5 exit {index}/{count}.")
        label = validate_label(prompt(f"Exit label [EXIT{index}]: ", f"EXIT{index}"))
        if label in seen:
            raise ValueError("Exit labels must be unique.")
        seen.add(label)
        address = prompt("SOCKS5 server hostname or public IP (no URL): ")
        try:
            port = int(prompt("SOCKS5 port [1080]: ", "1080"))
        except ValueError as error:
            raise ValueError("The SOCKS5 port must be a number between 1 and 65535.") from error
        address = validate_endpoint(address, port)
        username = prompt("SOCKS5 username (hidden; empty for no authentication): ", hidden=True)
        password = prompt("SOCKS5 password (hidden): ", hidden=True) if username else ""
        validate_credentials(username, password)
        exit_spec = {
            "label": label, "address": address, "port": port,
            "username": username, "password": password,
        }
        observed = probe_exit(exit_spec)
        expected = prompt("Expected exit IP (blank to accept observed address): ")
        if expected:
            try:
                expected = str(ipaddress.ip_address(expected))
            except ValueError as error:
                raise ValueError("Expected exit IP is invalid.") from error
            if expected != observed:
                raise RuntimeError("Observed SOCKS5 exit did not match expected IP; nothing changed.")
        print(f"PREFLIGHT OK: STATIC-{label} observed exit {observed}")
        exits.append(exit_spec)
    candidate, nodes = extend_config(config, exits)
    profile = client_profile(server_ip, public, short_id, nodes,
                             server_name=config["inbounds"][0]["streamSettings"]["realitySettings"]["serverNames"][0])
    payload = json.dumps(candidate, indent=2).encode("utf-8") + b"\n"
    backup = apply_update(
        base.CONFIG, original, payload, new_profile, profile,
        owner.pw_uid, owner.pw_gid, service_gid,
    )
    print("SUCCESS: static exit config installed; Xray active on TCP 8443 locally.")
    print("SOCKS5 exits passed preflight; an actual Clash connection is still required.")
    print("Private client profile:", new_profile)
    print("Private original-config backup:", backup)
    print("Import the NEW profile, select an exit in STATIC-SELECT, then check api.ipify.org.")
    print("This profile routes GitHub and api.ipify.org only; other sites are DIRECT.")



def _unlink_if_exists(path):
    try:
        path.unlink()
    except FileNotFoundError:
        pass

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("STOPPED: cancelled.", file=sys.stderr)
        sys.exit(1)
    except Exception as error:
        print(f"STOPPED: {error}", file=sys.stderr)
        sys.exit(1)
