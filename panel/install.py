"""Install the private panel and add its route to the existing HTTPS site."""

import argparse
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit
from urllib.request import urlopen

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from panel.server import Manager, atomic_write
import configure_reality as base

TARGET = Path("/opt/vps-panel")
DATA = Path("/var/lib/vps-panel")
CADDY = Path("/etc/caddy/Caddyfile")
FRAGMENT = Path("/etc/caddy/vps-panel.caddy")
UNIT = Path("/etc/systemd/system/vps-panel.service")
PORT = 18787


def run(args, *, check=True, timeout=90):
    result = subprocess.run(args, capture_output=True, text=True, check=False, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError("Deployment check failed: " + Path(args[0]).name)
    return result


def install(public_ip, origin, source_profile):
    if os.geteuid() != 0:
        raise RuntimeError("Run the installer with sudo.")
    public_ip = base.validate_ip(public_ip)
    parsed = urlsplit(origin)
    host = parsed.hostname
    if parsed.scheme != "https" or not host or not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        raise RuntimeError("An existing HTTPS hostname is required.")
    if TARGET.is_symlink() or DATA.is_symlink() or CADDY.is_symlink() or UNIT.is_symlink():
        raise RuntimeError("Refusing a symbolic-link deployment destination.")
    if TARGET.exists() and not (TARGET / "install-marker.json").exists():
        raise RuntimeError("The panel directory is already used by another application.")
    if UNIT.exists() and "Managed by Private Node Console" not in UNIT.read_text():
        raise RuntimeError("An unmanaged service already uses the panel service name.")
    if not UNIT.exists():
        with socket.socket() as stream:
            stream.bind(("127.0.0.1", PORT))
    source = Path(__file__).resolve().parent.parent
    TARGET.mkdir(parents=True, exist_ok=True)
    paths = [
        "configure_reality.py", "configure_static_exits.py", "test_configure_reality.py",
        "test_configure_static_exits.py", "panel/__init__.py", "panel/server.py",
        "panel/test_panel.py", "panel/web/index.html", "panel/web/style.css",
        "panel/web/app.js", "panel/web/mark.svg",
        "panel/routing.py", "panel/node_info.py", "panel/services-routing.json", "panel/rules/domestic-dns.yaml",
    ]
    for relative in paths:
        target = TARGET / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / relative, target)
        os.chmod(target, 0o644)
    atomic_write(TARGET / "install-marker.json", b'{"application":"Private Node Console"}\n')
    environment = os.environ.copy()
    environment["XRAY_TEST_BINARY"] = "/usr/local/bin/xray"
    checks = subprocess.run(
        [sys.executable, "-m", "unittest", "test_configure_reality", "test_configure_static_exits", "panel.test_panel"],
        cwd=TARGET, env=environment, capture_output=True, text=True, timeout=120,
    )
    if checks.returncode:
        raise RuntimeError("Linux application/core verification failed; HTTPS routes were not changed.")
    print("Linux backend, permission, rollback and official-core tests passed.", flush=True)
    DATA.mkdir(exist_ok=True)
    os.chmod(DATA, 0o700)
    auth = DATA / "auth.private.json"
    if not auth.exists():
        atomic_write(auth, (source / "auth-seed.private.json").read_bytes())
    Manager(DATA, public_ip, base.CONFIG, source_profile, origin=origin)
    unit = f"""# Managed by Private Node Console
[Unit]
Description=Private VPS Node Console
After=network-online.target xray.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory={TARGET}
ExecStart=/usr/bin/python3 {TARGET}/panel/server.py --directory {DATA} --public-ip {public_ip} --origin {origin} --port {PORT}
Restart=on-failure
RestartSec=2
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ReadWritePaths={DATA} /usr/local/etc/xray
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER
TasksMax=64
MemoryMax=256M

[Install]
WantedBy=multi-user.target
"""
    atomic_write(UNIT, unit.encode())
    os.chmod(UNIT, 0o644)
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "--now", "vps-panel.service"])
    run(["systemctl", "restart", "vps-panel.service"])
    for _ in range(30):
        try:
            with urlopen(f"http://127.0.0.1:{PORT}/api/session", timeout=1) as response:
                if b'"authenticated"' in response.read():
                    break
        except OSError:
            time.sleep(0.3)
    else:
        raise RuntimeError("The panel worker did not start; HTTPS routes were not changed.")

    original = CADDY.read_bytes()
    original_mode = CADDY.stat().st_mode & 0o777
    old_fragment = FRAGMENT.read_bytes() if FRAGMENT.exists() else None
    text = original.decode()
    import_line = "    import /etc/caddy/vps-panel.caddy"
    if import_line not in text:
        match = re.search(r"(?m)^\s*" + re.escape(host) + r"\s*\{[^\n]*\n", text)
        if not match:
            raise RuntimeError("The expected HTTPS host block was not found; no Caddy file replaced.")
        text = text[:match.end()] + import_line + "\n" + text[match.end():]
    fragment = f"""# Managed by Private Node Console
redir /node-console /node-console/ 308
handle_path /node-console/* {{
    request_body {{
        max_size 64KB
    }}
    reverse_proxy 127.0.0.1:{PORT} {{
        header_up X-Real-IP {{remote_host}}
    }}
}}
"""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup = CADDY.with_name("Caddyfile.before-panel-" + stamp + ".private.backup")
    candidate = CADDY.with_name("Caddyfile.panel-candidate-" + stamp)
    replaced = False
    try:
        atomic_write(backup, original)
        atomic_write(FRAGMENT, fragment.encode())
        os.chmod(FRAGMENT, 0o644)
        atomic_write(candidate, text.encode())
        os.chmod(candidate, original_mode)
        run(["caddy", "validate", "--config", str(candidate), "--adapter", "caddyfile"])
        if CADDY.read_bytes() != original:
            raise RuntimeError("Caddy configuration changed concurrently; update stopped.")
        os.replace(candidate, CADDY)
        replaced = True
        run(["systemctl", "reload", "caddy"])
    except BaseException:
        if replaced:
            atomic_write(CADDY, original)
            os.chmod(CADDY, original_mode)
        if old_fragment is not None:
            atomic_write(FRAGMENT, old_fragment)
            os.chmod(FRAGMENT, 0o644)
        else:
            FRAGMENT.unlink(missing_ok=True)
        if replaced:
            run(["systemctl", "reload", "caddy"], check=False)
        raise
    finally:
        candidate.unlink(missing_ok=True)
    for service in ("xray.service", "caddy.service", "vps-panel.service"):
        run(["systemctl", "is-active", "--quiet", service])
    print("DEPLOYED: " + origin + "/node-console/", flush=True)
    print("The existing Xray node is active; no proxy credentials were printed.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-ip", required=True)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--source-profile", default="/home/ubuntu/clash-reality.yaml")
    args = parser.parse_args()
    try:
        install(args.public_ip, args.origin, args.source_profile)
    except Exception as error:
        print("DEPLOYMENT STOPPED: " + str(error), file=sys.stderr)
        sys.exit(1)
