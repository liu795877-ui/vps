"""Exercise REALITY over TCP 443, binding the test connection to physical WLAN."""

import argparse
import json
from pathlib import Path
import select
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone, timedelta

FOLDER = Path(__file__).resolve().parent
HOST = "198.200.49.63"
parser = argparse.ArgumentParser()
parser.add_argument('--ssh-tunnel', action='store_true',
                    help='Verify REALITY and egress via SSH while diagnosing cloud ingress.')
parser.add_argument('--single-check', action='store_true')
parser.add_argument('--speed-bytes',type=int,default=0,
                    help='Also run one bounded download throughput measurement.')
args = parser.parse_args()
ssh_client = None
if args.ssh_tunnel:
    from ssh_access import connect
    ssh_client = connect()
wifi = json.loads(subprocess.run(
    ["powershell.exe", "-NoProfile", "-Command",
     "Get-NetIPAddress -InterfaceAlias WLAN -AddressFamily IPv4 | "
     "Where-Object AddressState -eq Preferred | Select-Object -First 1 "
     "IPAddress,InterfaceIndex | ConvertTo-Json -Compress"],
    check=True, capture_output=True,
).stdout.decode("utf-8-sig"))

listener = socket.socket()
listener.bind(("127.0.0.1", 0))
listener.listen(8)
listener.settimeout(0.5)
relay_port = listener.getsockname()[1]
stop = threading.Event()
relay_errors = []


def forward(local):
    remote = None
    try:
        if ssh_client is not None:
            remote = ssh_client.get_transport().open_channel(
                'direct-tcpip', ('127.0.0.1', 443), local.getpeername(), timeout=15)
        else:
            remote = socket.socket()
            remote.settimeout(15)
            remote.setsockopt(socket.IPPROTO_IP, 31, socket.htonl(wifi["InterfaceIndex"]))
            remote.bind((wifi["IPAddress"], 0))
            remote.connect((HOST, 443))
            remote.settimeout(None)
        while not stop.is_set():
            readable, _, _ = select.select([local, remote], [], [], 0.5)
            for source in readable:
                data = source.recv(65536)
                if not data:
                    return
                target = remote if source is local else local
                target.sendall(data)
    except Exception as error:
        relay_errors.append(type(error).__name__ + ": " + str(error))
    finally:
        local.close()
        if remote is not None:
            remote.close()


def accept_connections():
    while not stop.is_set():
        try:
            local, _ = listener.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=forward, args=(local,), daemon=True).start()


threading.Thread(target=accept_connections, daemon=True).start()
reserved = socket.socket()
reserved.bind(("127.0.0.1", 0))
socks_port = reserved.getsockname()[1]
reserved.close()
client = json.loads((FOLDER / "client-test.private.json").read_text(encoding="utf-8"))
client['log']['loglevel'] = 'info'
client["inbounds"][0]["port"] = socks_port
client["outbounds"][0]["settings"]["vnext"][0].update(address="127.0.0.1", port=relay_port)
config = FOLDER / "client-test-direct.private.json"
config.write_text(json.dumps(client, indent=2), encoding="utf-8")
report = {"checked_at": datetime.now(timezone(timedelta(hours=8))).isoformat(timespec="seconds"),
          "server": HOST, "server_port": 443,
          "transport": "VLESS + REALITY + Vision",
          "test_path": ("Local Xray client -> SSH direct-tcpip channel -> VPS loopback:443"
                        if args.ssh_tunnel else
                        "Local Xray client -> local TCP relay bound to WLAN -> public VPS:443"),
          "public_port_verified": not args.ssh_tunnel,
          "checks": []}
process = None
try:
    with (FOLDER / "client-test.log").open("wb") as log:
        process = subprocess.Popen(
            [str(FOLDER / "artifacts/windows-64/xray.exe"), "run", "-config", str(config)],
            stdin=subprocess.DEVNULL, stdout=log, stderr=log,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        for attempt in range(30):
            if process.poll() is not None:
                raise RuntimeError("Temporary Xray client exited")
            try:
                with socket.create_connection(("127.0.0.1", socks_port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("Temporary client SOCKS listener did not start")
        prefix = ["C:/Windows/System32/curl.exe", "--proxy", f"socks5h://127.0.0.1:{socks_port}",
                  "--noproxy", "", "--connect-timeout", "20", "--max-time", "35", "--silent", "--show-error"]
        if args.speed_bytes:
            prefix.append('--ssl-no-revoke')
        checks = [
            ("exit_ip", "https://api.ipify.org"),
            ("google", "https://www.google.com/generate_204"),
            ("cloudflare", "https://www.cloudflare.com/cdn-cgi/trace"),
        ]
        checks = checks[:1] if args.single_check else checks
        if args.speed_bytes:
            checks.append(('download_speed','https://speed.cloudflare.com/__down?bytes='+str(args.speed_bytes)))
        for label, url in checks:
            extra = ['--output','NUL'] if label=='download_speed' else []
            result = subprocess.run(prefix + extra + ["--write-out", "\nHTTP_CODE:%{http_code}\nTIME_TOTAL:%{time_total}\nBYTES:%{size_download}\n", url],
                                    capture_output=True, timeout=40)
            output = result.stdout.decode("utf-8", errors="replace")
            body, _, metadata = output.rpartition("\nHTTP_CODE:")
            status, _, time_text = metadata.partition("\nTIME_TOTAL:")
            time_text, _, byte_text = time_text.partition('\nBYTES:')
            check = {"name": label, "url": url, "exit_code": result.returncode,
                     "http_status": status.strip(), "seconds": time_text.strip(),
                     "error": result.stderr.decode("utf-8", errors="replace").strip()}
            if label=='download_speed':
                check['actual_bytes']=int(float(byte_text.strip() or '0'))
                check['success']=result.returncode==0 and check['http_status']=='200' and check['actual_bytes']==args.speed_bytes
                check['mbps_observed']=round(check['actual_bytes']*8/max(float(time_text.strip() or '0'),.001)/1e6,3)
            if label == "exit_ip":
                check["actual_exit_ip"] = body.strip()
                check["matches_vps"] = body.strip() == HOST
            if label == "cloudflare":
                trace = dict(line.split("=", 1) for line in body.splitlines() if "=" in line)
                check["actual_exit_ip"] = trace.get("ip")
                check["location"] = trace.get("loc")
                check["matches_vps"] = trace.get("ip") == HOST
            report["checks"].append(check)
            print(json.dumps(check), flush=True)
        report["success"] = (
            report["checks"][0].get("matches_vps") is True
            and report["checks"][0]["http_status"] == "200"
            and (args.single_check or
                 (report["checks"][1]["http_status"] == "204"
                  and report["checks"][2].get("matches_vps") is True))
        )
        if args.speed_bytes:
            report['success']=report['success'] and report['checks'][-1].get('success') is True
finally:
    if process is not None and process.poll() is None:
        process.terminate()
        process.wait(timeout=10)
    stop.set()
    listener.close()
    if ssh_client is not None:
        ssh_client.close()
    report["relay_errors"] = relay_errors
    report_name = 'proxy-verification-ssh.json' if args.ssh_tunnel else 'proxy-verification.json'
    if args.speed_bytes:
        report_name='speed-bound-xray-download.json'
    (FOLDER / report_name).write_text(json.dumps(report, indent=2), encoding="utf-8")
if not report.get("success"):
    raise SystemExit("Proxy verification did not pass all checks")
print("SUCCESS: Real client requests used the VPS public exit IP.")
