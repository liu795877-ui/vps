"""Sequential ICMP comparison of official GreenCloud US test addresses."""

import argparse
import csv
import json
import re
import statistics
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path


SHANGHAI = timezone(timedelta(hours=8))
TARGETS = [
    ("Dallas", "达拉斯", "TX", "64.44.147.6"),
    ("Chicago DC1", "芝加哥 DC1", "IL1", "167.88.10.4"),
    ("Kansas City", "堪萨斯城", "MO", "72.18.215.71"),
    ("Jacksonville", "杰克逊维尔", "JAX", "64.44.162.14"),
    ("Buffalo", "布法罗", "NY", "96.9.249.58"),
    ("Staten Island", "纽约 Staten Island", "NYC", "108.171.198.77"),
    ("Los Angeles", "洛杉矶", "LA", "64.185.232.162"),
    ("San Jose", "圣何塞", "SJC", "173.249.206.247"),
    ("Phoenix", "凤凰城", "AZ", "173.249.203.193"),
    ("Ogden", "奥格登", "UT", "108.171.216.251"),
    ("Ashburn", "阿什本", "VA", "104.225.11.54"),
    ("Chicago DC2", "芝加哥 DC2", "IL2", "173.249.214.11"),
]


def timestamp():
    return datetime.now(SHANGHAI).isoformat(timespec="seconds")


def route_for(ip):
    cmd = (
        f"Find-NetRoute -RemoteIPAddress '{ip}' | "
        "Select-Object InterfaceAlias,InterfaceIndex,IPAddress,"
        "DestinationPrefix,NextHop,RouteMetric | ConvertTo-Json -Compress"
    )
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", cmd],
            capture_output=True, timeout=20,
        )
        data = json.loads(proc.stdout.decode("utf-8-sig", errors="replace"))
        return data
    except Exception as exc:
        return {"error": str(exc)}


def save_results(report, folder):
    (folder / "results.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    keys = ["name", "name_zh", "code", "ip", "sent", "received", "lost",
            "loss_pct", "min_ms", "avg_ms", "median_ms", "max_ms", "stdev_ms",
            "started_at", "finished_at"]
    with (folder / "comparison.csv").open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(report["results"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=30)
    parser.add_argument("--timeout-ms", type=int, default=1500)
    parser.add_argument("--codes", nargs="*")
    parser.add_argument("--output-dir")
    parser.add_argument("--targets-json")
    parser.add_argument("--source", default="https://greencloudvps.com/data-centers.php")
    args = parser.parse_args()
    run_label = datetime.now(SHANGHAI).strftime("%Y%m%d_%H%M%S")
    folder = Path(args.output_dir) if args.output_dir else (
        Path(__file__).parent / "reports" / f"greencloud_ping_{run_label}"
    )
    folder.mkdir(parents=True, exist_ok=True)
    report = {
        "started_at": timestamp(),
        "source": args.source,
        "method": {"tool": "Windows ping.exe", "count": args.count,
                   "timeout_ms": args.timeout_ms, "payload_bytes": 32,
                   "ip_version": 4, "execution": "sequential"},
        "results": [],
    }
    available_targets = TARGETS
    if args.targets_json:
        available_targets = json.loads(Path(args.targets_json).read_text(encoding="utf-8-sig"))
    targets = [row for row in available_targets if not args.codes or row[2] in args.codes]
    print(f"REPORT_DIR {folder.resolve()}", flush=True)
    for index, (name, name_zh, code, ip) in enumerate(targets, start=1):
        started_at = timestamp()
        route_before = route_for(ip)
        print(f"START {index}/{len(targets)} {name} {ip} {started_at}", flush=True)
        cmd = ["ping.exe", "-4", "-n", str(args.count), "-w",
               str(args.timeout_ms), "-l", "32", ip]
        proc = subprocess.run(cmd, capture_output=True,
                              timeout=args.count * (args.timeout_ms / 1000 + 2) + 15)
        raw = proc.stdout.decode("utf-8", errors="replace")
        if "\ufffd" in raw:
            raw = proc.stdout.decode("gb18030", errors="replace")
        raw += proc.stderr.decode("utf-8", errors="replace")
        (folder / f"{index:02d}_{code}_{ip}.txt").write_text(raw, encoding="utf-8")
        times, ttls = [], []
        for line in raw.splitlines():
            if "TTL=" not in line.upper():
                continue
            latency = re.search(r"([=<])\s*(\d+)\s*ms", line, re.IGNORECASE)
            ttl = re.search(r"TTL=(\d+)", line, re.IGNORECASE)
            if latency:
                times.append(0.5 if latency[1] == "<" else int(latency[2]))
                if ttl:
                    ttls.append(int(ttl[1]))
        received = len(times)
        result = {
            "name": name, "name_zh": name_zh, "code": code, "ip": ip,
            "sent": args.count, "received": received,
            "lost": args.count - received,
            "loss_pct": round((args.count - received) * 100 / args.count, 2),
            "min_ms": min(times) if times else None,
            "avg_ms": round(statistics.mean(times), 1) if times else None,
            "median_ms": round(statistics.median(times), 1) if times else None,
            "max_ms": max(times) if times else None,
            "stdev_ms": round(statistics.pstdev(times), 1) if times else None,
            "samples_ms": times, "ttls": sorted(set(ttls)),
            "route_before": route_before, "route_after": route_for(ip),
            "started_at": started_at, "finished_at": timestamp(),
            "command": cmd, "exit_code": proc.returncode,
        }
        report["results"].append(result)
        save_results(report, folder)
        summary = {k: result[k] for k in ("name", "ip", "received", "sent",
                                         "loss_pct", "min_ms", "avg_ms", "max_ms",
                                         "stdev_ms")}
        print("RESULT " + json.dumps(summary, ensure_ascii=True), flush=True)
    report["finished_at"] = timestamp()
    save_results(report, folder)
    print("COMPLETE " + str(folder.resolve()), flush=True)


if __name__ == "__main__":
    main()
