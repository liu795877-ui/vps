"""Extract routing data without retaining nodes, control secrets or provider tokens."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

import yaml


def fetch_payload(url):
    with urlopen(Request(url, headers={"User-Agent": "NodeConsoleRoutingAudit"}), timeout=25) as response:
        content = response.read(16 * 1024 * 1024 + 1)
    if len(content) > 16 * 1024 * 1024:
        raise ValueError("Rule provider response exceeded the import limit.")
    data = yaml.safe_load(content)
    payload = data.get("payload") if isinstance(data, dict) else None
    if not isinstance(payload, list) or not all(isinstance(item, str) for item in payload):
        raise ValueError("Rule provider did not return a string payload list.")
    return {"payload": payload}


def extract(source, directory, cache):
    config = yaml.safe_load(source.read_text(encoding="utf-8-sig"))
    node_names = {item["name"] for item in config["proxies"]}
    groups = []
    for original in config["proxy-groups"]:
        group = {key: original[key] for key in ("name", "type", "interval", "tolerance", "lazy") if key in original}
        group["proxies"] = list(dict.fromkeys(
            ("AUTO · 网页切换" if group["type"] == "url-test" else "STATIC-SELECT")
            if name in node_names else name for name in original["proxies"]
        ))
        if group["type"] == "url-test":
            group["url"] = "https://www.gstatic.com/generate_204"
        if group["name"] == "Proxy":
            group["proxies"] = ["STATIC-SELECT"] + [name for name in group["proxies"] if name != "STATIC-SELECT"]
        groups.append(group)
    providers = {}
    sources = []
    for name, original in config["rule-providers"].items():
        target = "rules/service/" + hashlib.sha256(name.encode()).hexdigest()[:16] + ".yaml"
        provider = {"type": "http", "behavior": original["behavior"], "interval": 86400,
                    "path": "./" + target, "proxy": "Proxy"}
        parsed = urlsplit(original["url"])
        if name == "Domestic DNS":
            provider["resource"] = "domestic-dns.yaml"
            provider["proxy"] = "DIRECT"
            url = original["url"]
        else:
            if not parsed.path.startswith("/rules/"):
                raise ValueError("Unsupported upstream path for provider: " + name)
            provider["url"] = "https://raw.githubusercontent.com/" + parsed.path.removeprefix("/rules/")
            url = provider["url"]
        providers[name] = provider
        sources.append((name, url, target))

    def load(spec):
        name, url, target = spec
        cached = cache / target
        if cached.exists():
            return name, target, json.loads(cached.read_text(encoding="utf-8"))
        for _ in range(3):
            try:
                return name, target, fetch_payload(url)
            except Exception:
                pass
        return name, target, None

    cache.mkdir(parents=True, exist_ok=True)
    failures = []
    counts = {}
    snapshots = {}
    with ThreadPoolExecutor(max_workers=6) as executor:
        for name, target, data in executor.map(load, sources):
            if data is None:
                failures.append(name)
                continue
            counts[name] = len(data["payload"])
            destination = cache / target
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
            if name == "Domestic DNS":
                if any(not item.startswith(("DOMAIN,", "DOMAIN-SUFFIX,", "DOMAIN-KEYWORD,")) for item in data["payload"]):
                    raise ValueError("The DNS snapshot contains unexpected rule types.")
                snapshots["domestic-dns.yaml"] = data
    if failures:
        raise RuntimeError("Rule providers could not be verified: " + ", ".join(failures))
    preset = {"name": "服务分类分流", "rules": config["rules"], "groups": groups,
              "providers": providers, "dns": config["dns"],
              "profile": {"store-selected": True, "store-fake-ip": True},
              "unified-delay": bool(config.get("unified-delay", True)),
              "snapshot_domains": counts["Domestic DNS"], "snapshot_date": "2026-10-08"}
    # Only the extracted routing keys are serialized; authenticated source URLs are discarded.
    serialized = json.dumps(preset, ensure_ascii=False, indent=2) + "\n"
    if any(value in serialized for item in config["proxies"] for key, value in item.items()
           if key in ("password", "uuid") and isinstance(value, str) and len(value) > 8):
        raise ValueError("Unexpected node credential in routing output.")
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "services-routing.json").write_text(serialized, encoding="utf-8")
    for filename, data in snapshots.items():
        target = directory / "rules" / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"rules": len(preset["rules"]), "providers_verified": len(counts),
                      "groups": len(groups), "dns_snapshot_domains": counts["Domestic DNS"]}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    args = parser.parse_args()
    extract(args.source, Path(__file__).parent, args.cache)
