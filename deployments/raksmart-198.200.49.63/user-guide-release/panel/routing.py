"""Compose the audited service rules using only the existing private VPS nodes."""

import copy
import hashlib
import json
import re
from collections import OrderedDict
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).parent
MODES = ("manual", "services", "smart")


def preset():
    return json.loads((ROOT / "services-routing.json").read_text(encoding="utf-8"))


def smart_preset():
    # Mihomo follows the order of nameserver-policy entries. Keep overrides first.
    return json.loads((ROOT / "smart-routing.json").read_text(encoding="utf-8"),
                      object_pairs_hook=OrderedDict)


def rule_payload(domains, direction):
    """A classical YAML provider accepted by Mihomo's line-based parser."""
    if direction not in ("direct", "proxy"):
        raise ValueError("Unknown custom rule direction.")
    payload = ["DOMAIN-SUFFIX," + domain for domain in domains]
    # Mihomo rejects an empty classical payload. .invalid is reserved by RFC 2606.
    if not payload:
        payload = ["DOMAIN,empty-custom-" + direction + ".invalid"]
    return "payload:\n" + "".join("  - " + json.dumps(rule, ensure_ascii=False) + "\n" for rule in payload)


def provider_urls(providers, origin, base_path):
    for item in providers.values():
        resource = item.pop("resource", None)
        if resource:
            item["url"] = origin.rstrip("/") + "/" + base_path.strip("/") + "/rules/" + resource
        if "url" not in item:
            continue
        parsed = urlsplit(item["url"])
        if parsed.scheme not in ("https", "http") or parsed.username or parsed.password or parsed.query:
            raise ValueError("Rule provider URL contains unsupported private parameters.")


def render(profile, nodes, domains, mode, origin="https://api.aiuzh.icu", base_path="/node-console/",
           direct_domains=(), rule_token=None):
    rules = ["DOMAIN-SUFFIX," + domain + ",DIRECT" for domain in direct_domains]
    rules += ["DOMAIN,api.ipify.org,STATIC-SELECT"] + [
        "DOMAIN-SUFFIX," + domain + ",STATIC-SELECT" for domain in domains
    ]
    if mode == "manual":
        return profile.split("\nrules:\n", 1)[0] + "\nrules:\n" + "".join(
            "  - " + json.dumps(rule, ensure_ascii=False) + "\n" for rule in rules + ["MATCH,DIRECT"]
        )
    if mode not in ("services", "smart"):
        raise ValueError("Unknown routing mode.")
    if mode == "smart":
        if not isinstance(rule_token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", rule_token):
            raise ValueError("Smart routing requires a valid independent rule token.")
        data = smart_preset()
        providers = OrderedDict()
        cache_id = hashlib.sha256(rule_token.encode("ascii")).hexdigest()[:12]
        for direction, name in (("direct", "Custom Direct"), ("proxy", "Custom Proxy")):
            providers[name] = {"type": "http", "behavior": "classical", "format": "yaml",
                               "interval": 300, "proxy": "DIRECT",
                               "path": "./rules/smart/custom-" + cache_id + "-" + direction + ".yaml",
                               "resource": "custom/" + rule_token + "/" + direction + ".yaml"}
        providers.update(copy.deepcopy(data["providers"]))
        provider_urls(providers, origin, base_path)
        # Custom rules come only from stable subscriptions, so an edit needs no
        # client re-import. Explicit private networks always remain on the LAN.
        rules = data["local_rules"] + ["RULE-SET,Custom Direct,DIRECT", "RULE-SET,Custom Proxy,STATIC-SELECT",
                                       "DOMAIN,api.ipify.org,STATIC-SELECT"] + data["rules"]
        fields = OrderedDict([
            ("proxy-groups", [{"name": "STATIC-SELECT", "type": "select",
                               "proxies": [node["name"] for node in nodes]}]),
            ("rule-providers", providers), ("dns", data["dns"]),
            ("profile", data["profile"]), ("unified-delay", True),
            ("rules", rules),
        ])
        prefix = profile.split("\nproxy-groups:\n", 1)[0]
        prefix = prefix.replace("# Example rules only: GitHub and the IP check use VPS; other sites are direct.",
                                "# Smart routing: mainland services use this device; overseas follows the web exit.")
        return prefix + "\n" + "".join(key + ": " + json.dumps(value, ensure_ascii=False) + "\n"
                                      for key, value in fields.items())
    data = preset()
    groups = [{"name": "STATIC-SELECT", "type": "select", "proxies": [node["name"] for node in nodes]}] + data["groups"]
    providers = copy.deepcopy(data["providers"])
    provider_urls(providers, origin, base_path)
    fields = {"proxy-groups": groups, "rule-providers": providers, "dns": data["dns"],
              "profile": data["profile"], "unified-delay": data["unified-delay"],
              "rules": rules + data["rules"]}
    prefix = profile.split("\nproxy-groups:\n", 1)[0]
    prefix = prefix.replace("# Example rules only: GitHub and the IP check use VPS; other sites are direct.",
                            "# Service routing: original rule order; service groups control proxy/direct routing.")
    return prefix + "\n" + "".join(key + ": " + json.dumps(value, ensure_ascii=False) + "\n"
                                      for key, value in fields.items())
