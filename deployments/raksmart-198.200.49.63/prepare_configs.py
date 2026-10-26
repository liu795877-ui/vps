"""Create a new independent VLESS REALITY node without printing credentials."""

import argparse
import base64
import json
from pathlib import Path
import secrets
import sys
import uuid
from urllib.parse import urlencode, quote

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

FOLDER = Path(__file__).resolve().parent
sys.path.insert(0, str(FOLDER.parents[1]))
import configure_reality as base

parser = argparse.ArgumentParser()
parser.add_argument("--target", default="www.cloudflare.com")
args = parser.parse_args()
identity_path = FOLDER / "identity.private.json"
if identity_path.exists():
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
else:
    private = X25519PrivateKey.generate()
    encoded = lambda value: base64.urlsafe_b64encode(value).decode().rstrip("=")
    identity = {
        "uuid": str(uuid.uuid4()),
        "private_key": encoded(private.private_bytes(serialization.Encoding.Raw,
                                                     serialization.PrivateFormat.Raw,
                                                     serialization.NoEncryption())),
        "public_key": encoded(private.public_key().public_bytes(serialization.Encoding.Raw,
                                                                serialization.PublicFormat.Raw)),
        "short_id": secrets.token_hex(8),
    }
    identity_path.write_text(json.dumps(identity, indent=2), encoding="utf-8")

host, port, name = "198.200.49.63", 443, "RAKsmart-US"
base.PORT = port
server = base.server_config(identity["uuid"], identity["private_key"], identity["short_id"],
                            target=args.target)
server["outbounds"][0]["settings"] = {"domainStrategy": "UseIPv4"}
server["dns"] = {
    "queryStrategy": "UseIPv4",
    "servers": ["https+local://1.1.1.1/dns-query", "https+local://1.0.0.1/dns-query"],
}
(FOLDER / "server.private.json").write_text(json.dumps(server, indent=2), encoding="utf-8")

test_client = {
    "log": {"loglevel": "warning"},
    "inbounds": [{"listen": "127.0.0.1", "port": 17980, "protocol": "socks",
                  "settings": {"auth": "noauth", "udp": False}}],
    "outbounds": [{"protocol": "vless", "settings": {"vnext": [{
        "address": host, "port": port,
        "users": [{"id": identity["uuid"], "encryption": "none", "flow": "xtls-rprx-vision"}],
    }]}, "streamSettings": {"network": "raw", "security": "reality", "realitySettings": {
        "serverName": args.target, "fingerprint": "chrome", "password": identity["public_key"],
        "shortId": identity["short_id"], "spiderX": "/",
    }}}],
}
(FOLDER / "client-test.private.json").write_text(json.dumps(test_client, indent=2), encoding="utf-8")

profile = f"""# Private node credentials. Import as a new local profile in FlClash.
mixed-port: 7890
allow-lan: false
mode: rule
log-level: warning
ipv6: false
dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
proxies:
  - name: {name}
    type: vless
    server: {host}
    port: {port}
    uuid: {identity['uuid']}
    network: tcp
    udp: true
    tls: true
    flow: xtls-rprx-vision
    servername: {args.target}
    client-fingerprint: chrome
    reality-opts:
      public-key: {identity['public_key']}
      short-id: "{identity['short_id']}"
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - {name}
      - DIRECT
rules:
  - DOMAIN,api.ipify.org,PROXY
  - IP-CIDR,{host}/32,DIRECT,no-resolve
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
"""
(FOLDER / "raksmart-reality.private.yaml").write_text(profile, encoding="utf-8")
params = urlencode({"encryption": "none", "security": "reality", "sni": args.target,
                    "fp": "chrome", "pbk": identity["public_key"], "sid": identity["short_id"],
                    "type": "tcp", "flow": "xtls-rprx-vision"})
link = f"vless://{identity['uuid']}@{host}:{port}?{params}#{quote(name)}"
(FOLDER / "vless-link.private.txt").write_text(link + "\n", encoding="utf-8")
print(json.dumps({"host": host, "port": port, "name": name,
                  "protocol": "VLESS + REALITY + Vision", "target": args.target,
                  "credentials": "Generated and saved privately; values not printed."}))
