"""Compose the console's independent HY2 and REALITY entries in one profile.

This runs after routing.render and preserves its rule/provider/DNS text.  Only
the generated proxy and group sections change.  No YAML dependency is required
on the Python 3.6 VPS.  Credentials are supplied by the account transport owner.
"""

import ipaddress
import json
import re


AUTO = "AUTO · 网页切换"
HY2 = "HY2 · 网页切换"
REALITY = "REALITY · TCP兼容"


def _section(profile, name):
    match = re.search(r"^" + re.escape(name) + r":([^\n]*)\n", profile, re.M)
    if not match:
        raise ValueError("Generated client section is missing: " + name)
    following = re.search(r"^[A-Za-z][A-Za-z0-9_-]*:", profile[match.end():], re.M)
    end = match.end() + following.start() if following else len(profile)
    return match.start(), end, match.group(1).strip(), profile[match.end():end]


def _scalar(value):
    value = value.strip()
    if value.startswith('"'):
        result = json.loads(value)
    elif value and not any(character in value for character in "\r\n#[]{},"):
        result = value
    else:
        raise ValueError("Unsupported generated YAML scalar")
    if not isinstance(result, str) or not result:
        raise ValueError("Invalid generated YAML scalar")
    return result


def _proxy_blocks(body):
    matches = list(re.finditer(r"^  - name: ([^\n]+)\n", body, re.M))
    if not matches or body[:matches[0].start()].strip():
        raise ValueError("Expected generated block proxy definitions")
    blocks = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        blocks.append((_scalar(match.group(1)), body[match.start():end]))
    if len({name for name, _ in blocks}) != len(blocks):
        raise ValueError("Duplicate generated proxy name")
    return blocks


def _groups(inline, body):
    if inline:
        result = json.loads(inline)
    else:
        # The sole multiline form is configure_static_exits' simple select
        # group.  The smart/service renderers write richer groups as JSON.
        result = []
        group = None
        reading_proxies = False
        for line in body.splitlines():
            if not line.strip():
                continue
            found = re.fullmatch(r"  - name: (.+)", line)
            if found:
                group = {"name": _scalar(found.group(1))}
                result.append(group)
                reading_proxies = False
            elif group is not None and re.fullmatch(r"    type: select", line):
                group["type"] = "select"
            elif group is not None and line == "    proxies:":
                group["proxies"] = []
                reading_proxies = True
            elif group is not None and reading_proxies and line.startswith("      - "):
                group["proxies"].append(_scalar(line[8:]))
            else:
                raise ValueError("Unsupported generated multiline proxy group")
    if (not isinstance(result, list) or not result or
            any(not isinstance(group, dict) or not isinstance(group.get("name"), str)
                for group in result) or len({group["name"] for group in result}) != len(result)):
        raise ValueError("Invalid generated proxy groups")
    return result


def compose(profile, public_ip, port, password, certificate_sha256,
            sni="raksmart-hy2.local"):
    """Return one account's HY2-first profile, retaining its existing rules.

    STATIC-SELECT still selects AUTO.  AUTO is a fallback group, and the
    independent REALITY entry is also available there for manual TCP use.
    Repeated composition refreshes the HY2 credential without duplicating
    entries.  Fixed REALITY exits retain their names, UUIDs and exact text.
    """
    if not isinstance(profile, str) or "\r" in profile:
        raise ValueError("Expected a generated LF client profile")
    if not isinstance(public_ip, str):
        raise ValueError("Invalid public server address")
    try:
        ipaddress.ip_address(public_ip)
    except ValueError:
        raise ValueError("Invalid public server address")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Invalid independent HY2 port")
    if (not isinstance(password, str) or not 12 <= len(password) <= 128
            or any(ord(character) < 32 or ord(character) == 127 for character in password)):
        raise ValueError("Invalid independent HY2 credential")
    if not isinstance(certificate_sha256, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", certificate_sha256):
        raise ValueError("Invalid HY2 certificate fingerprint")
    if (not isinstance(sni, str) or len(sni) > 253
            or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", sni)):
        raise ValueError("Invalid HY2 server name")

    proxy_start, proxy_end, proxy_inline, proxy_body = _section(profile, "proxies")
    group_start, group_end, group_inline, group_body = _section(profile, "proxy-groups")
    if proxy_inline or proxy_end != group_start:
        raise ValueError("Expected adjacent generated proxy and group sections")
    blocks = _proxy_blocks(proxy_body)
    groups = _groups(group_inline, group_body)
    auto_blocks = [(name, block) for name, block in blocks if name in (AUTO, REALITY)]
    if len(auto_blocks) != 1 or not re.search(r"^    type: vless$", auto_blocks[0][1], re.M):
        raise ValueError("Expected exactly one generated REALITY AUTO entry")
    original_name, original_block = auto_blocks[0]
    composed = original_name == REALITY
    reserved_groups = [group for group in groups if group["name"] in (HY2, REALITY)]
    if reserved_groups or (not composed and any(name == HY2 for name, _ in blocks)):
        raise ValueError("Independent transport names are already in use")
    selection = next((group for group in groups if group["name"] == "STATIC-SELECT"), None)
    if not selection or selection.get("type") != "select" or AUTO not in selection.get("proxies", []):
        raise ValueError("Expected the existing STATIC-SELECT AUTO selection")
    if composed:
        prior_auto = next((group for group in groups if group["name"] == AUTO), None)
        prior_hy2 = [block for name, block in blocks if name == HY2]
        if (not prior_auto or prior_auto.get("type") != "fallback" or
                prior_auto.get("proxies") != [HY2, REALITY] or len(prior_hy2) != 1 or
                not re.search(r"^    type: hysteria2$", prior_hy2[0], re.M)):
            raise ValueError("Incomplete composed transport profile")
    elif any(group["name"] == AUTO for group in groups):
        raise ValueError("AUTO transport group name is already in use")

    quote = lambda value: json.dumps(value, ensure_ascii=False)
    reality_block = re.sub(r"^  - name: [^\n]+", "  - name: " + quote(REALITY),
                          original_block, count=1, flags=re.M)
    # Literal scalars use JSON quoting, which is also valid YAML quoting.
    hy2_block = ("  - name: " + quote(HY2) + "\n"
                 "    type: hysteria2\n"
                 "    server: " + quote(public_ip) + "\n"
                 "    port: " + str(port) + "\n"
                 "    password: " + quote(password) + "\n"
                 "    sni: " + quote(sni) + "\n"
                 "    skip-cert-verify: false\n"
                 "    fingerprint: " + quote(certificate_sha256.lower()) + "\n"
                 "    udp: false\n"
                 "    bbr-profile: standard\n")
    fixed_blocks = [block for name, block in blocks if name not in (AUTO, REALITY, HY2)]
    proxy_text = "proxies:\n" + hy2_block + reality_block.rstrip("\n") + "\n"
    if fixed_blocks:
        proxy_text += "".join(fixed_blocks)
    proxy_text = proxy_text.rstrip("\n") + "\n"
    groups = [group for group in groups if group["name"] != AUTO]
    if REALITY not in selection["proxies"]:
        selection["proxies"].insert(selection["proxies"].index(AUTO) + 1, REALITY)
    groups.append({"name": AUTO, "type": "fallback", "proxies": [HY2, REALITY],
                   "url": "https://www.gstatic.com/generate_204", "expected-status": "204",
                   "interval": 30, "timeout": 5000, "lazy": False})
    group_text = "proxy-groups: " + json.dumps(groups, ensure_ascii=False) + "\n"
    return profile[:proxy_start] + proxy_text + group_text + profile[group_end:]
