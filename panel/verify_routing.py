"""Validate the service profile in an isolated Mihomo configuration directory."""

import argparse
import json
from pathlib import Path
import subprocess

from panel import server


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    args = parser.parse_args()
    root = args.cache.resolve()
    manager = server.Manager(root / "test-only", "8.8.8.8", root / "test-only" / "xray.json", demo=True)
    existing = next((item for item in manager.state["exits"] if item["name"] == "Validation exit"), None)
    identity = existing["id"] if existing else manager.edit_exit({
        "name":"Validation exit","address":"test-only.proxy.example.com",
        "port":1080,"auth":"none","expected_ip":"",
    })["id"]
    state = manager.state | {"routing_mode":"services","domains":[]}
    _, profile = manager.build(state, identity)
    profile_path = root / "profile-test.yaml"
    profile_path.write_text(profile, encoding="utf-8")
    result = subprocess.run([str(args.core), "-t", "-d", str(root), "-f", str(profile_path)],
                            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    if result.returncode:
        print(result.stdout[-5000:])
        print(result.stderr[-1500:])
        raise RuntimeError("Isolated Mihomo configuration validation failed.")
    print("Mihomo accepted the service rules, AND expression, strategy groups and DNS policies.")


if __name__ == "__main__":
    main()
