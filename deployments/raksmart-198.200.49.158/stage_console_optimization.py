"""Freeze the verified .63 console for .158 without importing or contacting a VPS.

Application bytes remain identical to .63 release05. The .158 production
baseline is reconstructed from its verified smart-routing archive and checked
against its unchanged original release. Offline Linux dependencies come only
from the four wheels recorded in the .63 operations manifest.
"""

import argparse
import ast
from datetime import datetime, timezone
import difflib
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import zipfile


FOLDER = Path(__file__).resolve().parent
SOURCE_FOLDER = FOLDER.parent / "raksmart-198.200.49.63"
SOURCE_RELEASE = SOURCE_FOLDER / "console-optimization-release-20261013-05"
DEFAULT_RELEASE = "console-optimization-release-20261013-01"
FORMAT = "vps-console-optimization-release-v1"
BASELINE_NAMES = (
    "configure_reality.py", "configure_static_exits.py",
    "test_configure_reality.py", "test_configure_static_exits.py",
    "panel/__init__.py", "panel/node_info.py", "panel/routing.py", "panel/server.py",
    "panel/services-routing.json", "panel/smart-routing.json",
    "panel/test_panel.py", "panel/test_routing.py", "panel/rules/domestic-dns.yaml",
    "panel/web/app.js", "panel/web/index.html", "panel/web/mark.svg", "panel/web/style.css",
)
WHEELS = (
    "cryptography-3.3.2-cp36-abi3-manylinux2010_x86_64.whl",
    "cffi-1.15.1-cp36-cp36m-manylinux_2_5_x86_64.manylinux1_x86_64.whl",
    "pycparser-2.21-py2.py3-none-any.whl",
    "six-1.17.0-py2.py3-none-any.whl",
)


def require(value, message):
    if not value:
        raise RuntimeError(message)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def read(path, inputs):
    require(path.is_file() and not path.is_symlink(), "Missing or linked input: " + str(path))
    require(not any(parent.is_symlink() for parent in path.parents), "Linked input ancestor")
    data = path.read_bytes()
    key = str(path.resolve())
    require(key not in inputs or inputs[key] == digest(data), "Input changed during preparation")
    inputs[key] = digest(data)
    return data


def relative(name):
    require(isinstance(name, str) and "\\" not in name, "Invalid logical path")
    path = PurePosixPath(name)
    require(not path.is_absolute() and path.parts and str(path) == name and
            all(part not in (".", "..", "__pycache__", "node_modules") for part in path.parts),
            "Unsafe logical path")
    require(".private." not in path.name and path.suffix != ".pyc", "Private/generated input")
    return path


def verified_archive(data, prefix, hashes):
    expected = {prefix + name for name in hashes}
    result = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as bundle:
        members = bundle.getmembers()
        require(len(members) == len(expected) and {item.name for item in members} == expected and
                all(item.isfile() and 0 <= item.size < 30 * 1024 * 1024 for item in members) and
                sum(item.size for item in members) < 30 * 1024 * 1024,
                "Archive contains unreviewed entries")
        for item in members:
            name = item.name[len(prefix):]
            relative(name)
            content = bundle.extractfile(item).read()
            require(digest(content) == hashes[name], "Frozen archive source differs: " + name)
            result[name] = content
    return result


def load_baseline(inputs):
    manifest_path = FOLDER / "smart-routing-release-manifest.json"
    manifest = json.loads(read(manifest_path, inputs))
    require(manifest.get("deployment_ip") == "198.200.49.158", "Unexpected baseline host")
    require(set(manifest["files"]) == set(manifest["source_sha256"]), "Incomplete smart patch index")
    archive = read(FOLDER / "smart-routing-release.tar.gz", inputs)
    require(digest(archive) == manifest["archive_sha256"], "Frozen .158 smart archive changed")
    hashes = {}
    origins = {}
    for name in BASELINE_NAMES:
        relative(name)
        content = read(FOLDER / "smart-routing-release" / name, inputs)
        hashes[name] = digest(content)
        if name in manifest["files"]:
            require(hashes[name] == manifest["source_sha256"][name], "Frozen smart patch differs: " + name)
            origins[name] = "158-smart-routing-manifest"
        else:
            require(content == read(FOLDER / "panel-release" / name, inputs),
                    "An original .158 baseline source changed: " + name)
            origins[name] = "158-original-panel-release"
    contents = verified_archive(archive, "release/", hashes)
    return contents, hashes, origins


def tar_bytes(contents, prefix):
    stream = io.BytesIO()
    with gzip.GzipFile(fileobj=stream, mode="wb", mtime=0, filename="") as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as bundle:
            for name, content in sorted(contents.items()):
                relative(name)
                item = tarfile.TarInfo(prefix + name)
                item.size, item.mode, item.mtime = len(content), 0o644, 0
                item.uid = item.gid = 0
                item.uname = item.gname = ""
                bundle.addfile(item, io.BytesIO(content))
    return stream.getvalue()


def vendor_bundle(inputs):
    manifest_path = SOURCE_FOLDER / "operations-release-manifest.json"
    frozen = json.loads(read(manifest_path, inputs))
    require(frozen.get("deployment_ip") == "198.200.49.63", "Unexpected dependency provenance")
    files, wheel_hashes = {}, {}
    for name in WHEELS:
        data = read(SOURCE_FOLDER / "operations-wheels" / name, inputs)
        wheel_hashes[name] = digest(data)
        require(wheel_hashes[name] == frozen["wheel_sha256"][name], "Frozen dependency wheel changed")
        with zipfile.ZipFile(io.BytesIO(data)) as wheel:
            entries = wheel.infolist()
            require(len({item.filename for item in entries}) == len(entries), "Duplicate wheel entries")
            for item in entries:
                if item.is_dir():
                    continue
                relative(item.filename)
                require(not stat.S_ISLNK(item.external_attr >> 16) and ".data/" not in item.filename,
                        "Wheel requires an unreviewed installation transform")
                require(item.filename not in files and 0 <= item.file_size < 30 * 1024 * 1024,
                        "Dependency collision or oversized file")
                files[item.filename] = wheel.read(item)
    require(sum(len(value) for value in files.values()) < 30 * 1024 * 1024, "Dependency bundle too large")
    archive = tar_bytes(files, "vendor/")
    manifest = {
        "format": "vps-console-vendor-v1", "python": "3.6", "platform": "linux-x86_64",
        "cryptography_version": "3.3.2", "archive_file": "vendor.tar.gz",
        "archive_sha256": digest(archive), "files": sorted(files),
        "file_sha256": {name: digest(value) for name, value in sorted(files.items())},
        "wheel_sha256": wheel_hashes,
        "source_manifest_sha256": inputs[str(manifest_path.resolve())],
        "production_dependency_installation_executed": False,
    }
    verified_archive(archive, "vendor/", manifest["file_sha256"])
    return archive, manifest


def build(release_name, check=False):
    require(re.fullmatch(r"console-optimization-release-\d{8}-[A-Za-z0-9_-]+", release_name),
            "Unexpected release name")
    target = FOLDER / release_name
    require(target.resolve().parent == FOLDER.resolve() and not target.is_symlink(), "Unsafe release destination")
    require(check or not target.exists(), "Release already exists; use a new release name")
    inputs = {}
    read(Path(__file__).resolve(), inputs)
    baseline, baseline_hashes, baseline_origins = load_baseline(inputs)
    source_manifest_data = read(SOURCE_RELEASE / "manifest.json", inputs)
    source = json.loads(source_manifest_data)
    require(source.get("format") == FORMAT and source.get("deployment_ip") == "198.200.49.63" and
            source.get("python_syntax") == "3.6" and len(source.get("release_files", [])) == 41 and
            set(source["release_files"]) == set(source["release_sha256"]),
            "Unexpected source .63 console release")
    archive = read(SOURCE_RELEASE / "release.tar.gz", inputs)
    require(digest(archive) == source["archive_sha256"], "Source .63 archive changed")
    contents = verified_archive(archive, "release/", source["release_sha256"])
    # Reuse only the read-only syntax/API/import-closure audit helpers.
    audit_path = SOURCE_FOLDER / "stage_console_optimization.py"
    read(audit_path, inputs)
    spec = importlib.util.spec_from_file_location("console_source_audit", str(audit_path))
    audit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit)
    for name, content in contents.items():
        require(content == read(SOURCE_RELEASE / "release" / name, inputs), "Source directory differs")
        if name.endswith(".py"):
            ast.parse(content.decode("utf-8"), filename=name, feature_version=(3, 6))
            audit.audit_python36(content.decode("utf-8"), name)
        elif name.endswith(".json"):
            json.loads(content)
    audit.verify_import_closure(contents)
    runtime_path = SOURCE_FOLDER / "console-optimization-python36-validation-20261013-05.json"
    runtime = json.loads(read(runtime_path, inputs))
    require(runtime.get("success") is True and runtime.get("archive_sha256") == digest(archive) and
            runtime.get("verification", {}).get("tests_run") == 234 and
            runtime["verification"]["failures"] == runtime["verification"]["errors"] == 0,
            "The .63 source release runtime evidence differs")
    vendor_archive, vendor = vendor_bundle(inputs)
    changed = sorted(name for name in contents if contents[name] != baseline.get(name))
    adaptations = {
        "application_source": "Exact .63 release05 bytes; no runtime edits.",
        "host": "198.200.49.158 comes from its preserved panel unit and migration context.",
        "static_exits": "The .63 member service/port/config-mode API replaces the .158 single-user API.",
        "python36": "All .63 release05 Python 3.6 adapters and their 234-test suite are retained.",
        "private_state": "No source or dependency package contains .63 account/identity/state data.",
        "baseline": "17 .158 source files reconstructed from the frozen smart archive; production hashes require SSH comparison.",
        "dependencies": "Four hash-pinned wheels copied verbatim into vendor layout; no pip execution.",
    }
    manifest = {
        "format": FORMAT, "deployment_ip": "198.200.49.158", "release_name": release_name,
        "origin": "https://198-200-49-158.sslip.io:8443",
        "prepared_at": datetime.now(timezone.utc).isoformat(), "python_syntax": "3.6",
        "application_files": sorted(contents), "release_files": sorted(contents),
        "release_sha256": dict(source["release_sha256"]), "source_sha256": dict(source["release_sha256"]),
        "adapted_sha256": dict(source["release_sha256"]), "changed_files": changed,
        "new_files": sorted(set(contents) - set(baseline)), "baseline_sha256": baseline_hashes,
        "baseline_file_origins": baseline_origins, "archive_file": "release.tar.gz",
        "archive_sha256": digest(archive), "builder_sha256": inputs[str(Path(__file__).resolve())],
        "source_deployment_ip": "198.200.49.63", "source_release_name": source["release_name"],
        "source_manifest_sha256": digest(source_manifest_data), "source_archive_sha256": digest(archive),
        "source_runtime_report_sha256": inputs[str(runtime_path.resolve())],
        "source_runtime_test_count": 234, "vendor_archive_sha256": vendor["archive_sha256"],
        "vendor_files": vendor["files"], "vendor_sha256": vendor["file_sha256"],
        "vendor_manifest_file": "vendor-manifest.json", "adaptation_process": adaptations,
        "compatibility": {"python36_syntax_passed": True, "known_newer_stdlib_api_audit_passed": True,
                          "source_python36_runtime_tests_passed": True, "python36_runtime_tests_passed": False,
                          "runtime_test_note": "Run all 234 tests inside a .158 exclusive temporary stage."},
        "production_deployment_executed": False, "private_credentials_included": False,
        "state_mutations_performed": [], "old_release_and_manifests_untouched": True,
        "ports_accounts_or_cloud_rules_changed": False,
    }
    for name, expected in inputs.items():
        require(digest(Path(name).read_bytes()) == expected, "A preparation input changed")
    if check:
        return {"checked_only": True, "release_written": False, "remote_connected": False,
                "application_files": len(contents), "baseline_files": len(baseline),
                "source_archive_sha256": digest(archive), "vendor_archive_sha256": vendor["archive_sha256"]}
    target.mkdir()
    for name, content in sorted(contents.items()):
        destination = target / "release" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as stream:
            stream.write(content)
    for name, content in (("release.tar.gz", archive), ("vendor.tar.gz", vendor_archive)):
        with (target / name).open("xb") as stream:
            stream.write(content)
    for name, content in (("manifest.json", manifest), ("vendor-manifest.json", vendor),
                          ("adaptation-process.json", adaptations)):
        with (target / name).open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(content, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    with (target / "application-changes.patch").open("x", encoding="utf-8", newline="\n") as stream:
        for name in changed:
            stream.writelines(difflib.unified_diff(baseline.get(name, b"").decode("utf-8").splitlines(True),
                              contents[name].decode("utf-8").splitlines(True),
                              fromfile="158-baseline/" + name, tofile="release/" + name))
    return {"prepared": True, "release": str(target), "application_files": len(contents),
            "baseline_files": len(baseline), "archive_sha256": digest(archive),
            "vendor_archive_sha256": vendor["archive_sha256"], "remote_connected": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-name", default=DEFAULT_RELEASE)
    parser.add_argument("--check", action="store_true", help="Review in memory without creating files")
    args = parser.parse_args()
    print(json.dumps(build(args.release_name, args.check), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
