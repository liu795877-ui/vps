"""Build an independent, reviewable .63 console package without remote access.

Run this helper only after the workspace changes are ready. It validates the
frozen HY2 release plus its AUTO patch against the maintenance baseline, copies
the application into a NEW directory, and records every compatibility edit.
It never imports the panel, reads private credentials, or runs an installer.
Python 3.6 parsing and a known-API audit do not replace tests on Python 3.6.
"""

import argparse
import ast
from datetime import datetime, timezone
import difflib
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile


FOLDER = Path(__file__).resolve().parent
ROOT = FOLDER.parents[1]
BASELINE = FOLDER / "panel-release"
FULL_RELEASE = FOLDER / "hy2-integration-release"
FULL_MANIFEST = FOLDER / "hy2-integration-release-manifest.json"
AUTO_RELEASE = FOLDER / "hy2-auto-health-release" / "release"
AUTO_MANIFEST = FOLDER / "hy2-auto-health-release" / "manifest.json"
DEFAULT_RELEASE = "console-optimization-release-20261012-01"
FORMAT = "vps-console-optimization-release-v1"

# These are intentional .63 production adaptations, not generic workspace
# sources. Keep both the adapters and their matching configuration tests.
PRESERVE_BASELINE = frozenset((
    "configure_reality.py", "configure_static_exits.py",
    "test_configure_reality.py", "test_configure_static_exits.py",
))
LOCAL_ONLY_MODULES = frozenset((
    "install.py", "deploy.py", "import_routing.py", "verify_routing.py",
))
WEB_SUFFIXES = frozenset((
    ".js", ".css", ".html", ".svg", ".png", ".jpg", ".jpeg",
    ".webp", ".ico", ".woff", ".woff2", ".ttf",
))
HTTP_FALLBACK = """from http.server import BaseHTTPRequestHandler, HTTPServer
try:
    from http.server import ThreadingHTTPServer
except ImportError:
    from socketserver import ThreadingMixIn

    class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True"""
UNLINK_HELPER = """\n\ndef _compat_unlink_if_exists(path):
    # Path.unlink(missing_ok=True) was introduced after Python 3.6.
    try:
        path.unlink()
    except FileNotFoundError:
        pass
"""


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_relative(name):
    require(isinstance(name, str) and "\\" not in name, "Unexpected application path")
    value = PurePosixPath(name)
    require(not value.is_absolute() and value.parts and
            all(part not in (".", "..", "__pycache__", "node_modules") for part in value.parts),
            "Unsafe application path: " + name)
    require(".private." not in value.name and value.suffix != ".pyc",
            "Private or generated input is not application source: " + name)
    return value


def read_source(path, inputs):
    require(path.is_file() and not path.is_symlink(), "Missing or linked input: " + str(path))
    require(not any(parent.is_symlink() for parent in path.parents if parent != parent.parent),
            "Input has a linked ancestor: " + str(path))
    data = path.read_bytes()
    key = str(path.resolve())
    current = digest(data)
    require(key not in inputs or inputs[key] == current, "Input changed during staging: " + str(path))
    inputs[key] = current
    return data


def read_json(path, inputs):
    return json.loads(read_source(path, inputs).decode("utf-8"))


def load_baseline(inputs):
    """Validate all historical frozen bytes before selecting the effective baseline."""
    full = read_json(FULL_MANIFEST, inputs)
    auto = read_json(AUTO_MANIFEST, inputs)
    require(full.get("deployment_ip") == "198.200.49.63" and full.get("python_syntax") == "3.6",
            "Unexpected frozen HY2 release")
    require(auto.get("format") == "vps-hy2-auto-health-v1" and
            auto.get("deployment_ip") == "198.200.49.63", "Unexpected frozen AUTO patch")
    names = full.get("release_files")
    require(isinstance(names, list) and len(names) == len(set(names)) and
            set(names) == set(full.get("release_sha256", {})), "Incomplete full-release file index")
    require(set(PRESERVE_BASELINE).issubset(names), "Frozen production adapters are absent")
    require(auto.get("files") == ["panel/accelerated_client.py", "panel/test_accelerated_client.py"],
            "Unexpected AUTO patch scope")
    require(set(auto["files"]).issubset(names), "AUTO patch does not extend the full release")
    expected = dict(full["release_sha256"])
    for name in names:
        safe_relative(name)
        require(digest(read_source(FULL_RELEASE / name, inputs)) == expected[name],
                "Frozen full-release bytes changed: " + name)
    for name in auto["files"]:
        require(auto.get("baseline_sha256", {}).get(name) == expected[name],
                "AUTO patch was built against a different full-release file: " + name)
        patched = read_source(AUTO_RELEASE / name, inputs)
        require(digest(patched) == auto.get("source_sha256", {}).get(name),
                "Frozen AUTO bytes changed: " + name)
        expected[name] = digest(patched)
    baseline = {}
    for name in sorted(names):
        data = read_source(BASELINE / name, inputs)
        require(digest(data) == expected[name], "Maintenance baseline differs from the frozen releases: " + name)
        baseline[name] = data
    return baseline, expected


def span(text, node):
    """Translate AST UTF-8 byte offsets into Python string offsets."""
    lines = text.splitlines(keepends=True)
    starts = [0]
    for line in lines:
        starts.append(starts[-1] + len(line))
    first = len(lines[node.lineno - 1].encode("utf-8")[:node.col_offset].decode("utf-8"))
    last = len(lines[node.end_lineno - 1].encode("utf-8")[:node.end_col_offset].decode("utf-8"))
    return starts[node.lineno - 1] + first, starts[node.end_lineno - 1] + last


def source_segment(text, node):
    start, end = span(text, node)
    return text[start:end]


def apply_edits(text, edits):
    previous_start = len(text) + 1
    for start, end, replacement in sorted(edits, reverse=True):
        require(0 <= start <= end <= previous_start, "Overlapping compatibility edits require review")
        text = text[:start] + replacement + text[end:]
        previous_start = start
    return text


def preserve_adoption_tests(text, baseline_text, records):
    tree = ast.parse(text)
    if any(isinstance(node, ast.ClassDef) and node.name == "ExistingRaksmartNodeTests" for node in tree.body):
        return text
    original = ast.parse(baseline_text)
    adoption = [node for node in original.body if isinstance(node, ast.ClassDef) and
                node.name == "ExistingRaksmartNodeTests"]
    anchors = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "PanelTests"]
    require(len(adoption) == len(anchors) == 1, "Cannot preserve the .63 adoption regression tests")
    position, unused = span(text, anchors[0])
    text = text[:position] + source_segment(baseline_text, adoption[0]) + "\n\n\n" + text[position:]
    has_base64 = any(isinstance(node, ast.Import) and any(alias.name == "base64" and
                     alias.asname is None for alias in node.names) for node in tree.body)
    if not has_base64:
        require(not any(isinstance(node, ast.ImportFrom) and node.module == "__future__"
                        for node in tree.body), "Test import insertion needs review")
        text = "import base64\n" + text
    records.append({"operation": "preserve_existing_63_adoption_tests", "classes": 1})
    return text


def compatible(text, name, baseline_text=None):
    """Adapt only identified AST nodes, recording each exact edit's purpose."""
    records = []
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    if normalized != text:
        records.append({"operation": "normalize_python_line_endings"})
    text = normalized
    if name == "panel/test_panel.py":
        require(baseline_text is not None, "Production adoption-test baseline is required")
        text = preserve_adoption_tests(text, baseline_text.replace("\r\n", "\n"), records)
    tree = ast.parse(text, filename=name)
    edits, unlink_count, http_count = [], 0, 0
    for node in ast.walk(tree):
        if (isinstance(node, ast.ImportFrom) and node.module == "http.server" and
                any(alias.name == "ThreadingHTTPServer" for alias in node.names)):
            require(name == "panel/server.py" and
                    [(alias.name, alias.asname) for alias in node.names] ==
                    [("BaseHTTPRequestHandler", None), ("ThreadingHTTPServer", None)],
                    "ThreadingHTTPServer import needs an explicit adapter: " + name)
            start, end = span(text, node)
            edits.append((start, end, HTTP_FALLBACK))
            http_count += 1
            records.append({"operation": "python36_threading_http_server_fallback", "line": node.lineno})
        if isinstance(node, ast.Call):
            keywords = {keyword.arg: keyword for keyword in node.keywords if keyword.arg is not None}
            if isinstance(node.func, ast.Attribute) and node.func.attr == "unlink" and "missing_ok" in keywords:
                keyword = keywords["missing_ok"]
                require(not node.args and len(node.keywords) == 1 and
                        isinstance(keyword.value, ast.Constant) and keyword.value.value is True,
                        "Path.unlink signature needs an explicit adapter: " + name)
                start, end = span(text, node)
                value = source_segment(text, node.func.value)
                edits.append((start, end, "_compat_unlink_if_exists(" + value + ")"))
                unlink_count += 1
                records.append({"operation": "python36_unlink_if_exists", "line": node.lineno,
                                "expression": source_segment(text, node)})
            if (isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and
                    node.func.value.id == "subprocess"):
                if "capture_output" in keywords:
                    keyword = keywords["capture_output"]
                    require(node.func.attr == "run" and not {"stdout", "stderr"}.intersection(keywords) and
                            isinstance(keyword.value, ast.Constant) and keyword.value.value is True,
                            "subprocess capture_output signature needs an explicit adapter: " + name)
                    start, end = span(text, keyword)
                    edits.append((start, end, "stdout=subprocess.PIPE, stderr=subprocess.PIPE"))
                    records.append({"operation": "python36_subprocess_capture_output", "line": keyword.lineno})
                if "text" in keywords:
                    keyword = keywords["text"]
                    require("universal_newlines" not in keywords and isinstance(keyword.value, ast.Constant) and
                            isinstance(keyword.value.value, bool), "subprocess text signature needs review: " + name)
                    start, end = span(text, keyword)
                    replacement = "universal_newlines=" + ("True" if keyword.value.value else "False")
                    edits.append((start, end, replacement))
                    records.append({"operation": "python36_subprocess_text", "line": keyword.lineno})
        if PurePosixPath(name).name.startswith("test_") and isinstance(node, ast.Attribute) and node.attr in ("args", "kwargs"):
            value = node.value
            if (isinstance(value, ast.Name) and value.id == "call") or (
                    isinstance(value, ast.Attribute) and value.attr == "call_args"):
                start, end = span(text, node)
                edits.append((start, end, source_segment(text, value) + ("[0]" if node.attr == "args" else "[1]")))
                records.append({"operation": "python36_mock_call_tuple_access", "line": node.lineno,
                                "attribute": node.attr})
    require(name != "panel/server.py" or http_count == 1,
            "The server HTTP import has changed; review its fallback before staging")
    text = apply_edits(text, edits)
    if unlink_count:
        tree = ast.parse(text)
        require(not any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and
                        node.name == "_compat_unlink_if_exists" for node in tree.body),
                "Compatibility helper already exists; review its semantics: " + name)
        main_guards = [node for node in tree.body if isinstance(node, ast.If) and
                       isinstance(node.test, ast.Compare) and isinstance(node.test.left, ast.Name) and
                       node.test.left.id == "__name__"]
        require(len(main_guards) <= 1, "Multiple main guards require compatibility review: " + name)
        position = span(text, main_guards[0])[0] if main_guards else len(text)
        text = text[:position] + UNLINK_HELPER + "\n\n" + text[position:]
        records.append({"operation": "insert_python36_unlink_helper", "calls": unlink_count})
    ast.parse(text, filename=name, feature_version=(3, 6))
    audit_python36(text, name)
    return text, records


def audit_python36(text, name):
    """Reject known newer syntax/API uses; the manifest keeps runtime tests pending."""
    tree = ast.parse(text, filename=name, feature_version=(3, 6))
    forbidden_modules = {"dataclasses", "contextvars", "zoneinfo", "graphlib", "tomllib", "importlib.resources"}
    forbidden_attributes = {"removeprefix", "removesuffix", "is_relative_to", "readlink", "fromisoformat",
                            "time_ns", "monotonic_ns", "perf_counter_ns", "process_time_ns", "thread_time",
                            "thread_time_ns", "cached_property", "copy_context", "aclose", "aiter", "anext"}
    module_attributes = {
        "math": {"comb", "perm", "prod", "isqrt", "dist", "lcm", "nextafter", "ulp"},
        "statistics": {"fmean", "geometric_mean", "multimode", "quantiles", "NormalDist"},
        "shlex": {"join"}, "typing": {"Literal", "Final", "Protocol", "TypedDict", "Self", "Never"},
        "contextlib": {"nullcontext", "asynccontextmanager", "aclosing"},
    }
    module_aliases, imported_functions = {}, {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                module_aliases[alias.asname or alias.name] = alias.name
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                imported_functions[alias.asname or alias.name] = node.module + "." + alias.name
    problems = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in forbidden_modules:
                    problems.append((node.lineno, "newer standard-library import " + alias.name))
        if isinstance(node, ast.ImportFrom):
            if node.module in forbidden_modules or (node.module == "__future__" and
                    any(alias.name == "annotations" for alias in node.names)):
                problems.append((node.lineno, "newer standard-library import " + str(node.module)))
            for alias in node.names:
                if alias.name in module_attributes.get(node.module, set()):
                    problems.append((node.lineno, "newer standard-library symbol " + alias.name))
        if isinstance(node, ast.Attribute) and node.attr in forbidden_attributes:
            problems.append((node.lineno, "newer runtime attribute " + node.attr))
        if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and
                node.attr in module_attributes.get(node.value.id, set())):
            problems.append((node.lineno, "newer standard-library symbol " + node.value.id + "." + node.attr))
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in {"breakpoint", "ExceptionGroup", "BaseExceptionGroup", "aiter", "anext"}:
                problems.append((node.lineno, "newer builtin " + node.func.id))
            function, module = None, None
            if isinstance(node.func, ast.Attribute):
                function = node.func.attr
                if isinstance(node.func.value, ast.Name):
                    module = module_aliases.get(node.func.value.id, node.func.value.id)
            elif isinstance(node.func, ast.Name):
                qualified = imported_functions.get(node.func.id)
                if qualified:
                    module, function = qualified.rsplit(".", 1)
            for keyword in node.keywords:
                if ((module == "subprocess" and keyword.arg in {"capture_output", "text"}) or
                        (function == "unlink" and keyword.arg == "missing_ok") or
                        (module == "shutil" and function == "copytree" and keyword.arg == "dirs_exist_ok") or
                        (function == "shutdown" and keyword.arg == "cancel_futures")):
                    problems.append((node.lineno, "newer runtime keyword " + keyword.arg))
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr) and (
                isinstance(node.left, ast.Dict) or isinstance(node.right, ast.Dict)):
            problems.append((node.lineno, "dictionary union requires Python 3.9"))
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id in {
                "list", "dict", "tuple", "set", "frozenset", "type"}:
            problems.append((node.lineno, "builtin generic requires Python 3.9"))
    require(not problems, "Python 3.6 runtime review required in " + name + ": " +
            "; ".join(str(line) + " " + message for line, message in sorted(set(problems))))


def workspace_names(baseline):
    names = set(baseline)
    for path in (ROOT / "panel").glob("*.py"):
        if path.name not in LOCAL_ONLY_MODULES:
            names.add(path.relative_to(ROOT).as_posix())
    for path in (ROOT / "panel" / "web").rglob("*"):
        if path.is_file() and path.suffix.lower() in WEB_SUFFIXES:
            names.add(path.relative_to(ROOT).as_posix())
    for name in names:
        safe_relative(name)
    return sorted(names)


def verify_import_closure(contents):
    for name, data in contents.items():
        if not name.endswith(".py"):
            continue
        tree = ast.parse(data.decode("utf-8"), filename=name)
        modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.update(alias.name for alias in node.names if alias.name.startswith("panel."))
            if isinstance(node, ast.ImportFrom) and node.module:
                if node.module.startswith("panel."):
                    modules.add(node.module)
                elif node.module == "panel":
                    modules.update("panel." + alias.name for alias in node.names)
        for module in modules:
            relative = module.replace(".", "/") + ".py"
            package = module.replace(".", "/") + "/__init__.py"
            require(relative in contents or package in contents,
                    "Local module missing from complete release: " + module + " (imported by " + name + ")")


def verify_inputs(inputs):
    for name, expected in inputs.items():
        path = Path(name)
        require(path.is_file() and not path.is_symlink() and digest(path.read_bytes()) == expected,
                "An input changed during preparation: " + name)


def archive_bytes(contents):
    stream = io.BytesIO()
    with gzip.GzipFile(fileobj=stream, mode="wb", mtime=0, filename="") as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as bundle:
            for name, data in sorted(contents.items()):
                entry = tarfile.TarInfo("release/" + name)
                entry.size, entry.mode, entry.mtime = len(data), 0o644, 0
                entry.uid = entry.gid = 0
                entry.uname = entry.gname = ""
                bundle.addfile(entry, io.BytesIO(data))
    return stream.getvalue()


def build(release_name, check_only=False):
    require(re.fullmatch(r"console-optimization-release-\d{8}-[A-Za-z0-9_-]+", release_name),
            "Use a new console-optimization-release-YYYYMMDD-id directory name")
    destination = FOLDER / release_name
    require(destination.resolve().parent == FOLDER.resolve() and not destination.exists() and
            not destination.is_symlink(), "Release directory already exists or is unsafe; choose a new name")
    inputs = {}
    builder_digest = digest(read_source(Path(__file__).resolve(), inputs))
    baseline, expected = load_baseline(inputs)
    contents, origins, source_hashes, workspace_hashes, adapter_hashes, patches = {}, {}, {}, {}, {}, []
    for name in workspace_names(baseline):
        root_path = ROOT / name
        if root_path.is_file():
            workspace_hashes[name] = digest(read_source(root_path, inputs))
        if name in PRESERVE_BASELINE:
            selected, origin = baseline[name], "maintenance-baseline"
        else:
            require(root_path.is_file(), "Workspace source is missing: " + name)
            selected, origin = read_source(root_path, inputs), "workspace-source"
        source_hashes[name] = digest(selected)
        records = []
        adapted = selected
        if name.endswith(".py"):
            if name in PRESERVE_BASELINE:
                ast.parse(selected.decode("utf-8"), filename=name, feature_version=(3, 6))
                audit_python36(selected.decode("utf-8"), name)
            else:
                baseline_text = baseline.get(name, b"").decode("utf-8")
                text, records = compatible(selected.decode("utf-8"), name, baseline_text)
                adapted = text.encode("utf-8")
        if name.endswith(".json"):
            json.loads(adapted.decode("utf-8"))
        if records:
            patches.extend(difflib.unified_diff(selected.decode("utf-8").splitlines(True),
                           adapted.decode("utf-8").splitlines(True),
                           fromfile="source/" + name, tofile="release/" + name))
        contents[name] = adapted
        origins[name] = {"origin": origin, "source_sha256": source_hashes[name], "adaptations": records}
        adapter_hashes[name] = digest(adapted)
    require(all(contents[name] == baseline[name] for name in PRESERVE_BASELINE),
            "Frozen .63 configuration adapter or its tests changed")
    verify_import_closure(contents)
    verify_inputs(inputs)
    archive = archive_bytes(contents)
    baseline_diff = []
    for name, data in sorted(contents.items()):
        if name in baseline and data == baseline[name]:
            continue
        if Path(name).suffix in {".py", ".js", ".html", ".css", ".svg", ".json", ".yaml"}:
            baseline_diff.extend(difflib.unified_diff(baseline.get(name, b"").decode("utf-8").splitlines(True),
                                 data.decode("utf-8").splitlines(True),
                                 fromfile="baseline/" + name, tofile="release/" + name))
    manifest = {
        "format": FORMAT, "deployment_ip": "198.200.49.63", "release_name": release_name,
        "prepared_at": datetime.now(timezone.utc).isoformat(), "python_syntax": "3.6",
        "application_files": sorted(contents), "release_files": sorted(contents),
        "changed_files": sorted(name for name, data in contents.items() if baseline.get(name) != data),
        "new_files": sorted(set(contents).difference(baseline)),
        "source_sha256": source_hashes, "workspace_source_sha256": workspace_hashes,
        "adapted_sha256": adapter_hashes, "release_sha256": adapter_hashes,
        "baseline_sha256": expected, "file_origins": origins,
        "frozen_full_manifest_sha256": inputs[str(FULL_MANIFEST.resolve())],
        "frozen_auto_manifest_sha256": inputs[str(AUTO_MANIFEST.resolve())],
        "builder_sha256": builder_digest, "archive_sha256": digest(archive),
        "archive_file": "release.tar.gz", "frozen_baseline_files": sorted(PRESERVE_BASELINE),
        "compatibility": {"python36_syntax_passed": True, "known_newer_stdlib_api_audit_passed": True,
                          "python36_runtime_tests_passed": False,
                          "runtime_test_note": "Run the full suite with the actual production Python 3.6 and vendor libraries before deployment."},
        "production_deployment_executed": False, "private_credentials_included": False,
        "state_mutations_performed": [], "old_release_and_manifests_untouched": True,
        "ports_accounts_or_cloud_rules_changed": False,
    }
    if check_only:
        return {"checked_only": True, "application_files": len(contents),
                "changed_files": manifest["changed_files"], "new_files": manifest["new_files"],
                "python_syntax": "3.6", "release_written": False}
    # No replacement or cleanup of existing releases is allowed. A partial
    # directory remains available for review if a write fails; use a new name.
    destination.mkdir()
    for name, data in sorted(contents.items()):
        path = destination / "release" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(data)
    with (destination / "release.tar.gz").open("xb") as stream:
        stream.write(archive)
    with (destination / "compatibility-adapters.patch").open("x", encoding="utf-8", newline="\n") as stream:
        stream.write("".join(patches))
    with (destination / "application-changes.patch").open("x", encoding="utf-8", newline="\n") as stream:
        stream.write("".join(baseline_diff))
    verify_inputs(inputs)
    for name, expected_digest in adapter_hashes.items():
        require(digest((destination / "release" / name).read_bytes()) == expected_digest,
                "Staged output differs: " + name)
    require(digest((destination / "release.tar.gz").read_bytes()) == manifest["archive_sha256"],
            "Staged archive differs")
    with (destination / "manifest.json").open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(manifest, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    return {"prepared": True, "release": str(destination), "application_files": len(contents),
            "changed_files": manifest["changed_files"], "new_files": manifest["new_files"],
            "archive_sha256": manifest["archive_sha256"], "python_syntax": "3.6",
            "deployment_executed": False, "runtime_tests_pending": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-name", default=DEFAULT_RELEASE)
    parser.add_argument("--check", action="store_true", help="Validate in memory without creating a release directory")
    args = parser.parse_args()
    print(json.dumps(build(args.release_name, args.check), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, SyntaxError) as error:
        print("Local staging stopped: " + str(error), file=sys.stderr)
        raise SystemExit(1)
