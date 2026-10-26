"""Validate a frozen console on .63 Python 3.6 inside an exclusive /tmp stage.

The default performs local package/review checks only. --run is required for
SSH; --run --inspect-only reads Python/vendor metadata without staging tests.
Validation uploads ONE archive and preserves its independent temporary stage.
It never installs a release, imports the production panel, or runs a service.
"""

import argparse
import ast
import base64
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile


FOLDER = Path(__file__).resolve().parent
DEFAULT_RELEASE = "console-optimization-release-20261012-02"
DEFAULT_REPORT = "console-optimization-python36-validation-20261012-02.json"
FORMAT = "vps-console-optimization-release-v1"
RUNTIME_NAMES = {
    "__init__", "accelerated_client", "accounts", "audit", "backups", "diagnostics",
    "health", "hy2", "node_info", "ports", "provisioning", "routing", "server",
    "subscriptions", "telemetry", "membership", "access_records",
}
REVIEW_NOTES = {
    "test_configure_reality": "Pure config; optional official-core tests disabled.",
    "test_configure_static_exits": "Temporary file transactions and mocked commands; core tests disabled.",
    "panel.test_accounts": "Temporary demo; production fixture redirects CONFIG_ROOT and mocks commands/listeners.",
    "panel.test_panel": "Temporary demo/loopback HTTP; .63 adoption fixture uses explicit temporary paths.",
    "panel.test_multiuser_http": "Temporary demo/loopback HTTP; stop telemetry can attempt reads, blocked by runner guard.",
    "panel.test_enhancements_http": "Temporary demo/loopback HTTP; rotation/deletion telemetry reads blocked by runner guard.",
    "panel.test_operations": "Temporary demo; telemetry and LinuxControls use injected runners; restore callbacks are fake.",
    "panel.test_hy2_integration": "Temporary account fixture; non-demo validation, service callbacks and query APIs mocked.",
    "panel.test_hy2_telemetry": "Temporary demo with synthetic provider, statistics runner and controls.",
    "panel.test_hy2_backups": "Temporary demo, generated synthetic TLS identity, injected runtime failures.",
    "panel.test_entrance_backups": "Temporary demo, synthetic credentials/TLS and local restore-failure callbacks.",
    "panel.test_entrances": "Temporary demo; non-demo binds mocked and LinuxControls runner injected.",
    "panel.test_provisioning": "Temporary demo and loopback HTTP; creation/start remains demo.",
    "panel.test_service_status": "Temporary demo; service status commands are mocked to synthetic systemd results.",
    "panel.test_accelerated_client": "Pure client-profile data; optional Mihomo validation disabled.",
    "panel.test_subscriptions": "In-memory hash/token/state operations only.",
    "panel.test_membership": "Temporary demo/loopback HTTP; injected clock, controls, counters and mocked systemd only.",
    "panel.test_access_records": "Temporary SQLite/demo/loopback HTTP; synthetic journals and mocked subprocess only.",
    "panel.test_routing": "Pure configuration; optional core and external route tests disabled.",
}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_file(path):
    require(path.is_file() and not path.is_symlink(), "Missing or linked local input: " + str(path))
    return path


def allowed_name(name):
    require(isinstance(name, str) and "\\" not in name, "Unexpected application path")
    path = PurePosixPath(name)
    require(not path.is_absolute() and path.parts and all(part not in ("..", ".") for part in path.parts),
            "Unsafe archive path")
    module = name[:-3].replace("/", ".") if name.endswith(".py") else None
    allowed = module in REVIEW_NOTES or name in {"configure_reality.py", "configure_static_exits.py"}
    allowed = allowed or (len(path.parts) == 2 and path.parts[0] == "panel" and
                          path.suffix == ".py" and path.stem in RUNTIME_NAMES)
    allowed = allowed or name in {"panel/services-routing.json", "panel/smart-routing.json",
                                  "panel/rules/domestic-dns.yaml"}
    allowed = allowed or (len(path.parts) >= 3 and path.parts[:2] == ("panel", "web") and
                          path.suffix.lower() in {".js", ".css", ".html", ".svg", ".png", ".jpg",
                                                  ".jpeg", ".webp", ".ico", ".woff", ".woff2", ".ttf"})
    require(allowed and ".private." not in path.name, "Unreviewed application file: " + name)


def local_review(release_name):
    require(re.fullmatch(r"console-optimization-release-\d{8}-[A-Za-z0-9_-]+", release_name),
            "Unexpected release directory name")
    release = FOLDER / release_name
    require(release.is_dir() and not release.is_symlink(), "Frozen release directory is required")
    manifest_data = safe_file(release / "manifest.json").read_bytes()
    manifest = json.loads(manifest_data.decode("utf-8"))
    require(manifest.get("format") == FORMAT and manifest.get("deployment_ip") == "198.200.49.63",
            "Unexpected frozen manifest")
    names = manifest.get("release_files")
    hashes = manifest.get("release_sha256")
    require(isinstance(names, list) and isinstance(hashes, dict) and len(names) == len(set(names)) and
            set(names) == set(hashes), "Incomplete frozen application index")
    for name in names:
        allowed_name(name)
    archive_path = safe_file(release / "release.tar.gz")
    archive = archive_path.read_bytes()
    require(digest(archive) == manifest.get("archive_sha256"), "Frozen archive hash differs")
    expected = {"release/" + name for name in names}
    tests = []
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        members = bundle.getmembers()
        require(len(members) == len(expected) and {item.name for item in members} == expected and
                all(item.isfile() and 0 <= item.size < 30 * 1024 * 1024 for item in members) and
                sum(item.size for item in members) < 30 * 1024 * 1024, "Unsafe or unreviewed archive content")
        for item in members:
            name = item.name[len("release/"):]
            content = bundle.extractfile(item).read()
            require(digest(content) == hashes[name], "Archive source hash differs: " + name)
            require(safe_file(release / "release" / name).read_bytes() == content,
                    "Frozen directory and archive differ: " + name)
            if name.endswith(".py"):
                ast.parse(content.decode("utf-8"), filename=name, feature_version=(3, 6))
            if PurePosixPath(name).name.startswith("test_"):
                module = name[:-3].replace("/", ".")
                require(module in REVIEW_NOTES, "Test module has not had an isolation review: " + module)
                tests.append({"module": module, "sha256": hashes[name], "review": REVIEW_NOTES[module]})
    expected_tests = set(REVIEW_NOTES)
    if "panel/membership.py" not in names:
        expected_tests.discard("panel.test_membership")
    if "panel/access_records.py" not in names:
        expected_tests.discard("panel.test_access_records")
    require({item["module"] for item in tests} == expected_tests, "Reviewed full test suite is incomplete")
    return {
        "release": str(release), "archive": str(archive_path), "archive_sha256": digest(archive),
        "manifest_sha256": digest(manifest_data), "release_files": names,
        "release_sha256": hashes, "tests": sorted(tests, key=lambda item: item["module"]),
        "optional_core_tests_disabled": ["XRAY_TEST_BINARY", "MIHOMO_TEST_BINARY", "SMART_ROUTING_CORE", "SMART_ROUTING_CACHE"],
    }


INSPECT_PROGRAM = r'''
import json, sys
from pathlib import Path
sys.dont_write_bytecode = True
vendor = Path('/opt/vps-panel/vendor')
if not vendor.is_dir() or vendor.is_symlink():
    raise RuntimeError('Existing vendor directory is required')
sys.path.insert(0, str(vendor))
import cryptography
from cryptography import x509
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
print(json.dumps({'python_version': list(sys.version_info[:3]), 'python_executable': sys.executable,
    'vendor_directory': str(vendor), 'cryptography_version': cryptography.__version__,
    'cryptography_file': cryptography.__file__, 'aesgcm_imported': True,
    'pbkdf2_imported': True, 'x509_imported': True, 'dont_write_bytecode': sys.dont_write_bytecode}))
'''


VALIDATION_PROGRAM = r'''
import base64, builtins, collections, contextlib, hashlib, io, json, os, socket, subprocess, sys, tarfile, tempfile, time, traceback, unittest
from pathlib import Path
sys.dont_write_bytecode = True
configuration = json.loads(base64.b64decode(CONFIGURATION_B64).decode('utf-8'))
stage = Path(configuration['stage'])
if not stage.is_dir() or stage.is_symlink() or stage.parent != Path('/tmp') or not stage.name.startswith('vps-console-validation-'):
    raise RuntimeError('Unexpected isolated stage')
if (stage.stat().st_mode & 0o777) != 0o700 or stage.stat().st_uid != os.geteuid():
    raise RuntimeError('Isolated stage permissions differ')
if sys.version_info[:2] != (3, 6):
    raise RuntimeError('Actual Python 3.6 is required')
archive = stage / 'release.tar.gz'
archive_data = archive.read_bytes()
if hashlib.sha256(archive_data).hexdigest() != configuration['archive_sha256']:
    raise RuntimeError('Remote archive checksum differs')
names = configuration['release_files']
expected = set('release/' + name for name in names)
with tarfile.open(str(archive), 'r:gz') as bundle:
    members = bundle.getmembers()
    if len(members) != len(expected) or set(item.name for item in members) != expected or not all(item.isfile() for item in members) or sum(item.size for item in members) >= 30 * 1024 * 1024:
        raise RuntimeError('Unsafe isolated archive')
    for item in members:
        name = item.name[len('release/'):]
        if name not in names or any(part in ('.', '..') for part in Path(name).parts):
            raise RuntimeError('Unreviewed archive path')
        data = bundle.extractfile(item).read()
        if hashlib.sha256(data).hexdigest() != configuration['release_sha256'][name]:
            raise RuntimeError('Remote source checksum differs')
        destination = stage / 'release' / name
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with destination.open('xb') as stream:
            stream.write(data)
        destination.chmod(0o600)
        if name.endswith('.py'):
            compile(data, name, 'exec')
scratch = stage / 'scratch'
scratch.mkdir(mode=0o700)
tempfile.tempdir = str(scratch)
for key in ('TMPDIR', 'TEMP', 'TMP'):
    os.environ[key] = str(scratch)
for key in list(os.environ):
    if key in configuration['optional_core_tests_disabled'] or key.lower().endswith('_proxy'):
        del os.environ[key]
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
release = stage / 'release'
os.chdir(str(release))
sys.path.insert(0, str(release))
sys.path.insert(1, '/opt/vps-panel/vendor')
import cryptography
vendor_metadata = {'version': cryptography.__version__, 'file': cryptography.__file__}
if not str(Path(cryptography.__file__).resolve()).startswith('/opt/vps-panel/vendor/'):
    raise RuntimeError('The installed vendor library was not selected')

# Constrain the application's ordinary file APIs to this one temporary stage.
# Reads of standard-library/vendor modules remain available; no production
# panel module is imported. All unmocked subprocesses are blocked, including
# the demo fixtures' accidental telemetry reads.
guarded_root = stage.resolve()
real_readlink = os.readlink
def confined(path, directory_fd=None):
    if isinstance(path, int):
        path = real_readlink('/proc/self/fd/' + str(path))
    else:
        path = os.fspath(path)
        if isinstance(path, bytes):
            path = os.fsdecode(path)
        if directory_fd is not None and not os.path.isabs(path):
            path = os.path.join(real_readlink('/proc/self/fd/' + str(directory_fd)), path)
    value = Path(path).resolve()
    if value != guarded_root and guarded_root not in value.parents:
        raise RuntimeError('Isolated validation blocked a write outside its temporary stage')

for module in (builtins, io):
    original = module.open
    # Bind a fresh wrapper per module rather than sharing a mutable closure.
    def open_wrapper(original):
        def call(file, mode='r', *args, **kwargs):
            if any(marker in mode for marker in ('w', 'a', 'x', '+')):
                confined(file)
            return original(file, mode, *args, **kwargs)
        return call
    module.open = open_wrapper(original)
original_os_open = os.open
def guarded_os_open(path, flags, *args, **kwargs):
    if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
        confined(path, kwargs.get('dir_fd'))
    return original_os_open(path, flags, *args, **kwargs)
os.open = guarded_os_open
def path_wrapper(original):
    def call(path, *args, **kwargs):
        confined(path, kwargs.get('dir_fd'))
        return original(path, *args, **kwargs)
    return call
for name in ('mkdir', 'rmdir', 'unlink', 'remove', 'chmod', 'chown', 'lchown', 'utime', 'truncate', 'fchmod', 'fchown', 'ftruncate'):
    if hasattr(os, name):
        setattr(os, name, path_wrapper(getattr(os, name)))
def two_path_wrapper(original):
    def call(source, destination, *args, **kwargs):
        confined(source, kwargs.get('src_dir_fd'))
        confined(destination, kwargs.get('dst_dir_fd'))
        return original(source, destination, *args, **kwargs)
    return call
for name in ('rename', 'replace', 'link', 'symlink'):
    setattr(os, name, two_path_wrapper(getattr(os, name)))

blocked = collections.Counter()
def no_subprocess(*args, **kwargs):
    arguments = args[0] if args else kwargs.get('args', [])
    tool = Path(str(arguments[0])).name if isinstance(arguments, (list, tuple)) and arguments else 'process'
    blocked[tool] += 1
    raise RuntimeError('Isolated validation blocked an unmocked subprocess')
subprocess.Popen = no_subprocess
def no_process_control(*args, **kwargs):
    blocked['os_process_control'] += 1
    raise RuntimeError('Isolated validation blocked process control')
for name in ('system', 'kill', 'killpg', 'execl', 'execle', 'execlp', 'execlpe', 'execv', 'execve', 'execvp', 'execvpe', 'spawnl', 'spawnle', 'spawnlp', 'spawnlpe', 'spawnv', 'spawnve', 'spawnvp', 'spawnvpe'):
    if hasattr(os, name):
        setattr(os, name, no_process_control)

# Tests can only bind fresh loopback ports and connect back to those ports.
test_ports = set()
original_bind, original_connect, original_connect_ex = socket.socket.bind, socket.socket.connect, socket.socket.connect_ex
def test_bind(connection, address):
    if not isinstance(address, tuple) or address[0] not in ('127.0.0.1', '::1') or address[1] != 0:
        raise RuntimeError('Isolated validation only permits ephemeral loopback listeners')
    response = original_bind(connection, address)
    test_ports.add(connection.getsockname()[1])
    return response
def local_address(address):
    if not isinstance(address, tuple) or address[0] not in ('127.0.0.1', '::1') or address[1] not in test_ports:
        raise RuntimeError('Isolated validation blocked a connection outside its test listeners')
def test_connect(connection, address):
    local_address(address)
    return original_connect(connection, address)
def test_connect_ex(connection, address):
    local_address(address)
    return original_connect_ex(connection, address)
socket.socket.bind, socket.socket.connect, socket.socket.connect_ex = test_bind, test_connect, test_connect_ex

class SafeResult(unittest.TextTestResult):
    def _exc_info_to_string(self, error, test):
        # Keep file/line positions without printing exception values, account
        # secrets or assertion diffs. The reviewed test ID remains in the log.
        frames = traceback.extract_tb(error[2])
        return '\n'.join('  File {0}, line {1}, in {2}'.format(frame.filename, frame.lineno, frame.name)
                         for frame in frames) + '\n' + error[0].__name__ + ' (values omitted)\n'

log_path = stage / 'validation.log'
started = time.monotonic()
with log_path.open('x', encoding='utf-8') as log:
    log_path.chmod(0o600)
    with contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
        suite = unittest.defaultTestLoader.loadTestsFromNames([item['module'] for item in configuration['tests']])
        result = unittest.TextTestRunner(stream=log, verbosity=2, resultclass=SafeResult).run(suite)
report = {'success': result.wasSuccessful(), 'scope': 'isolated actual Python 3.6 unittest',
    'python_version': list(sys.version_info[:3]), 'python_executable': sys.executable,
    'vendor': vendor_metadata, 'stage': str(stage), 'log': str(log_path),
    'archive_sha256': configuration['archive_sha256'], 'manifest_sha256': configuration['manifest_sha256'],
    'elapsed_seconds': round(time.monotonic() - started, 3),
    'tests_run': result.testsRun, 'passed': result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped),
    'skipped': len(result.skipped), 'failures': len(result.failures), 'errors': len(result.errors),
    'skip_details': [{'test': test.id(), 'reason': reason} for test, reason in result.skipped],
    'failure_tests': [test.id() for test, unused in result.failures],
    'error_tests': [test.id() for test, unused in result.errors],
    'blocked_unmocked_subprocesses': dict(blocked), 'optional_core_tests_disabled': configuration['optional_core_tests_disabled'],
    'write_guard_enforced': True, 'network_guard': 'fresh ephemeral loopback test listeners only',
    'production_application_updated': False, 'production_data_updated': False,
    'proxy_or_firewall_commands_executed': False, 'bytecode_writes_disabled': True,
    'production_acceptance_performed': False, 'stage_retained': True}
report_path = stage / 'validation-report.json'
with report_path.open('x', encoding='utf-8') as stream:
    json.dump(report, stream, indent=2)
    stream.write('\n')
report_path.chmod(0o600)
print(json.dumps(report, sort_keys=True))
raise SystemExit(0 if report['success'] else 1)
'''


def remote_command(program):
    require("\nCONSOLE_VALIDATION_PROGRAM\n" not in program, "Unexpected remote program delimiter")
    return "PYTHONDONTWRITEBYTECODE=1 nice -n 15 python3 -B -u - <<'CONSOLE_VALIDATION_PROGRAM'\n" + program + "\nCONSOLE_VALIDATION_PROGRAM"


def strict_connect(ssh):
    keys_path = safe_file(ssh.HOST_KEYS)
    expected = digest(keys_path.read_bytes())
    keys = ssh.paramiko.HostKeys()
    keys.load(str(keys_path))
    require(keys.lookup("[" + ssh.HOST + "]:" + str(ssh.PORT)) is not None,
            "The existing pinned .63 SSH host key is required")
    original = ssh.paramiko.SSHClient
    class StrictClient(original):
        def set_missing_host_key_policy(self, policy):
            require(isinstance(policy, ssh.paramiko.RejectPolicy), "Host-key auto-adoption is prohibited")
            return super().set_missing_host_key_policy(policy)
        def save_host_keys(self, filename):
            raise RuntimeError("This validation must not write SSH host keys")
    ssh.paramiko.SSHClient = StrictClient
    try:
        client = ssh.connect()
    finally:
        ssh.paramiko.SSHClient = original
    if not keys_path.is_file() or digest(keys_path.read_bytes()) != expected:
        client.close()
        raise RuntimeError("Pinned SSH host keys changed")
    return client


def report_path(name):
    require(re.fullmatch(r"console-optimization-[A-Za-z0-9_-]+\.json", name), "Use a new named validation JSON report")
    path = FOLDER / name
    require(not path.exists() and not path.is_symlink() and not path.with_suffix(".log").exists(),
            "Validation report or log already exists; choose a new report name")
    return path


def run(review, output_path, inspect_only=False):
    import ssh_access as ssh
    client = strict_connect(ssh)
    result = {"success": False, "release_tests_run": False, "remote_stage": None,
              "started_at": datetime.now(timezone.utc).isoformat(), "helper_sha256": digest(Path(__file__).read_bytes())}
    try:
        code, output, unused = ssh.execute(client, remote_command(INSPECT_PROGRAM), timeout=30)
        require(code == 0, "Remote Python/vendor inspection failed")
        environment = json.loads(output)
        result["environment"] = environment
        require(environment["python_version"][:2] == [3, 6] and environment["dont_write_bytecode"],
                "Expected actual Python 3.6 with disabled bytecode writes")
        if inspect_only:
            result.update(success=True, read_only=True, release_uploaded=False)
            return result
        result.update(archive_sha256=review["archive_sha256"], manifest_sha256=review["manifest_sha256"],
                      test_source_review=review["tests"])
        program = "import json, os, tempfile\np = tempfile.mkdtemp(prefix='vps-console-validation-', dir='/tmp')\nos.chmod(p, 0o700)\nprint(json.dumps({'stage': p}))"
        code, output, unused = ssh.execute(client, remote_command(program), timeout=15)
        require(code == 0, "Could not create an exclusive validation stage")
        stage = json.loads(output)["stage"]
        require(re.fullmatch(r"/tmp/vps-console-validation-[A-Za-z0-9_-]+", stage), "Unexpected validation stage")
        result["remote_stage"] = stage
        archive = safe_file(Path(review["archive"])).read_bytes()
        require(digest(archive) == review["archive_sha256"], "Frozen archive changed before upload")
        with client.open_sftp() as sftp:
            with sftp.open(stage + "/release.tar.gz", "wx") as stream:
                stream.write(archive)
            sftp.chmod(stage + "/release.tar.gz", 0o600)
        configuration = {key: review[key] for key in ("archive_sha256", "manifest_sha256", "release_files",
                         "release_sha256", "tests", "optional_core_tests_disabled")}
        configuration["stage"] = stage
        encoded = base64.b64encode(json.dumps(configuration).encode("utf-8")).decode("ascii")
        program = "CONFIGURATION_B64 = '" + encoded + "'\n" + VALIDATION_PROGRAM
        ast.parse(program, feature_version=(3, 6))
        result["release_tests_run"] = True
        code, output, error = ssh.execute(client, remote_command(program), timeout=600)
        with output_path.with_suffix(".log").open("x", encoding="utf-8", newline="\n") as log:
            with client.open_sftp() as sftp:
                try:
                    with sftp.open(stage + "/validation.log", "r") as remote_log:
                        payload = remote_log.read()
                    log.write(payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else payload)
                except OSError:
                    log.write("Validation stopped before unittest logging; exception values omitted.\n")
        require(bool(output.strip()), "Remote validation did not return a report; retained stage requires review")
        verification = json.loads(output)
        result.update(verification=verification, success=code == 0 and verification.get("success") is True,
                      remote_exit_code=code, remote_stage_retained=True)
        return result
    except Exception as error:
        result.update(success=False, error_type=type(error).__name__,
                      failure="Isolated validation did not complete; inspect its retained stage and report.")
        return result
    finally:
        client.close()
        with output_path.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
            stream.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-name", default=DEFAULT_RELEASE)
    parser.add_argument("--release-directory", help="Absolute path to a frozen release in this deployment folder")
    parser.add_argument("--report-name", default=DEFAULT_REPORT)
    parser.add_argument("--run", action="store_true", help="Explicitly connect and run the isolated validation")
    parser.add_argument("--inspect-only", action="store_true", help="With --run, read Python/vendor metadata only")
    args = parser.parse_args()
    require(not args.inspect_only or args.run, "--inspect-only requires explicit --run")
    if args.release_directory:
        directory = Path(args.release_directory).resolve()
        require(directory.parent == FOLDER.resolve(), "Release directory must remain in this .63 deployment folder")
        args.release_name = directory.name
    review = None if args.inspect_only else local_review(args.release_name)
    if not args.run:
        print(json.dumps({"local_review_passed": True, "archive_sha256": review["archive_sha256"],
                          "reviewed_test_modules": len(review["tests"]), "remote_connected": False,
                          "actual_python36_tests_run": False, "explicit_run_required": True}, indent=2))
        return 0
    path = report_path(args.report_name)
    result = run(review, path, args.inspect_only)
    verification = result.get("verification", {})
    print(json.dumps({"success": result["success"], "report": str(path), "remote_stage": result.get("remote_stage"),
                      "python_version": result.get("environment", {}).get("python_version"),
                      "tests_run": verification.get("tests_run", 0), "passed": verification.get("passed", 0),
                      "skipped": verification.get("skipped", 0), "failures": verification.get("failures", 0),
                      "errors": verification.get("errors", 0), "production_updated": False}, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, SyntaxError) as error:
        print("Isolated validation stopped: " + str(error), file=sys.stderr)
        raise SystemExit(1)
