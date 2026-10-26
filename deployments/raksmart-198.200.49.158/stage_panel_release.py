"""Synchronize console updates while keeping this VPS's Python 3.6 adapters."""
import ast
from pathlib import Path
import tarfile

FOLDER = Path(__file__).resolve().parent
ROOT = FOLDER.parents[1]
RELEASE = FOLDER / 'panel-release'


def prepare():
    content = (ROOT / 'panel/server.py').read_text(encoding='utf-8')
    current = 'from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer'
    compatible = '''from http.server import BaseHTTPRequestHandler, HTTPServer
try:
    from http.server import ThreadingHTTPServer
except ImportError:
    from socketserver import ThreadingMixIn

    class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True'''
    if current in content:
        content = content.replace(current, compatible)
    content = content.replace('temporary.unlink(missing_ok=True)', 'base.unlink_if_exists(temporary)')
    content = content.replace('temporary_profile.unlink(missing_ok=True)', 'base.unlink_if_exists(temporary_profile)')
    legacy = '''                return {key: item.get(key) for key in (
                    "id", "name", "address", "port", "expected_ip", "observed_ip", "tested_at"
                )} | {"authenticated": bool(item.get("username")),
                     "active": item["id"] == state["active_id"],
                     "pending": not applied or configured([item]) != configured([applied])}'''
    replacement = '''                result = {key: item.get(key) for key in (
                    "id", "name", "address", "port", "expected_ip", "observed_ip", "tested_at"
                )}
                result.update(authenticated=bool(item.get("username")),
                              active=item["id"] == state["active_id"],
                              pending=not applied or configured([item]) != configured([applied]))
                return result'''
    content = content.replace(legacy, replacement)
    if '} | {' in content:
        raise RuntimeError('Unconverted dictionary merge in candidate server')
    ast.parse(content, feature_version=(3, 6))
    (RELEASE / 'panel/server.py').write_text(content, encoding='utf-8')
    for name in ['panel/node_info.py', 'panel/web/app.js', 'panel/web/index.html', 'panel/web/style.css']:
        (RELEASE / name).write_bytes((ROOT / name).read_bytes())

    previous = (RELEASE / 'panel/test_panel.py').read_text(encoding='utf-8')
    adoption = previous.split('class ExistingRaksmartNodeTests', 1)[1].split('class PanelTests', 1)[0]
    tests = (ROOT / 'panel/test_panel.py').read_text(encoding='utf-8')
    tests = tests.replace('class PanelTests', 'class ExistingRaksmartNodeTests' + adoption + 'class PanelTests', 1)
    if 'import base64' not in tests:
        tests = 'import base64\n' + tests
    ast.parse(tests, feature_version=(3, 6))
    (RELEASE / 'panel/test_panel.py').write_text(tests, encoding='utf-8')

    with tarfile.open(FOLDER / 'panel-features-validation.tar.gz', 'w:gz') as archive:
        for candidate in RELEASE.rglob('*'):
            if (candidate.is_file() and candidate.suffix != '.pyc' and
                    '__pycache__' not in candidate.parts and '.private.' not in candidate.name):
                archive.add(candidate, arcname=candidate.relative_to(RELEASE).as_posix())
    print('Compatible candidate sources and isolated validation archive prepared.')


if __name__ == '__main__':
    prepare()
