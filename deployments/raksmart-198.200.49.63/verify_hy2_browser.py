"""Prepare or run read-only HY2 integration browser acceptance.

Preparation reads only local public source files and checks JavaScript syntax.
Execution uses the existing restricted physical-WLAN CONNECT bridge; Edge
performs normal trusted HTTPS verification. Only login/logout and GET requests
are permitted by the browser scenario. No save or configuration action occurs.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import socketserver
import subprocess
import threading
import traceback

from frontend_motion_access import FOLDER, NO_WINDOW, physical_wifi
from run_user_guide_browser import Handler


EXPECTATIONS = FOLDER / 'hy2-browser-expectations.json'
SCENARIO = FOLDER / 'hy2-integration-browser.mjs'
ROOT = FOLDER.parents[1]
PUBLIC_FILES = ('panel/web/index.html', 'panel/web/app.js', 'panel/web/style.css')
RELEASE_MANIFEST = FOLDER / 'hy2-integration-release-manifest.json'
RELEASE = FOLDER / 'hy2-integration-release'


def prepare():
    subprocess.run(['node', '--check', str(SCENARIO)], capture_output=True, check=True,
                   timeout=20, creationflags=NO_WINDOW)
    manifest = json.loads(RELEASE_MANIFEST.read_text(encoding='utf-8'))
    if manifest.get('deployment_ip') != '198.200.49.63':
        raise RuntimeError('The reviewed integration manifest targets another server')
    hashes = {name: manifest['source_sha256'][name] for name in PUBLIC_FILES}
    for name in PUBLIC_FILES:
        if hashes[name] != hashlib.sha256((RELEASE / name).read_bytes()).hexdigest():
            raise RuntimeError('The frozen integration release asset differs from its reviewed manifest')
    data = {'prepared_at': datetime.now(timezone.utc).isoformat(), 'deployment_ip': '198.200.49.63',
            'expected_frontend_source': RELEASE_MANIFEST.name, 'frozen_frontend_sha256': hashes,
            'scenario_sha256': hashlib.sha256(SCENARIO.read_bytes()).hexdigest(),
            'server_requests': 0, 'configuration_mutations': 0}
    EXPECTATIONS.write_text(json.dumps(data, indent=2), encoding='utf-8')
    print(json.dumps({'prepared': True, 'server_requests': 0, 'configuration_mutations': 0,
                      'expected_frontend_files': len(PUBLIC_FILES)}))
    return 0


def run():
    expectations = json.loads(EXPECTATIONS.read_text(encoding='utf-8'))
    if expectations.get('scenario_sha256') != hashlib.sha256(SCENARIO.read_bytes()).hexdigest():
        raise RuntimeError('Prepare the current browser scenario before running it')
    server = None
    with (FOLDER / 'hy2-browser.private.log').open('w', encoding='utf-8') as log:
        try:
            physical_wifi()
            server = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Handler)
            server.daemon_threads = True
            threading.Thread(target=server.serve_forever, daemon=True).start()
            environment = os.environ.copy()
            environment['NODE_CONSOLE_TEST_PROXY'] = 'http://127.0.0.1:' + str(server.server_address[1])
            result = subprocess.run(['node', str(SCENARIO)], env=environment, timeout=360,
                                    capture_output=True, stdin=subprocess.DEVNULL, creationflags=NO_WINDOW)
            log.write(result.stdout.decode('utf-8', errors='replace'))
            log.write(result.stderr.decode('utf-8', errors='replace'))
            print('63 HY2 browser acceptance passed.' if result.returncode == 0 else
                  '63 HY2 browser acceptance failed; inspect its sanitized report and private diagnostic log.')
            return result.returncode
        except Exception:
            traceback.print_exc(file=log)
            print('63 HY2 browser acceptance failed; inspect its private diagnostic log.')
            return 1
        finally:
            if server is not None:
                server.shutdown()
                server.server_close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--prepare', action='store_true')
    mode.add_argument('--run', action='store_true')
    args = parser.parse_args()
    raise SystemExit(prepare() if args.prepare else run())
