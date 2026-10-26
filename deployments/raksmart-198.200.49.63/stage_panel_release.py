"""Prepare only application sources, retaining tested Python 3.6 adapters."""
import ast
import base64
import hashlib
import json
from pathlib import Path
import re
import secrets
import sys
import tarfile

FOLDER = Path(__file__).resolve().parent
ROOT = FOLDER.parents[1]
REFERENCE = FOLDER.parent / 'raksmart-198.200.49.158' / 'panel-release'
RELEASE = FOLDER / 'panel-release'
ORIGIN = 'https://198-200-49-63.sslip.io:8443'


def scalar(value):
    value = value.strip()
    return json.loads(value) if value.startswith('"') else value


def prepare():
    RELEASE.mkdir(exist_ok=True)
    copied = []
    for candidate in REFERENCE.rglob('*'):
        if (candidate.is_file() and '__pycache__' not in candidate.parts
                and '.private.' not in candidate.name and candidate.suffix != '.pyc'):
            relative = candidate.relative_to(REFERENCE)
            destination = RELEASE / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(candidate.read_bytes())
            copied.append(relative.as_posix())
    current = 'from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer'
    compatible = '''from http.server import BaseHTTPRequestHandler, HTTPServer
try:
    from http.server import ThreadingHTTPServer
except ImportError:
    from socketserver import ThreadingMixIn

    class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True'''
    content = (ROOT / 'panel/server.py').read_text(encoding='utf-8')
    content = content.replace(current, compatible)
    content = content.replace('temporary.unlink(missing_ok=True)', 'base.unlink_if_exists(temporary)')
    content = content.replace('temporary_profile.unlink(missing_ok=True)', 'base.unlink_if_exists(temporary_profile)')
    if '} | {' in content:
        raise RuntimeError('Unconverted dictionary merge in panel source')
    (RELEASE / 'panel/server.py').write_text(content, encoding='utf-8')
    for name in ['panel/__init__.py', 'panel/node_info.py', 'panel/routing.py',
                 'panel/services-routing.json', 'panel/rules/domestic-dns.yaml',
                 'panel/web/app.js', 'panel/web/index.html', 'panel/web/style.css',
                 'panel/web/mark.svg']:
        (RELEASE / name).write_bytes((ROOT / name).read_bytes())
        if name not in copied:
            copied.append(name)
    reference_tests = (REFERENCE / 'panel/test_panel.py').read_text(encoding='utf-8')
    adoption = reference_tests.split('class ExistingRaksmartNodeTests', 1)[1].split('class PanelTests', 1)[0]
    tests = (ROOT / 'panel/test_panel.py').read_text(encoding='utf-8')
    tests = 'import base64\n' + tests.replace('class PanelTests', 'class ExistingRaksmartNodeTests' + adoption + 'class PanelTests', 1)
    tests = tests.replace('capture_output=True, text=True,', 'stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,')
    (RELEASE / 'panel/test_panel.py').write_text(tests, encoding='utf-8')
    for candidate in RELEASE.rglob('*.py'):
        ast.parse(candidate.read_text(encoding='utf-8'), filename=str(candidate), feature_version=(3, 6))

    sys.path.insert(0, str(RELEASE))
    import configure_reality as base
    import configure_static_exits as static
    from panel.server import password_record
    profile_text = (FOLDER / 'raksmart-reality.private.yaml').read_text(encoding='utf-8')
    config = json.loads((FOLDER / 'panel-adoption-server.private.json').read_text(encoding='utf-8'))
    original = config['inbounds'][0]
    identity = original['settings']['clients'][0]['id']
    reality = original['streamSettings']['realitySettings']
    public_match = re.search(r'^\s+public-key:\s*(.+)\s*$', profile_text, re.M)
    if not public_match:
        raise RuntimeError('The existing 63 profile has no public key')
    public = scalar(public_match.group(1))
    for label, expected in [('uuid', identity), ('server', '198.200.49.63'),
                            ('servername', reality['serverNames'][0]),
                            ('short-id', reality['shortIds'][0])]:
        match = re.search(r'^\s+' + re.escape(label) + r':\s*(.+)\s*$', profile_text, re.M)
        if not match or scalar(match.group(1)) != expected:
            raise RuntimeError('Existing 63 profile does not match the inspected node: ' + label)
    adoption_text = base.client_profile('198.200.49.63', identity, public, reality['shortIds'][0],
                                       target=reality['serverNames'][0])
    static.inspect_base(config, adoption_text, '198.200.49.63')
    (FOLDER / 'panel-base.private.yaml').write_text(adoption_text, encoding='utf-8')
    login_path = FOLDER / 'panel-login.private.json'
    if login_path.exists():
        login = json.loads(login_path.read_text(encoding='utf-8'))
        if login.get('url') != ORIGIN + '/node-console/' or login.get('username') != 'admin':
            raise RuntimeError('Existing panel login belongs to a different site')
    else:
        login = {'url': ORIGIN + '/node-console/', 'username': 'admin',
                 'password': secrets.token_urlsafe(24)}
        login_path.write_text(json.dumps(login, indent=2), encoding='utf-8')
    (FOLDER / 'panel-auth-seed.private.json').write_text(json.dumps(password_record(login['password'])), encoding='utf-8')
    archive_path = FOLDER / 'panel-release.private.tar.gz'
    with tarfile.open(archive_path, 'w:gz') as archive:
        for name in sorted(copied):
            archive.add(RELEASE / name, arcname='release/' + name)
    manifest = {'origin': ORIGIN, 'python_syntax': '3.6', 'application_files': sorted(copied),
                'archive_sha256': hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                'adoption_config_sha256': hashlib.sha256((FOLDER / 'panel-adoption-server.private.json').read_bytes()).hexdigest(),
                'initial_exit_count': 0, 'identities_from_158_copied': False}
    (FOLDER / 'panel-release-manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print(json.dumps({'prepared': True, 'files': len(copied), 'python_syntax': '3.6',
                      'adoption_matches_63': True, 'independent_admin_login_saved': True}))


if __name__ == '__main__':
    prepare()
