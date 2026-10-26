"""Local adoption fixtures; no SSH, systemd, firewall or production writes."""
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

FOLDER = Path(__file__).resolve().parent
ROOT = FOLDER.parents[1]
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location('adoption_remote_fixture', str(FOLDER / 'deploy_console_optimization_remote.py'))
remote = importlib.util.module_from_spec(spec)
spec.loader.exec_module(remote)

from panel import server, telemetry, hy2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


class Fixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='console-adoption-fixture-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.app = self.root / 'app'
        self.data = self.root / 'data'
        self.legacy = self.root / 'legacy'
        self.systemd = self.root / 'systemd'
        self.stage = self.root / 'stage'
        self.config = self.root / 'xray/config.json'
        self.caddy = self.root / 'caddy/Caddyfile'
        for path in (self.app / 'panel', self.data, self.legacy, self.systemd, self.stage,
                     self.config.parent, self.caddy.parent):
            path.mkdir(parents=True, exist_ok=True)
        self.caddy.write_text((FOLDER / 'Caddyfile').read_text(encoding='utf-8'), encoding='utf-8')
        values = {'APP': self.app, 'DATA': self.data, 'HY2_ROOT': self.legacy, 'SYSTEMD': self.systemd,
                  'MEMBERS': self.root / 'members', 'XRAY_CONFIG': self.config, 'CADDY_CONFIG': self.caddy}
        for name, value in values.items():
            patch = mock.patch.object(remote, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        patch = mock.patch.object(remote, 'ASSETS', {})
        patch.start()
        self.addCleanup(patch.stop)
        patch = mock.patch.object(remote, 'grp', SimpleNamespace(getgrnam=lambda name: SimpleNamespace(gr_gid=0)))
        patch.start()
        self.addCleanup(patch.stop)
        patch = mock.patch.object(remote, 'atomic', side_effect=self.atomic)
        patch.start()
        self.addCleanup(patch.stop)
        self.commands = []
        patch = mock.patch.object(remote, 'run', side_effect=self.run_command)
        patch.start()
        self.addCleanup(patch.stop)

    def atomic(self, path, payload, attributes=None):
        path = Path(path)
        self.assertIn(self.root, path.parents)
        path.write_bytes(payload)

    def run_command(self, args, check=True, timeout=25):
        self.commands.append((args, check))
        self.assertNotEqual(args[0], 'ssh')
        return subprocess.CompletedProcess(args, 0, b'', b'')

    def synthetic_identity(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'raksmart-hy2.local')])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA256()))
        self.certificate = cert.public_bytes(serialization.Encoding.PEM)
        self.private_key = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption())
        (self.legacy / 'server.crt.pem').write_bytes(self.certificate)
        (self.legacy / 'server.key.pem').write_bytes(self.private_key)
        self.password = 'S' * 43
        text = ('listen: 0.0.0.0:443\n'
                'tls:\n  cert: ' + str(self.legacy / 'server.crt.pem') + '\n'
                '  key: ' + str(self.legacy / 'server.key.pem') + '\n'
                'auth:\n  type: password\n  password: ' + self.password + '\n')
        (self.legacy / 'server.yaml').write_text(text, encoding='utf-8')
        return cert.fingerprint(hashes.SHA256()).hex()

    def owner_state(self, target):
        with mock.patch.object(server.base, 'PORT', 443):
            owner = server.Manager(self.data, '198.200.49.158', self.config, demo=True,
                                   origin='https://198-200-49-158.sslip.io:8443')
        state = copy.deepcopy(owner.state)
        state.update(routing_mode='smart', applied_routing_mode='smart', direct_domains=['direct.example'],
                     applied_direct_domains=['direct.example'], domains=['proxy.example'],
                     applied_domains=['proxy.example'])
        exit_item = {'id': '1a2b3c4d', 'name': 'Kept exit', 'address': '8.8.8.8', 'port': 1080,
                     'username': 'synthetic-account', 'password': 'synthetic-password',
                     'expected_ip': '', 'observed_ip': '8.8.4.4', 'tested_at': 'fixture',
                     'client_id': '11111111-2222-3333-4444-555555555555'}
        state['exits'] = [copy.deepcopy(exit_item)]
        state['applied_exits'] = [copy.deepcopy(exit_item)]
        config, profile = owner.build(state, target)
        # The historical production config predates statistics.
        for field in ('api', 'stats', 'policy'):
            config.pop(field, None)
        state.update(active_id=target, profile=profile, managed_hash=remote.sha(remote.json_bytes(config)))
        state['exits'][0]['password'] = 'unsaved-draft-do-not-apply'
        state['history'] = [{'profile': 'unchanged-history-profile', 'domains': ['old.example'],
                             'rule_token': state['rule_token']}]
        for field in ('profile_token', 'profile_version', 'profile_hash', 'profile_updated'):
            state.pop(field, None)
        self.config.write_bytes(remote.json_bytes(config))
        (self.data / 'state.private.json').write_bytes(remote.json_bytes(state))
        return state, config


class MigrationFixtures(Fixture):
    def check_target(self, target):
        pin = self.synthetic_identity()
        old_state, old_config = self.owner_state(target)
        configuration = {'deployment_ip': '198.200.49.158', 'certificate_sha256': pin,
                         'hy2_sni': 'raksmart-hy2.local'}
        values, observed_state = remote.migration_payloads(configuration, self.root / 'candidate')
        self.assertEqual(old_state, observed_state)
        state = json.loads(values[str(self.data / 'state.private.json')][0])
        config = json.loads(values[str(self.config)][0])
        registry = json.loads(values[str(self.data / 'hy2.private.json')][0])
        self.assertEqual(state['active_id'], target)
        self.assertEqual(state['history'], old_state['history'])
        self.assertEqual(state['exits'], old_state['exits'])
        self.assertEqual(state['applied_exits'], old_state['applied_exits'])
        self.assertEqual(config['outbounds'], old_config['outbounds'])
        bridge = next(rule for rule in config['routing']['rules'] if rule.get('inboundTag') == ['panel-hy2-socks'])
        auto = next(rule for rule in config['routing']['rules'] if rule.get('user') == ['panel-auto@exits.invalid']
                    and rule.get('network') == 'tcp')
        self.assertEqual(bridge['outboundTag'], auto['outboundTag'])
        self.assertEqual(bridge['outboundTag'], 'direct' if target == 'server' else 'static-E1A2B3C4D')
        self.assertEqual(registry['accounts']['admin']['password'], self.password)
        self.assertEqual(registry['certificate_sha256'], pin)
        self.assertEqual(values[str(self.data / 'hy2-server.crt.pem')][0], self.certificate)
        self.assertEqual(values[str(self.data / 'hy2-server.key.pem')][0], self.private_key)
        self.assertEqual(config['api']['listen'], '127.0.0.1:15443')
        self.assertEqual(config['inbounds'][1]['listen'], '127.0.0.1')
        self.assertEqual(config['inbounds'][1]['port'], 16043)
        self.assertIn('type: hysteria2', state['profile'])
        self.assertEqual(old_state['rule_token'], state['rule_token'])
        self.assertNotIn(registry['accounts']['admin']['socks_password'], state['profile'])
        self.assertNotIn(str(self.data / 'backup-key.private.bin'), values)

    def test_current_server_exit_and_unsaved_draft_preserved(self):
        self.check_target('server')

    def test_current_static_exit_and_unsaved_draft_preserved(self):
        self.check_target('1a2b3c4d')

    def test_profile_or_history_edits_are_rejected(self):
        before = {'auto_id': 'kept', 'history': [{'profile': 'old'}], 'rule_token': 'kept'}
        for field in ('auto_id', 'history', 'rule_token'):
            after = copy.deepcopy(before)
            after[field] = 'concurrent'
            with self.assertRaises(RuntimeError):
                remote.state_preserved(before, after)

    def test_caddy_addition_preserves_every_other_byte(self):
        original = self.caddy.read_bytes()
        for payload in (original, original.replace(b'\n', b'\r\n')):
            candidate = remote.caddy_backup_limit(payload)
            self.assertEqual(candidate.count(b'max_size 64KB'), 1)
            self.assertEqual(candidate.count(b'max_size 48MB'), 1)
            self.assertEqual(candidate.count(b'/node-console/api/backups/preview'), 1)
            with self.assertRaises(RuntimeError):
                remote.caddy_backup_limit(candidate)


class RollbackFixtures(Fixture):
    def journal(self):
        source = self.app / 'panel/server.py'
        source.write_bytes(b'old-source')
        self.config.write_bytes(b'old-config')
        state = self.data / 'state.private.json'
        old_state = {'fixture': True, 'managed_hash': remote.sha(b'old-config')}
        state.write_bytes(remote.json_bytes(old_state))
        new_registry = self.data / 'users.private.json'
        paths = [source, self.config, state, new_registry, self.caddy]
        payloads = {str(path): (b'new-' + path.name.encode(), remote.info(path) if path.exists() else remote.default_info())
                    for path in paths}
        payloads[str(new_registry)] = (remote.json_bytes({'version': 1, 'users': []}), remote.default_info())
        configuration = {'deployment_ip': '198.200.49.158', 'origin': 'https://198-200-49-158.sslip.io:8443',
                         'baseline_sha256': {'panel/server.py': remote.sha(b'old-source')},
                         'release_sha256': {'panel/server.py': remote.sha(b'new-server.py')},
                         'release_files': ['panel/server.py'], 'vendor_sha256': {}, 'vendor_files': [],
                         'archive_sha256': 'a' * 64, 'certificate_sha256': 'b' * 64,
                         'hy2_sni': 'raksmart-hy2.local'}
        before = {'fixture': True, 'files': {str(self.caddy): {'sha256': remote.sha(self.caddy.read_bytes())}}}
        journal = remote.checkpoint(self.stage, payloads, configuration, before, old_state)
        return journal, payloads

    def execute_rollback(self, journal):
        patchers = [
            mock.patch.object(remote, 'service', return_value={'LoadState': 'not-found', 'ActiveState': 'inactive'}),
            mock.patch.object(remote, 'wait_panel'),
            mock.patch.object(remote, 'protected_snapshot', return_value={'fixture': True}),
            mock.patch.object(remote, 'compare_protected'),
            mock.patch.object(remote, 'baseline_check', return_value=[]),
            mock.patch.object(remote.os, 'chown', create=True),
            mock.patch.object(remote.os, 'chmod'),
        ]
        for patch in patchers:
            patch.start()
        try:
            remote.rollback(self.stage, journal)
        finally:
            for patch in reversed(patchers):
                patch.stop()

    def check_fault(self, installed):
        journal, payloads = self.journal()
        original = {entry['path']: Path(entry['path']).read_bytes() if Path(entry['path']).exists() else None
                    for entry in journal['entries']}
        for entry in journal['entries'][:installed]:
            Path(entry['path']).write_bytes(payloads[entry['path']][0])
        retained = {
            'traffic.private.json': b'growing-traffic',
            'audit.private.jsonl': b'growing-audit',
            'backup-key.private.bin': b'K' * 32,
        }
        for name, payload in retained.items():
            (self.data / name).write_bytes(payload)
        self.execute_rollback(journal)
        for path, payload in original.items():
            self.assertEqual(Path(path).read_bytes() if Path(path).exists() else None, payload)
        for name, payload in retained.items():
            self.assertEqual((self.data / name).read_bytes(), payload)
        self.assertIn((['systemctl', 'stop', remote.OWNER_HY2], False), self.commands)
        self.assertIn((['systemctl', 'enable', remote.LEGACY], True), self.commands)
        self.assertIn((['systemctl', 'reload', 'caddy.service'], True), self.commands)
        self.assertEqual(journal['phase'], 'rolled-back')

    def test_failure_after_first_source_or_state_replacement_restores_partial_transaction(self):
        self.check_fault(3)

    def test_failure_after_all_replacements_and_service_switch_restores_originals(self):
        self.check_fault(5)

    def test_failure_before_any_replacement_tolerates_missing_owner_service(self):
        self.check_fault(0)

    def test_concurrent_source_edit_refuses_rollback_before_service_stop(self):
        journal, payloads = self.journal()
        (self.app / 'panel/server.py').write_bytes(b'concurrent-user-edit')
        before = len(self.commands)
        with self.assertRaises(RuntimeError):
            self.execute_rollback(journal)
        self.assertEqual(len(self.commands), before)
        self.assertEqual((self.app / 'panel/server.py').read_bytes(), b'concurrent-user-edit')

    def test_missing_marker_and_private_backup_hash_are_checked(self):
        journal, unused = self.journal()
        entry = next(item for item in journal['entries'] if item['before_sha256'] is None)
        (self.stage / entry['missing_marker']).write_bytes(b'tampered')
        with self.assertRaises(RuntimeError):
            remote.validate_rollback(self.stage, journal)

    def test_nonempty_members_refuse_first_adoption_rollback(self):
        journal, unused = self.journal()
        (self.data / 'users.private.json').write_bytes(remote.json_bytes({'version': 1, 'users': [{'id': 'new'}]}))
        with self.assertRaises(RuntimeError):
            remote.validate_rollback(self.stage, journal)


class PackageFixtures(unittest.TestCase):
    def test_exact_frozen_source_and_vendor_archives_parse_locally(self):
        directory = FOLDER / 'console-optimization-release-20261013-01'
        manifest = json.loads((directory / 'manifest.json').read_text(encoding='utf-8'))
        sources = remote.archive_contents(directory / 'release.tar.gz', 'release/', manifest['release_sha256'],
                                          32 * 1024 * 1024)
        vendors = remote.archive_contents(directory / 'vendor.tar.gz', '',
                                          {'vendor/' + name: value for name, value in manifest['vendor_sha256'].items()},
                                          128 * 1024 * 1024)
        self.assertEqual(len(sources), 41)
        self.assertEqual(len(vendors), len(manifest['vendor_files']))
        self.assertEqual(set(vendors), {'vendor/' + name for name in manifest['vendor_files']})

    def test_unsafe_paths_are_rejected(self):
        for name in ('panel/../private.py', '/etc/passwd', 'panel/web/../../auth.private.json',
                     'panel/__pycache__/secret.py', 'panel/auth.private.json'):
            with self.assertRaises(RuntimeError):
                remote.source_name(name)
        for name in ('vendor/../secret', 'vendor/__pycache__/secret.pyc', '/vendor/root'):
            with self.assertRaises(RuntimeError):
                remote.vendor_name(name)

    def test_traffic_cumulative_must_not_decrease(self):
        before = {'version': 1, 'users': {'admin': {'quota_bytes': 0, 'rate_bps': 0,
                  'months': {'2026-10': {'up_bytes': 10, 'down_bytes': 20}}}}}
        after = copy.deepcopy(before)
        after['users']['admin']['months']['2026-10']['down_bytes'] = 30
        remote.compare_ledger(before, after)
        after['users']['admin']['months']['2026-10']['down_bytes'] = 19
        with self.assertRaises(RuntimeError):
            remote.compare_ledger(before, after)


if __name__ == '__main__':
    unittest.main()
