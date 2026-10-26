"""Isolated tests for destructive deployment boundaries; never open SSH."""
import ast
import copy
import importlib.util
import io
import json
import os
import stat
from pathlib import Path
import sys
import tarfile
import tempfile
import types
import unittest
from unittest import mock

FOLDER = Path(__file__).resolve().parent
if os.name != 'posix':
    sys.modules.setdefault('fcntl', types.ModuleType('fcntl'))
spec = importlib.util.spec_from_file_location('console_deploy_remote_under_test', FOLDER / 'deploy_console_optimization_remote.py')
remote = importlib.util.module_from_spec(spec)
spec.loader.exec_module(remote)


class DeploymentBoundaries(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.app = self.root / 'app'
        self.app.mkdir()
        (self.app / 'panel').mkdir()
        self.stage = self.root / 'stage'
        self.stage.mkdir()
        (self.stage / 'code-before').mkdir()
        self.patches = [mock.patch.object(remote, 'APP', self.app),
                        mock.patch.object(remote.subprocess, 'run', side_effect=AssertionError('No host command permitted'))]
        for patch in self.patches:
            patch.start()
        self.addCleanup(self.temporary.cleanup)
        self.addCleanup(lambda: [patch.stop() for patch in reversed(self.patches)])

    def journal(self):
        original, candidate = b'original source\n', b'candidate source\n'
        (self.app / 'panel/server.py').write_bytes(candidate)
        (self.app / 'panel/ports.py').write_bytes(candidate)
        (self.app / 'panel/health.py').write_bytes(original)
        (self.stage / 'code-before/0.source').write_bytes(original)
        (self.stage / 'code-before/1.missing').write_bytes(b'Previously absent\n')
        info = remote.attributes(self.app / 'panel/server.py')
        baseline = {'panel/server.py': remote.sha(original), 'panel/health.py': remote.sha(original)}
        release = dict(baseline, **{'panel/server.py': remote.sha(candidate), 'panel/ports.py': remote.sha(candidate)})
        return {'format': remote.FORMAT, 'archive_sha256': 'a' * 64, 'phase': 'installing',
                'baseline_sha256': baseline, 'release_sha256': release,
                'entries': [{'name': 'panel/server.py', 'before_sha256': remote.sha(original),
                             'after_sha256': remote.sha(candidate), 'attributes': info, 'backup': 'code-before/0.source'},
                            {'name': 'panel/ports.py', 'before_sha256': None,
                             'after_sha256': remote.sha(candidate), 'attributes': None, 'backup': None}]}

    def test_source_and_absolute_paths_reject_escape_private_and_vendor(self):
        for name in ('../outside.py', 'panel/../outside.py', 'panel/vendor/a.py',
                     'panel/__pycache__/a.py', 'panel/auth.private.json', '/panel/server.py', 'panel\\server.py'):
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                remote.source_name(name)
        with self.assertRaises(RuntimeError):
            remote.safe(self.root / '..' / 'outside', missing=True)

    def test_journal_rejects_escape_backup_and_corrupt_original_before_stop(self):
        good = self.journal()
        for key, value in (('name', '../../outside.py'), ('backup', '../outside'), ('before_sha256', 'b' * 64)):
            bad = copy.deepcopy(good)
            bad['entries'][0][key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                remote.rollback(self.stage, bad)

    def test_foreign_changed_and_unchanged_sources_block_rollback_before_stop(self):
        for path in ('panel/server.py', 'panel/health.py'):
            journal = self.journal()
            (self.app / path).write_bytes(b'unrelated edit')
            with self.subTest(path=path), self.assertRaises(RuntimeError):
                remote.rollback(self.stage, journal)

    def test_partial_install_restores_original_and_removes_new_source(self):
        journal = self.journal()
        calls = []
        def fake_run(args, **unused):
            self.assertIn(args, (['systemctl', 'stop', remote.PANEL], ['systemctl', 'start', remote.PANEL]))
            calls.append(args)
        with mock.patch.object(remote, 'run', side_effect=fake_run), \
                mock.patch.object(remote, 'service', return_value={'ActiveState': 'inactive'}), \
                mock.patch.object(remote, 'ready'), \
                mock.patch.object(remote, 'atomic', side_effect=lambda path, payload, info=None: path.write_bytes(payload)):
            remote.rollback(self.stage, journal)
        self.assertEqual((self.app / 'panel/server.py').read_bytes(), b'original source\n')
        self.assertFalse((self.app / 'panel/ports.py').exists())
        self.assertEqual(calls, [['systemctl', 'stop', remote.PANEL], ['systemctl', 'start', remote.PANEL]])
        self.assertFalse(remote.baseline_check({'baseline_sha256': journal['baseline_sha256'],
                                               'release_files': list(journal['release_sha256'])}))

    def test_missing_marker_required(self):
        journal = self.journal()
        (self.stage / 'code-before/1.missing').unlink()
        with self.assertRaises(RuntimeError):
            remote.validate_journal(self.stage, journal)

    def test_baseline_drift_and_new_file_presence_detected(self):
        payload = b'x'
        (self.app / 'panel/server.py').write_bytes(payload)
        config = {'baseline_sha256': {'panel/server.py': remote.sha(payload)},
                  'release_files': ['panel/server.py', 'panel/ports.py']}
        self.assertEqual(remote.baseline_check(config), [])
        (self.app / 'panel/ports.py').write_bytes(payload)
        self.assertEqual(remote.baseline_check(config)[0]['path'], 'panel/ports.py')
        (self.app / 'panel/server.py').write_bytes(b'changed')
        self.assertEqual(len(remote.baseline_check(config)), 2)

    def test_bytecode_removal_is_only_for_changed_python(self):
        cache = self.app / 'panel/__pycache__'
        cache.mkdir()
        for name in ('server.cpython-36.pyc', 'accounts.cpython-36.pyc'):
            (cache / name).write_bytes(b'x')
        vendor = self.app / 'vendor'
        vendor.mkdir()
        (vendor / 'keep.pyc').write_bytes(b'x')
        (self.app / 'panel/server.pyc').write_bytes(b'x')
        removed = remote.bytecode(['panel/server.py', 'panel/web/app.js'])
        self.assertEqual(len(removed), 2)
        self.assertTrue((cache / 'accounts.cpython-36.pyc').exists())
        self.assertTrue((vendor / 'keep.pyc').exists())

    def bundle(self, name='release/panel/server.py', payload=b'x = 1\n', link=False):
        manifest = {'format': remote.SOURCE_FORMAT, 'deployment_ip': '198.200.49.63',
                    'release_files': ['panel/server.py'], 'release_sha256': {'panel/server.py': remote.sha(payload)}}
        target = self.stage / 'release.tar.gz'
        with tarfile.open(str(target), 'w:gz') as archive:
            item = tarfile.TarInfo(name)
            item.size = len(payload)
            if link:
                item.type, item.linkname = tarfile.SYMTYPE, '/etc/passwd'
                archive.addfile(item)
            else:
                archive.addfile(item, io.BytesIO(payload))
        manifest['archive_sha256'] = remote.sha(target.read_bytes())
        serialized = remote.json_data(manifest)
        (self.stage / 'release-manifest.json').write_bytes(serialized)
        return dict(manifest, manifest_sha256=remote.sha(serialized))

    def test_archive_validated_without_extractall(self):
        config = self.bundle()
        self.assertEqual(remote.unpack(self.stage, config), {'panel/server.py': b'x = 1\n'})
        self.assertFalse((self.stage / 'release').exists())

    def test_archive_links_traversal_and_manifest_drift_rejected(self):
        for name, link in (('release/panel/server.py', True), ('release/../outside.py', False)):
            config = self.bundle(name=name, link=link)
            with self.subTest(name=name, link=link), self.assertRaises(RuntimeError):
                remote.unpack(self.stage, config)
        config = self.bundle()
        (self.stage / 'release-manifest.json').write_bytes(b'{}')
        with self.assertRaises(RuntimeError):
            remote.unpack(self.stage, config)

    def traffic(self):
        return {'version': 1, 'users': {'admin': {'quota_bytes': 0, 'rate_bps': 0,
                'months': {'2026-10': {'up_bytes': 10, 'down_bytes': 20}}, 'epoch': 'same',
                'counters': {'up': 10}, 'sample_time': 100,
                'sources': {'hy2': {'epoch': 'same', 'counters': {'down': 20}, 'sample_time': 100}}}}}

    def test_traffic_increases_are_accepted_and_decreases_or_identity_change_rejected(self):
        before = self.traffic()
        after = copy.deepcopy(before)
        after['users']['admin']['months']['2026-10']['up_bytes'] += 1
        remote.compare_ledger(before, after)
        for mutation in ('month', 'legacy_counter', 'source_counter', 'epoch', 'sample', 'identity', 'limits'):
            after = copy.deepcopy(before)
            account = after['users']['admin']
            if mutation == 'month': account['months']['2026-10']['up_bytes'] = 9
            if mutation == 'legacy_counter': account['counters']['up'] = 9
            if mutation == 'source_counter': account['sources']['hy2']['counters']['down'] = 19
            if mutation == 'epoch': account['epoch'] = 'different'
            if mutation == 'sample': account['sources']['hy2']['sample_time'] = 99
            if mutation == 'identity': after['users']['another'] = {}
            if mutation == 'limits': account['rate_bps'] = 100000
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                remote.compare_ledger(before, after)

    def test_remote_helper_parses_as_python36(self):
        ast.parse((FOLDER / 'deploy_console_optimization_remote.py').read_text(encoding='utf-8'), feature_version=(3, 6))

    def test_systemd219_service_query_excludes_unsupported_property(self):
        output = b'ActiveState=active\nSubState=running\nUnitFileState=enabled\nMainPID=123\nLoadState=loaded\nFragmentPath=/etc/systemd/system/xray.service\nExecMainStartTimestampMonotonic=42\nActiveEnterTimestampMonotonic=42\n'
        def observe(args, **unused):
            self.assertNotIn('--property=NRestarts', args)
            return types.SimpleNamespace(stdout=output)
        with mock.patch.object(remote, 'run', side_effect=observe):
            observed = remote.service('xray.service')
        self.assertEqual(observed['MainPID'], '123')
        self.assertEqual(observed['LoadState'], 'loaded')

    def test_template_check_uses_existing_instances_and_checks_fragment(self):
        names = {'xray-panel@.service', 'raksmart-hy2@.service',
                 'xray-panel@0123456789abcdef.service', 'raksmart-hy2@443.service'}
        template_paths = {'/etc/systemd/system/' + name for name in
                          ('xray-panel@.service', 'raksmart-hy2@.service')}
        class FakePath:
            def __init__(self, value): self.value = str(value)
            def __truediv__(self, name): return FakePath(self.value + '/' + name)
            def __str__(self): return self.value
            def exists(self): return self.value in template_paths
        calls = []
        def observe(name):
            calls.append(name)
            self.assertNotIn(name, ('xray-panel@.service', 'raksmart-hy2@.service'))
            template = name.split('@', 1)[0] + '@.service'
            return {'LoadState': 'loaded', 'FragmentPath': '/etc/systemd/system/' + template}
        with mock.patch.object(remote, 'Path', FakePath), \
                mock.patch.object(remote, 'tree_files', return_value=[]), \
                mock.patch.object(remote, 'safe', return_value=types.SimpleNamespace(glob=lambda unused: [])), \
                mock.patch.object(remote, 'file_observation', return_value={'exists': True, 'sha256': 'a' * 64}), \
                mock.patch.object(remote, 'service', side_effect=observe):
            result = remote.unit_files(names)
            self.assertEqual(set(calls), {'xray-panel@0123456789abcdef.service', 'raksmart-hy2@443.service'})
            self.assertEqual(result['loaded:raksmart-hy2@.service']['FragmentPath'], '/etc/systemd/system/raksmart-hy2@.service')
            with mock.patch.object(remote, 'service', return_value={'LoadState': 'loaded', 'FragmentPath': '/unprotected/template'}), \
                    self.assertRaises(RuntimeError):
                remote.unit_files(names)

    def test_member_registry_preflight_rejects_partial_config_and_auto_failover(self):
        identity = '0123456789abcdef'
        state, config, health = [self.root / name for name in ('member-state', 'member-config', 'health')]
        config.write_bytes(b'configuration')
        state.write_text(json.dumps({'managed_hash': remote.sha(config.read_bytes())}))
        health.write_text('{}')
        paths = {str(remote.DATA / 'users' / identity / 'state.private.json'): state,
                 str(Path('/usr/local/etc/xray-members') / identity / 'config.json'): config,
                 str(remote.DATA / 'health.private.json'): health}
        with mock.patch.object(remote, 'safe', side_effect=lambda path, *args, **kwargs: paths[str(path)]):
            remote.registry_preflight({'id': identity})
            config.write_bytes(b'partial new configuration')
            with self.assertRaises(RuntimeError):
                remote.registry_preflight({'id': identity})
            config.write_bytes(b'configuration')
            health.write_text(json.dumps({identity: {'mode': 'auto'}}))
            with self.assertRaises(RuntimeError):
                remote.registry_preflight({'id': identity})
            with self.assertRaises(RuntimeError):
                remote.registry_preflight({'id': 'admin'})

    def test_missing_member_login_requires_explicit_registry_preflight(self):
        item = {'id': '0123456789abcdef', 'username': 'private-member', 'enabled': True}
        with mock.patch.object(remote, 'records', return_value=[item]), \
                mock.patch.object(remote, 'registry_preflight') as inspect, \
                mock.patch.object(remote, 'api', side_effect=AssertionError('No login/reset permitted')):
            with self.assertRaises(RuntimeError):
                remote.quiescent({}, [])
            self.assertEqual(remote.quiescent({}, [], True), 1)
            inspect.assert_called_once_with(item)

    def test_only_verified_sysctl_alias_is_observed_without_mutation(self):
        path = Path('/etc/sysctl.d/99-sysctl.conf')
        target = self.root / 'sysctl.conf'
        target.write_bytes(b'net.core.rmem_max=7340032\n')
        with mock.patch.object(remote.Path, 'is_symlink', return_value=True), \
                mock.patch.object(remote.os, 'readlink', return_value='../sysctl.conf'), \
                mock.patch.object(remote.Path, 'lstat', return_value=types.SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0, st_gid=0)), \
                mock.patch.object(remote, 'safe', return_value=target):
            result = remote.sysctl_alias_observation(path)
            self.assertEqual(result['target_sha256'], remote.sha(target.read_bytes()))
            self.assertEqual(result['mode'], 0o777)
            with mock.patch.object(remote.os, 'readlink', return_value='/unrelated'), self.assertRaises(RuntimeError):
                remote.sysctl_alias_observation(path)
            with self.assertRaises(RuntimeError):
                remote.sysctl_alias_observation(Path('/etc/sysctl.d/other.conf'))


if __name__ == '__main__':
    unittest.main()
