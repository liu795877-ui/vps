"""Encrypted HY2 identity completeness, rollback and legacy restore coverage."""

import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import unittest

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from panel import backups, hy2, server
from panel import test_operations as legacy


class AcceleratedBackupTests(legacy.Fixture):
    PASSWORD = "synthetic-backup-password-2026"

    def setUp(self):
        super().setUp()
        # The generic demo fixture uses TCP 8443; adopted HY2 hosts use 443.
        state = copy.deepcopy(self.owner.state)
        state["base"]["inbounds"][0]["port"] = 443
        config, profile = self.owner.build(state, state["active_id"])
        payload = server.json_bytes(config)
        server.atomic_write(self.owner.config_path, payload)
        state.update(profile=profile, managed_hash=server.digest(payload))
        self.owner.save(state)
        self.backup = backups.BackupManager(self.accounts, clock=self.clock)

    def records(self):
        return [self.accounts._record("admin")] + list(self.accounts.records)

    def enable_hy2(self):
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "raksmart-hy2.local")])
        certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("raksmart-hy2.local")]), critical=False)
            .sign(key, hashes.SHA256(), default_backend()))
        data = {"version": 1, "enabled": True, "certificate_sha256": certificate.fingerprint(hashes.SHA256()).hex(),
                "sni": "raksmart-hy2.local", "accounts": {}}
        for number, record in enumerate(self.records(), 1):
            data["accounts"][record["id"]] = {"port": record["port"], "password": "P" * 42 + str(number),
                "api_secret": "A" * 42 + str(number), "socks_password": "S" * 42 + str(number)}
        self.original_registry = copy.deepcopy(data)
        server.atomic_write(self.owner.directory / "hy2.private.json", server.json_bytes(data))
        server.atomic_write(self.owner.directory / "hy2-server.crt.pem", certificate.public_bytes(serialization.Encoding.PEM))
        server.atomic_write(self.owner.directory / "hy2-server.key.pem", key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.acceleration = hy2.Integration(self.accounts)
        self.accounts.acceleration = self.acceleration
        for record in self.records():
            manager = self.accounts._manager(record)
            running_state = copy.deepcopy(manager.state)
            running_state["exits"] = copy.deepcopy(running_state["applied_exits"])
            config, profile = manager.build(running_state, manager.state["active_id"])
            payload = server.json_bytes(config)
            server.atomic_write(manager.config_path, payload)
            state = copy.deepcopy(manager.state)
            state.update(profile=profile, managed_hash=server.digest(payload))
            manager.save(state)
        return data

    def snapshot(self):
        return self.backup._snapshot(self.records())

    def refresh_config(self, record):
        manager = self.accounts._manager(record)
        config, profile = manager.build(manager.state, manager.state["active_id"])
        payload = server.json_bytes(config)
        server.atomic_write(manager.config_path, payload)
        state = copy.deepcopy(manager.state)
        state.update(profile=profile, managed_hash=server.digest(payload))
        manager.save(state)

    @staticmethod
    def replace_file(snapshot, name, value, is_json=True):
        payload = server.json_bytes(value) if is_json else value
        snapshot["files"][name].update(data=base64.b64encode(payload).decode("ascii"),
                                       sha256=hashlib.sha256(payload).hexdigest())

    def portable(self):
        item = self.backup.create(password=self.PASSWORD)
        exported = self.backup.export(item["id"], self.PASSWORD)
        return self.backup.download(exported["download_token"])[0]

    def preview(self, archive):
        return self.backup.preview(base64.b64encode(archive).decode("ascii"), self.PASSWORD)

    def test_encrypted_snapshot_contains_registry_and_tls_pair_without_plaintext(self):
        self.enable_hy2()
        archive = self.portable()
        self.assertNotIn(self.original_registry["accounts"]["admin"]["password"].encode(), archive)
        self.assertNotIn(b"PRIVATE KEY", archive)
        snapshot = json.loads(backups.decrypt(archive, password=self.PASSWORD))
        self.assertTrue(backups.HY2_FILES <= set(snapshot["files"]))
        records, decoded = self.backup._validate_snapshot(snapshot)
        self.assertEqual(len(records), 2)
        self.assertEqual(json.loads(decoded["system/hy2.private.json"]), self.original_registry)
        self.assertTrue(any("HY2" in warning for warning in self.preview(archive)["warnings"]))

    def test_hy2_registry_and_certificate_pair_missing_are_rejected(self):
        self.enable_hy2()
        complete = self.snapshot()
        for name in backups.HY2_FILES:
            snapshot = copy.deepcopy(complete)
            del snapshot["files"][name]
            with self.assertRaises(server.PanelError):
                self.backup._validate_snapshot(snapshot)

    def test_registry_unknown_account_missing_account_and_wrong_port_rejected(self):
        self.enable_hy2()
        original = self.snapshot()
        data = self.original_registry
        cases = []
        missing = copy.deepcopy(data)
        del missing["accounts"][self.member["id"]]
        cases.append(missing)
        unknown = copy.deepcopy(data)
        unknown["accounts"]["f" * 16] = unknown["accounts"].pop(self.member["id"])
        cases.append(unknown)
        wrong_port = copy.deepcopy(data)
        wrong_port["accounts"][self.member["id"]]["port"] = 2443
        cases.append(wrong_port)
        for candidate in cases:
            snapshot = copy.deepcopy(original)
            self.replace_file(snapshot, "system/hy2.private.json", candidate)
            with self.assertRaises(server.PanelError):
                self.backup._validate_snapshot(snapshot)

    def test_corrupt_certificate_wrong_private_key_and_wrong_pin_rejected(self):
        self.enable_hy2()
        original = self.snapshot()
        corrupt = copy.deepcopy(original)
        self.replace_file(corrupt, "system/hy2-server.crt.pem", b"invalid certificate", is_json=False)
        wrong_key = copy.deepcopy(original)
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.replace_file(wrong_key, "system/hy2-server.key.pem", key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()), is_json=False)
        wrong_pin = copy.deepcopy(original)
        registry = copy.deepcopy(self.original_registry)
        registry["certificate_sha256"] = "0" * 64
        self.replace_file(wrong_pin, "system/hy2.private.json", registry)
        for candidate in (corrupt, wrong_key, wrong_pin):
            with self.assertRaises(server.PanelError):
                self.backup._validate_snapshot(candidate)

    def test_forwarding_password_mismatch_rejected_despite_valid_managed_hash(self):
        self.enable_hy2()
        snapshot = self.snapshot()
        config = json.loads(base64.b64decode(snapshot["files"]["admin/config.json"]["data"]))
        config["inbounds"][1]["settings"]["accounts"][0]["pass"] = "different-forwarding-password"
        self.replace_file(snapshot, "admin/config.json", config)
        state = json.loads(base64.b64decode(snapshot["files"]["admin/state.json"]["data"]))
        state["managed_hash"] = snapshot["files"]["admin/config.json"]["sha256"]
        self.replace_file(snapshot, "admin/state.json", state)
        with self.assertRaises(server.PanelError):
            self.backup._validate_snapshot(snapshot)

    def test_live_hy2_rotation_invalidates_an_existing_restore_preview(self):
        self.enable_hy2()
        preview = self.preview(self.portable())
        self.acceleration.rotate(self.accounts._record("admin"))
        with self.assertRaises(server.PanelError):
            self.backup.restore(preview["preview_token"], "RESTORE")
        self.assertNotEqual(self.acceleration.data, self.original_registry)

    def test_complete_restore_preserves_tls_and_hy2_and_reloads_before_member_validation(self):
        self.enable_hy2()
        archive = self.portable()
        expected = {name: (self.owner.directory / name).read_bytes()
                    for name in ("hy2.private.json", "hy2-server.crt.pem", "hy2-server.key.pem")}
        self.acceleration.rotate(self.accounts._record("admin"))
        self.refresh_config(self.accounts._record("admin"))
        preview = self.preview(archive)
        restored = self.backup.restore(preview["preview_token"], "RESTORE")
        self.assertTrue(restored["restored"])
        self.assertEqual(self.acceleration.data, self.original_registry)
        for name, payload in expected.items():
            self.assertEqual((self.owner.directory / name).read_bytes(), payload)
        self.assertTrue(self.accounts._manager(self.member).state["profile"])

    def test_legacy_snapshot_restores_reality_and_removes_hy2_registry_and_tls(self):
        old = self.portable()
        self.enable_hy2()
        preview = self.preview(old)
        self.assertTrue(any("REALITY" in warning for warning in preview["warnings"]))
        restored = self.backup.restore(preview["preview_token"], "RESTORE")
        self.assertTrue(restored["restored"])
        self.assertFalse(self.acceleration.enabled)
        self.assertIsNone(self.acceleration.data)
        for name in ("hy2.private.json", "hy2-server.crt.pem", "hy2-server.key.pem"):
            self.assertFalse((self.owner.directory / name).exists())
        for record in self.records():
            manager = self.accounts._manager(record)
            self.assertEqual(len(json.loads(manager.config_path.read_text(encoding="utf-8"))["inbounds"]), 1)
            self.assertNotIn("type: hysteria2", manager.state["profile"] or "")

    def test_failed_restore_rolls_back_original_hy2_credentials_tls_and_config(self):
        self.enable_hy2()
        archive = self.portable()
        self.acceleration.rotate(self.accounts._record("admin"))
        # Regenerate the admin config with its newly rotated SOCKS identity.
        self.refresh_config(self.accounts._record("admin"))
        original = self.snapshot()
        expected_registry = copy.deepcopy(self.acceleration.data)
        preview = self.preview(archive)
        failed = [False]

        def runtime(action, records):
            if action == "start" and not failed[0]:
                failed[0] = True
                raise RuntimeError("startup failed")

        self.backup._runtime = runtime
        with self.assertRaises(server.PanelError):
            self.backup.restore(preview["preview_token"], "RESTORE")
        current = self.snapshot()
        self.assertEqual({name: item["sha256"] for name, item in current["files"].items()},
                         {name: item["sha256"] for name, item in original["files"].items()})
        self.assertEqual(self.acceleration.data, expected_registry)


if __name__ == "__main__":
    unittest.main()
