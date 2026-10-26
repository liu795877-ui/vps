import base64
import ipaddress
import json
import os
from pathlib import Path
import tempfile
import unittest
import uuid

import configure_reality as setup

PRIVATE = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
PUBLIC = base64.urlsafe_b64encode(bytes(range(32, 64))).decode().rstrip("=")
USER_ID = "22d0b41d-2eec-437b-b87d-e3e1a64d88a6"
SHORT_ID = "0123456789abcdef"


class ConfigurationTests(unittest.TestCase):
    def test_current_key_output(self):
        self.assertEqual(
            setup.parse_keys(
                f"PrivateKey: {PRIVATE}\nPassword: {PUBLIC}\nHash32: ignored\n"
            ),
            (PRIVATE, PUBLIC),
        )

    def test_legacy_key_output(self):
        self.assertEqual(
            setup.parse_keys(f"Private key: {PRIVATE}\nPublic key: {PUBLIC}\n"),
            (PRIVATE, PUBLIC),
        )

    def test_release_key_output(self):
        self.assertEqual(
            setup.parse_keys(
                f"PrivateKey: {PRIVATE}\nPassword (PublicKey): {PUBLIC}\n"
            ),
            (PRIVATE, PUBLIC),
        )

    def test_malformed_output_is_rejected_without_echoing_it(self):
        for output in ("", "PrivateKey: SECRET_VALUE", f"PrivateKey: {PRIVATE}"):
            with self.subTest(output=bool(output)):
                with self.assertRaises(RuntimeError) as caught:
                    setup.parse_keys(output)
                self.assertNotIn("SECRET_VALUE", str(caught.exception))

    def test_ip_validation(self):
        self.assertEqual(setup.validate_ip(" 8.8.8.8 "), "8.8.8.8")
        for address in ("127.0.0.1", "169.254.169.254", "10.0.0.1", "not-an-ip"):
            with self.subTest(address=address):
                with self.assertRaises(ValueError):
                    setup.validate_ip(address)

    def test_server_has_one_authenticated_inbound(self):
        config = setup.server_config(USER_ID, PRIVATE, SHORT_ID)
        self.assertEqual(len(config["inbounds"]), 1)
        inbound = config["inbounds"][0]
        self.assertEqual(inbound["port"], 8443)
        self.assertEqual(inbound["protocol"], "vless")
        self.assertEqual(inbound["settings"]["decryption"], "none")
        self.assertEqual(str(uuid.UUID(USER_ID)), USER_ID)
        self.assertEqual(
            inbound["settings"]["clients"][0]["flow"], "xtls-rprx-vision"
        )
        reality = inbound["streamSettings"]["realitySettings"]
        self.assertEqual(reality["privateKey"], PRIVATE)
        self.assertEqual(reality["shortIds"], [SHORT_ID])
        self.assertEqual(reality["target"], "www.microsoft.com:443")

    def test_metadata_and_loopback_are_blocked_without_geo_database(self):
        ranges = [ipaddress.ip_network(value) for value in setup.PRIVATE_RANGES]
        for address in ("127.0.0.1", "169.254.169.254", "10.0.0.1", "::1"):
            parsed = ipaddress.ip_address(address)
            self.assertTrue(any(parsed in network for network in ranges))
        config = setup.server_config(USER_ID, PRIVATE, SHORT_ID)
        self.assertEqual(config["routing"]["domainStrategy"], "IPIfNonMatch")
        self.assertEqual(config["routing"]["rules"][0]["outboundTag"], "block")

    def test_client_never_contains_server_private_key(self):
        profile = setup.client_profile("8.8.8.8", USER_ID, PUBLIC, SHORT_ID)
        self.assertIn(PUBLIC, profile)
        self.assertNotIn(PRIVATE, profile)
        self.assertIn(USER_ID, profile)
        self.assertIn("allow-lan: false", profile)
        self.assertIn("DOMAIN,api.ipify.org,VPS-SELECT", profile)
        self.assertIn("MATCH,DIRECT", profile)

    def test_client_and_server_agree(self):
        config = setup.server_config(USER_ID, PRIVATE, SHORT_ID)
        profile = setup.client_profile("8.8.8.8", USER_ID, PUBLIC, SHORT_ID)
        self.assertIn(f"port: {config['inbounds'][0]['port']}", profile)
        self.assertIn(f'short-id: "{SHORT_ID}"', profile)
        self.assertIn('servername: "www.microsoft.com"', profile)
        self.assertIn("flow: xtls-rprx-vision", profile)


@unittest.skipUnless(os.environ.get("XRAY_TEST_BINARY"), "No official test binary")
class OfficialCoreTests(unittest.TestCase):
    def test_official_core_accepts_generated_config(self):
        binary = os.environ["XRAY_TEST_BINARY"]
        private, public = setup.parse_keys(setup.command([binary, "x25519"]).stdout)
        root = Path(__file__).resolve().parent / ".validation"
        root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="config-test-", dir=root) as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                json.dumps(setup.server_config(str(uuid.uuid4()), private, SHORT_ID)),
                encoding="utf-8",
            )
            result = setup.command([binary, "run", "-test", "-config", str(path)])
            self.assertEqual(result.returncode, 0)
            self.assertIn("Configuration OK", result.stdout)
            profile = setup.client_profile("8.8.8.8", USER_ID, public, SHORT_ID)
            self.assertNotIn(private, profile)


if __name__ == "__main__":
    unittest.main()
