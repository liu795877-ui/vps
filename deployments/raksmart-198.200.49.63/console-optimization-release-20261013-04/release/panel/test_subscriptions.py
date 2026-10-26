"""Capability migration and server profile versions, without client claims."""

import copy
import hashlib
import unittest

from panel import subscriptions


class SubscriptionMetadataTests(unittest.TestCase):
    def state(self, profile="profile-content"):
        return {"base": {"inbounds": [{"settings": {"clients": [{"id": "old-primary"}]}}]},
                "auto_id": "old-auto", "rule_token": "old-rule", "public": "old-public",
                "short": "old-short", "profile": profile, "history": [{"config": "old-history"}]}

    def test_migration_adds_capability_without_replacing_any_proxy_identity(self):
        state = self.state()
        original = copy.deepcopy(state)
        self.assertTrue(subscriptions.ensure_metadata(state))
        self.assertTrue(subscriptions.valid_token(state["profile_token"]))
        self.assertEqual(state["profile_version"], 1)
        self.assertEqual(state["profile_hash"], hashlib.sha256(b"profile-content").hexdigest())
        for key, value in original.items():
            self.assertEqual(state[key], value)
        after = copy.deepcopy(state)
        self.assertFalse(subscriptions.ensure_metadata(state))
        self.assertEqual(state, after)

    def test_only_profile_content_changes_its_version_and_timestamp(self):
        previous = self.state()
        subscriptions.ensure_metadata(previous)
        state = copy.deepcopy(previous)
        state["exits"] = ["a draft change"]
        state["profile_token"] = "A" * 43
        subscriptions.update_metadata(state, previous)
        self.assertEqual(state["profile_version"], previous["profile_version"])
        self.assertEqual(state["profile_updated"], previous["profile_updated"])
        state["profile"] += "\nnew node"
        subscriptions.update_metadata(state, previous)
        self.assertEqual(state["profile_version"], previous["profile_version"] + 1)
        self.assertNotEqual(state["profile_hash"], previous["profile_hash"])
        saved = copy.deepcopy(state)
        self.assertFalse(subscriptions.ensure_metadata(state))
        self.assertEqual(state, saved)

    def test_not_yet_generated_profile_and_rollback_are_honest_versions(self):
        state = self.state(None)
        subscriptions.ensure_metadata(state)
        self.assertEqual(state["profile_version"], 0)
        self.assertIsNone(state["profile_hash"])
        self.assertIsNone(state["profile_updated"])
        previous = copy.deepcopy(state)
        state["profile"] = "first"
        subscriptions.update_metadata(state, previous)
        self.assertEqual(state["profile_version"], 1)
        previous = copy.deepcopy(state)
        state["profile"] = "second"
        subscriptions.update_metadata(state, previous)
        previous = copy.deepcopy(state)
        state["profile"] = "first"
        subscriptions.update_metadata(state, previous)
        self.assertEqual(state["profile_version"], 3)

    def test_same_object_save_uses_stored_hash_to_detect_profile_change(self):
        state = self.state()
        subscriptions.ensure_metadata(state)
        state["profile"] = "changed in place"
        subscriptions.update_metadata(state, state)
        self.assertEqual(state["profile_version"], 2)

    def test_metadata_has_no_import_or_sync_claim_and_url_is_account_scoped(self):
        state = self.state()
        subscriptions.ensure_metadata(state)
        public = subscriptions.metadata(state, "https://panel.example/", "/node-console/")
        self.assertEqual(set(public), {"version", "hash", "updated", "url", "download_ready"})
        self.assertEqual(public["url"], "https://panel.example/node-console/subscription/"
                         + state["profile_token"] + ".yaml")
        self.assertTrue(public["download_ready"])
        self.assertNotIn("url", subscriptions.metadata(state, "https://panel.example", "/", False))
        self.assertEqual(subscriptions.metadata(state, "https://panel.example", "/")["url"],
                         "https://panel.example/subscription/" + state["profile_token"] + ".yaml")

    def test_malformed_private_metadata_is_not_silently_revoked(self):
        for field, value in (("profile_token", "short-token"), ("profile_version", True),
                             ("profile_version", -1), ("profile", b"invalid")):
            state = self.state()
            state[field] = value
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    subscriptions.ensure_metadata(state)


if __name__ == "__main__":
    unittest.main()
