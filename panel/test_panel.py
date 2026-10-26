import copy
import http.client
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock

import configure_reality as base
from panel import server
from panel import routing


class DomainNormalizationTests(unittest.TestCase):
    def test_links_drop_paths_parameters_and_keep_the_exact_host_scope(self):
        self.assertEqual(server.clean_domains([
            "https://mooc1.chaoxing.com/mycourse/studentstudy?chapterId=1256244322&enc=private#chapter",
            "http://MOOC1.CHAOXING.COM.:80/account",
            "//mooc1.chaoxing.com:443/course",
            "mooc1.chaoxing.com:8443/studentstudy?redirect=https://example.com/",
            "mooc1.chaoxing.com",
        ]), ["mooc1.chaoxing.com"])
        self.assertFalse(server.domain_overlaps("mooc1.chaoxing.com", "passport.chaoxing.com"))
        self.assertTrue(server.domain_overlaps("mooc1.chaoxing.com", "video.mooc1.chaoxing.com"))

    def test_domains_and_idna_links_share_normalization_and_deduplication(self):
        self.assertEqual(server.clean_domains([
            "视频.cn", "https://视频.CN:443/课程?token=discarded",
            "//XN--CY2A840A.CN./", "Github.com.", "https://github.com/?account=@me", "",
        ]), ["xn--cy2a840a.cn", "github.com"])

    def test_outer_spaces_and_blank_rows_preserve_copy_paste_behavior(self):
        self.assertEqual(server.clean_domains([
            "", " ", "   ", "  Github.com   ", " https://GITHUB.COM/account?token=discarded  ",
            "  https://example.com/  ",
        ]), ["github.com", "example.com"])

    def test_invalid_inputs_do_not_echo_private_urls(self):
        invalid = [
            "socks5://example.com:443/", "ftp://example.com/", "https:example.com",
            "https:/example.com", "https:///example.com", "/example.com/path", "https://",
            "https://user:secret@example.com/", "//user@example.com/", "https://@example.com/",
            "https://example.com:", "example.com:0", "example.com:65536", "example.com:-1",
            "example.com:+443", "example.com:４４３", "https://example.com:80:443/",
            "https://[example.com]/", "https://[]/", "https://[v1.example.com]/", "https://example.com..",
            "https://127.0.0.1/", "127.0.0.1:443/path", "https://[::1]:443/",
            "127.1", "https://127.000.000.001/", "https://0x7f.0x1/",
            "localhost", "https://localhost:443/", "https://study.localhost/",
            "example.com ", "https://exa mple.com/",
            "https://example.com/path with space", "https://example.com/\tpath",
            "\nhttps://example.com/", "\thttps://example.com/", "https://example.com/\x00", "example.com\x7f",
            "https://example.com/\u200b", "https://example.com/\\path",
            "https://example.com\\@other.com/", "example.com,DIRECT", "*.example.com",
        ]
        for value in invalid:
            with self.subTest(value=value):
                private_url = value + "?token=private-test-token"
                with self.assertRaises(server.PanelError) as raised:
                    server.clean_domains([private_url])
                self.assertNotIn(private_url, str(raised.exception))
                self.assertNotIn("private-test-token", str(raised.exception))

    def test_domain_list_limits_and_types_are_preserved(self):
        self.assertEqual(server.clean_domains(["example.com"] * 100), ["example.com"])
        self.assertEqual(server.clean_domains([]), [])
        for values in ("example.com", None, [None], [123], ["example.com"] * 101):
            with self.subTest(values=values):
                with self.assertRaises(server.PanelError):
                    server.clean_domains(values)


class PanelTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="node-panel-test-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.manager = server.Manager(self.directory, "8.8.8.8", self.directory / "xray.json", demo=True)

    def add_exit(self, name="Exit A", address="proxy.example.com"):
        return self.manager.edit_exit({"name": name, "address": address, "port": 1080,
                                       "auth": "credentials", "username": "test-only-user",
                                       "password": "test-only-secret", "expected_ip": ""})["id"]

    def wait(self, job):
        for _ in range(100):
            result = self.manager.jobs[job["job_id"]]
            if result["status"] != "running":
                return result
            time.sleep(0.03)
        self.fail("Job did not complete")

    def profile_node_names(self):
        profile = self.manager.state["profile"].split("\nproxies:\n", 1)[1].split("\nproxy-groups:", 1)[0]
        return [json.loads(value) for value in re.findall(r"^  - name: (.+)$", profile, re.M)]

    def auto_fragment(self):
        proxies = self.manager.state["profile"].split("\nproxies:\n", 1)[1].split("\nproxy-groups:", 1)[0]
        for fragment in re.split(r"(?m)^  - name: ", proxies)[1:]:
            if json.loads(fragment.splitlines()[0]) == "AUTO · 网页切换":
                return fragment.rstrip()
        self.fail("The stable AUTO node is missing")

    def auto_route(self):
        config = json.loads(self.manager.config_path.read_bytes())
        return next(rule["outboundTag"] for rule in config["routing"]["rules"]
                    if rule.get("user") == ["panel-auto@exits.invalid"] and rule.get("network") == "tcp")

    def test_public_state_never_exposes_passwords_usernames_or_node_credentials(self):
        self.add_exit()
        data = json.dumps(self.manager.public_state())
        self.assertNotIn("test-only-user", data)
        self.assertNotIn("test-only-secret", data)
        self.assertNotIn(self.manager.state["auto_id"], data)
        self.assertNotIn(self.manager.state["rule_token"], data)
        self.assertNotIn(self.manager.state["base"]["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"], data)

    def test_blank_credentials_preserve_existing_and_explicit_no_auth_clears_them(self):
        identity = self.add_exit()
        request = {"id": identity, "name": "Exit A", "address": "proxy.example.com", "port": 1080,
                   "auth": "credentials", "username": "", "password": "", "expected_ip": ""}
        self.manager.edit_exit(request)
        self.assertEqual(self.manager.state["exits"][0]["password"], "test-only-secret")
        request["auth"] = "none"
        self.manager.edit_exit(request)
        self.assertEqual(self.manager.state["exits"][0]["password"], "")

    def test_auto_identity_and_profile_stay_stable_when_switching_exit(self):
        a = self.add_exit()
        b = self.add_exit("Exit B")
        initial = copy.deepcopy(self.manager.state)
        config_a, profile_a = self.manager.build(initial, a)
        config_b, profile_b = self.manager.build(initial, b)
        self.assertEqual(profile_a, profile_b)
        self.assertIn("AUTO", profile_a)
        self.assertNotIn("test-only-secret", profile_a)
        auto_a = config_a["inbounds"][0]["settings"]["clients"][-1]
        auto_b = config_b["inbounds"][0]["settings"]["clients"][-1]
        self.assertEqual(auto_a, auto_b)
        self.assertNotEqual(config_a["routing"]["rules"][-1]["outboundTag"],
                            config_b["routing"]["rules"][-1]["outboundTag"])
        self.assertEqual(config_a["routing"]["rules"][0], initial["base"]["routing"]["rules"][0])

    def test_one_profile_contains_both_fixed_exits_with_independent_routes(self):
        selected = self.add_exit("Exit A", "proxy-a.example.com")
        self.add_exit("Exit B", "proxy-b.example.com")
        state = copy.deepcopy(self.manager.state)
        for mode in routing.MODES:
            with self.subTest(mode=mode):
                state["routing_mode"] = mode
                config, profile = self.manager.build(state, selected)
                fragments = profile.split("\nproxies:\n", 1)[1].split("\nproxy-groups:", 1)[0]
                names = [json.loads(value) for value in re.findall(r"^  - name: (.+)$", fragments, re.M)]
                identities = [json.loads(value) for value in re.findall(r"^    uuid: (.+)$", fragments, re.M)]
                exported = dict(zip(names, identities))
                self.assertEqual(set(exported), {"AUTO · 网页切换", "出口 · Exit A", "出口 · Exit B"})
                if mode == "manual":
                    group = profile.split("\nproxy-groups:\n", 1)[1].split("\nrules:\n", 1)[0]
                    choices = [json.loads(value) for value in re.findall(r"^      - (.+)$", group, re.M)]
                else:
                    groups = json.loads(profile.split("\nproxy-groups: ", 1)[1].splitlines()[0])
                    choices = next(group["proxies"] for group in groups if group["name"] == "STATIC-SELECT")
                self.assertEqual(set(choices), set(exported))
                clients = {client["id"]: client for client in config["inbounds"][0]["settings"]["clients"]}
                outbounds = {outbound["tag"]: outbound for outbound in config["outbounds"]}
                tags = []
                for item in state["exits"]:
                    client = clients[exported["出口 · " + item["name"]]]
                    routes = [rule for rule in config["routing"]["rules"] if rule.get("user") == [client["email"]]]
                    tcp = next(rule for rule in routes if rule.get("network") == "tcp")
                    udp = next(rule for rule in routes if rule.get("network") == "udp")
                    self.assertEqual(udp["outboundTag"], "block")
                    outbound = outbounds[tcp["outboundTag"]]
                    self.assertEqual(outbound["settings"]["servers"][0]["address"], item["address"])
                    tags.append(tcp["outboundTag"])
                self.assertEqual(len(set(tags)), 2)
                self.assertNotIn("test-only-user", profile)
                self.assertNotIn("test-only-secret", profile)

    def test_client_config_tracks_applied_nodes_after_add_rename_and_delete(self):
        initial = self.manager.public_state()["client_config"]
        self.assertEqual(initial["exit_count"], 0)
        self.assertEqual(initial["nodes"], [])
        self.assertFalse(initial["refresh_required"])
        a = self.add_exit()
        self.wait(self.manager.start_job("apply", a))
        b = self.add_exit("Exit B")
        draft = self.manager.public_state()["client_config"]
        self.assertEqual(draft["exit_count"], 1)
        self.assertEqual(draft["nodes"], ["出口 · Exit A"])
        self.assertFalse(draft["refresh_required"])
        self.assertTrue(draft["fixed_nodes_refresh_required"])
        self.assertNotIn("出口 · Exit B", self.profile_node_names())
        self.assertEqual(self.wait(self.manager.start_job("apply", b))["status"], "success")
        current = self.manager.public_state()["client_config"]
        self.assertEqual(current["group"], "STATIC-SELECT")
        self.assertEqual(current["auto_node"], "AUTO · 网页切换")
        self.assertEqual(current["exit_count"], 2)
        self.assertFalse(current["refresh_required"])
        previous_profile = self.manager.state["profile"]
        self.manager.edit_exit({"id": b, "name": "Renamed B", "address": "proxy.example.com",
                                "port": 1080, "auth": "credentials", "username": "",
                                "password": "", "expected_ip": ""})
        renamed = self.manager.public_state()["client_config"]
        self.assertEqual(renamed["nodes"], ["出口 · Exit A", "出口 · Exit B"])
        self.assertFalse(renamed["refresh_required"])
        self.assertTrue(renamed["fixed_nodes_refresh_required"])
        self.assertEqual(self.manager.state["profile"], previous_profile)
        self.assertEqual(self.wait(self.manager.start_job("apply", b))["status"], "success")
        self.assertIn("出口 · Renamed B", self.profile_node_names())
        self.assertNotIn("出口 · Exit B", self.profile_node_names())
        self.manager.delete_exit(a)
        deleted = self.manager.public_state()["client_config"]
        self.assertEqual(deleted["exit_count"], 2)
        self.assertFalse(deleted["refresh_required"])
        self.assertTrue(deleted["fixed_nodes_refresh_required"])
        self.assertEqual(self.wait(self.manager.start_job("apply", b))["status"], "success")
        final = self.manager.public_state()["client_config"]
        self.assertEqual(final["nodes"], ["出口 · Renamed B"])
        self.assertEqual(final["exit_count"], 1)
        self.assertFalse(final["refresh_required"])
        self.assertNotIn("出口 · Exit A", self.profile_node_names())

    def test_apply_and_rollback_restore_the_previous_exit(self):
        a = self.add_exit()
        b = self.add_exit("Exit B")
        self.assertEqual(self.wait(self.manager.start_job("apply", a))["status"], "success")
        self.assertTrue(self.manager.public_state()["dirty"])
        self.assertEqual([item["id"] for item in self.manager.state["applied_exits"]], [a])
        first = self.manager.config_path.read_bytes()
        self.assertEqual(self.wait(self.manager.start_job("apply", b))["status"], "success")
        self.assertEqual(self.manager.state["active_id"], b)
        self.assertEqual(self.wait(self.manager.start_job("rollback"))["status"], "success")
        self.assertEqual(self.manager.state["active_id"], a)
        self.assertEqual(json.loads(first), json.loads(self.manager.config_path.read_bytes()))

    def test_download_preserves_the_existing_server_reality_hostname(self):
        identity = self.add_exit()
        state = copy.deepcopy(self.manager.state)
        reality = state["base"]["inbounds"][0]["streamSettings"]["realitySettings"]
        reality.update(target="www.cloudflare.com:443", serverNames=["www.cloudflare.com"])
        config, profile = self.manager.build(state, identity)
        self.assertEqual(config["inbounds"][0]["streamSettings"], state["base"]["inbounds"][0]["streamSettings"])
        self.assertEqual(profile.count('servername: "www.cloudflare.com"'), 2)

    def test_failed_proxy_preflight_does_not_change_running_config(self):
        identity = self.add_exit(address="fail.example.com")
        original = self.manager.config_path.read_bytes()
        result = self.wait(self.manager.start_job("apply", identity))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(self.manager.config_path.read_bytes(), original)
        self.assertIsNone(self.manager.state["active_id"])

    def test_job_metadata_identifies_only_the_failed_selected_branch_without_exposing_credentials(self):
        selected = self.add_exit()
        failed = self.add_exit("Exit B", "fail.example.com")
        result = self.wait(self.manager.start_job("apply", failed))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["exit_id"], failed)
        self.assertEqual(result["testing_id"], failed)
        self.assertEqual(self.wait(self.manager.start_job("apply", selected))["status"], "success")
        self.assertEqual(self.manager.state["active_id"], selected)
        self.assertEqual([item["id"] for item in self.manager.state["applied_exits"]], [selected])
        public = json.dumps(self.manager.public_state()["job"])
        self.assertNotIn("test-only-secret", public)
        self.assertNotIn("test-only-user", public)

    def test_server_exit_with_zero_static_exits_keeps_the_auto_entry_available(self):
        original = copy.deepcopy(self.manager.state["base"])
        identity = self.manager.state["auto_id"]
        result = self.wait(self.manager.start_job("apply", server.SERVER_EXIT_ID))
        self.assertEqual(result["status"], "success")
        self.assertEqual(self.auto_route(), "direct")
        self.assertEqual(self.profile_node_names(), ["AUTO · 网页切换"])
        config = json.loads(self.manager.config_path.read_bytes())
        primary = [{key: value for key, value in client.items() if key != "email"}
                   for client in config["inbounds"][0]["settings"]["clients"][:-1]]
        self.assertEqual(primary, original["inbounds"][0]["settings"]["clients"])
        self.assertEqual(config["api"]["listen"], "127.0.0.1:" + str(15000 + original["inbounds"][0]["port"]))
        self.assertEqual(config["api"]["services"], ["StatsService"])
        self.assertEqual(config["inbounds"][0]["settings"]["clients"][-1]["id"], identity)
        self.assertEqual(config["routing"]["rules"][:-2], original["routing"]["rules"])
        self.assertEqual(config["outbounds"], original["outbounds"])
        public = self.manager.public_state()
        self.assertEqual(public["active_target"], "server")
        self.assertTrue(public["server_exit"]["active"])
        self.assertEqual(public["server_exit"]["observed_ip"], "8.8.8.8")
        self.assertIsNone(public["active"])
        self.assertTrue(public["download_ready"])
        self.assertFalse(public["dirty"])

    def test_static_server_new_static_switches_leave_old_auto_client_settings_identical(self):
        a = self.add_exit()
        self.assertEqual(self.wait(self.manager.start_job("apply", a))["status"], "success")
        old_auto = self.auto_fragment()
        old_identity = self.manager.state["auto_id"]
        self.assertEqual(self.wait(self.manager.start_job("apply", server.SERVER_EXIT_ID))["status"], "success")
        self.assertEqual(self.auto_route(), "direct")
        self.assertEqual(self.auto_fragment(), old_auto)
        b = self.add_exit("Exit B", "proxy-b.example.com")
        self.assertEqual(self.wait(self.manager.start_job("apply", b))["status"], "success")
        self.assertEqual(self.auto_route(), "static-E" + b.upper())
        self.assertEqual(self.auto_fragment(), old_auto)
        self.assertEqual(self.manager.state["auto_id"], old_identity)
        self.assertFalse(self.manager.public_state()["client_config"]["refresh_required"])
        self.assertEqual(self.manager.public_state()["active_target"], "static")
        self.assertFalse(self.manager.public_state()["server_exit"]["active"])

    def test_failed_target_keeps_previous_server_route_and_state(self):
        self.wait(self.manager.start_job("apply", server.SERVER_EXIT_ID))
        broken = self.add_exit(address="fail.example.com")
        original = self.manager.config_path.read_bytes()
        previous = copy.deepcopy(self.manager.state)
        self.assertEqual(self.wait(self.manager.start_job("apply", broken))["status"], "failed")
        self.assertEqual(self.manager.config_path.read_bytes(), original)
        self.assertEqual(self.manager.state, previous)
        self.assertEqual(self.auto_route(), "direct")

    def test_unrelated_new_and_edited_bad_drafts_cannot_block_switch_or_enter_running_config(self):
        verified = self.add_exit("Verified", "proxy-verified.example.com")
        self.wait(self.manager.start_job("apply", verified))
        applied = copy.deepcopy(self.manager.state["applied_exits"][0])
        self.manager.edit_exit({"id": verified, "name": "Edited bad draft", "address": "fail.example.com",
                                "port": 1080, "auth": "credentials", "username": "", "password": "",
                                "expected_ip": ""})
        broken_new = self.add_exit("New bad draft", "fail-new.example.com")
        healthy = self.add_exit("Healthy", "proxy-healthy.example.com")
        with mock.patch.object(self.manager, "probe", wraps=self.manager.probe) as probe:
            self.assertEqual(self.wait(self.manager.start_job("apply", server.SERVER_EXIT_ID))["status"], "success")
            probe.assert_not_called()
            self.assertEqual(self.wait(self.manager.start_job("apply", healthy))["status"], "success")
            self.assertEqual([call[0][0]["id"] for call in probe.call_args_list], [healthy])
        self.assertEqual(self.manager.state["applied_exits"][0], applied)
        self.assertNotIn(broken_new, [item["id"] for item in self.manager.state["applied_exits"]])
        config = self.manager.config_path.read_bytes()
        self.assertNotIn(b"fail.example.com", config)
        self.assertNotIn(b"fail-new.example.com", config)
        self.assertEqual(self.auto_route(), "static-E" + healthy.upper())
        pending = {item["id"]: item["pending"] for item in self.manager.public_state()["exits"]}
        self.assertTrue(pending[verified])
        self.assertTrue(pending[broken_new])
        self.assertFalse(pending[healthy])

    def test_deleting_the_last_static_exit_and_selecting_server_keeps_auto_identity(self):
        identity = self.add_exit()
        self.wait(self.manager.start_job("apply", identity))
        old_auto = self.auto_fragment()
        self.manager.delete_exit(identity)
        self.assertEqual(self.wait(self.manager.start_job("apply", server.SERVER_EXIT_ID))["status"], "success")
        self.assertEqual(self.manager.state["applied_exits"], [])
        self.assertEqual(self.auto_route(), "direct")
        self.assertEqual(self.auto_fragment(), old_auto)
        self.assertEqual(self.profile_node_names(), ["AUTO · 网页切换"])
        self.assertFalse(self.manager.public_state()["dirty"])

    def test_rollback_restores_static_then_server_without_changing_auto_identity(self):
        self.wait(self.manager.start_job("apply", server.SERVER_EXIT_ID))
        identity = self.add_exit()
        self.wait(self.manager.start_job("apply", identity))
        old_auto = self.auto_fragment()
        self.wait(self.manager.start_job("apply", server.SERVER_EXIT_ID))
        self.assertEqual(self.wait(self.manager.start_job("rollback"))["status"], "success")
        self.assertEqual(self.auto_route(), "static-E" + identity.upper())
        self.assertEqual(self.auto_fragment(), old_auto)
        self.assertEqual(self.wait(self.manager.start_job("rollback"))["status"], "success")
        self.assertEqual(self.auto_route(), "direct")
        self.assertEqual(self.manager.state["active_id"], server.SERVER_EXIT_ID)
        self.assertEqual(self.auto_fragment(), old_auto)

    def test_legacy_empty_history_restores_server_with_auto_instead_of_removing_auto(self):
        identity = self.add_exit()
        self.wait(self.manager.start_job("apply", identity))
        old_auto = self.auto_fragment()
        self.assertIsNone(self.manager.state["history"][0]["active_id"])
        self.assertIsNone(self.manager.state["history"][0]["profile"])
        self.assertEqual(self.wait(self.manager.start_job("rollback"))["status"], "success")
        self.assertEqual(self.auto_route(), "direct")
        self.assertEqual(self.auto_fragment(), old_auto)
        self.assertEqual(self.manager.state["active_id"], server.SERVER_EXIT_ID)
        self.manager.set_routing([], "services")
        self.assertIn("rule-providers:", self.manager.state["profile"])
        self.assertEqual(self.auto_route(), "direct")

    def test_partial_apply_keeps_fixed_names_unique_when_an_old_applied_name_collides(self):
        a = self.add_exit("Exit A")
        self.wait(self.manager.start_job("apply", a))
        self.manager.edit_exit({"id": a, "name": "Renamed A", "address": "proxy.example.com", "port": 1080,
                                "auth": "credentials", "username": "", "password": "", "expected_ip": ""})
        b = self.add_exit("Exit A")
        self.assertEqual(self.wait(self.manager.start_job("apply", b))["status"], "success")
        names = self.profile_node_names()
        self.assertEqual(len(names), len(set(name.casefold() for name in names)))
        self.assertEqual(set(names[1:]), set(self.manager.public_state()["client_config"]["nodes"]))
        self.assertEqual(self.manager.state["applied_exits"][0]["name"], "Exit A")
        self.assertTrue(self.manager.public_state()["exits"][0]["pending"])

    def test_branch_pending_status_distinguishes_draft_credentials_from_applied_route(self):
        identity = self.add_exit()
        self.assertTrue(self.manager.public_state()["exits"][0]["pending"])
        self.wait(self.manager.start_job("apply", identity))
        self.assertFalse(self.manager.public_state()["exits"][0]["pending"])
        self.manager.edit_exit({"id":identity, "name":"Exit A", "address":"proxy.example.com",
                                "port":1080, "auth":"credentials", "username":"",
                                "password":"changed-test-only-secret", "expected_ip":""})
        public = self.manager.public_state()
        self.assertTrue(public["exits"][0]["pending"])
        self.assertFalse(public["active"]["pending"])

    def test_external_config_edit_is_not_overwritten(self):
        identity = self.add_exit()
        self.manager.config_path.write_bytes(b"EXTERNAL-EDIT")
        result = self.wait(self.manager.start_job("apply", identity))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(self.manager.config_path.read_bytes(), b"EXTERNAL-EDIT")

    def test_retesting_an_applied_exit_does_not_mark_the_config_dirty(self):
        identity = self.add_exit()
        self.wait(self.manager.start_job("apply", identity))
        self.wait(self.manager.start_job("test", identity))
        self.assertFalse(self.manager.public_state()["dirty"])

    def test_state_commit_failure_recovers_previous_config(self):
        identity = self.add_exit()
        original = self.manager.config_path.read_bytes()
        with mock.patch.object(self.manager, "save", side_effect=OSError("TEST disk failure")):
            result = self.wait(self.manager.start_job("apply", identity))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(self.manager.config_path.read_bytes(), original)

    def test_domain_validation_blocks_rule_injection(self):
        self.assertEqual(server.clean_domains(["GitHub.com", "github.com", ""]), ["github.com"])
        self.assertEqual(server.clean_domains(["https://example.com/"]), ["example.com"])
        for values in (["example.com,DIRECT"], ["example.com\nMATCH,DIRECT"]):
            with self.assertRaises(server.PanelError):
                server.clean_domains(values)

    def test_service_routing_keeps_provider_order_defaults_and_private_nodes(self):
        identity = self.add_exit()
        state = copy.deepcopy(self.manager.state)
        state.update(domains=[], routing_mode="services")
        _, profile = self.manager.build(state, identity)
        rules = json.loads(profile.split("\nrules: ", 1)[1].splitlines()[0])
        self.assertEqual(rules[1:], routing.preset()["rules"])
        self.assertEqual(rules[0], "DOMAIN,api.ipify.org,STATIC-SELECT")
        groups = json.loads(profile.split("\nproxy-groups: ", 1)[1].splitlines()[0])
        names = {group["name"]:group for group in groups}
        for name in ("Domestic", "Apple", "PayPal", "Scholar", "miHoYo", "Asian TV"):
            self.assertEqual(names[name]["proxies"][0], "DIRECT")
        self.assertEqual(names["Proxy"]["proxies"][0], "STATIC-SELECT")
        self.assertEqual(names["Auto - UrlTest"]["proxies"], ["AUTO · 网页切换"])
        self.assertEqual(names["Others"]["proxies"][0], "Proxy")
        self.assertNotIn("test-only-secret", profile)
        providers = json.loads(profile.split("\nrule-providers: ", 1)[1].splitlines()[0])
        self.assertEqual(len(providers), 60)
        self.assertTrue(providers["Domestic DNS"]["url"].endswith("/node-console/rules/domestic-dns.yaml"))
        for provider in providers.values():
            self.assertNotIn("?", provider["url"])

    def test_saving_routing_regenerates_download_without_changing_xray_or_drafts(self):
        identity = self.add_exit()
        self.wait(self.manager.start_job("apply", identity))
        original = self.manager.config_path.read_bytes()
        self.manager.edit_exit({"id":identity,"name":"Edited draft","address":"proxy.example.com",
                                "port":1080,"auth":"credentials","username":"","password":"",
                                "expected_ip":""})
        self.manager.set_routing([], "services")
        self.assertEqual(self.manager.config_path.read_bytes(), original)
        self.assertEqual(self.manager.state["exits"][0]["name"], "Edited draft")
        self.assertEqual(self.manager.state["applied_exits"][0]["name"], "Exit A")
        self.assertIn("rule-providers:", self.manager.state["profile"])
        self.assertTrue(self.manager.public_state()["dirty"])

    def test_smart_custom_rules_refresh_without_changing_live_xray_auto_or_exit(self):
        identity = self.add_exit()
        self.wait(self.manager.start_job("apply", identity))
        self.manager.set_routing(["foreign.example.com"], "smart", ["local.example.cn"])
        previous = copy.deepcopy(self.manager.state)
        xray = self.manager.config_path.read_bytes()
        auto = self.auto_fragment()
        self.manager.edit_exit({"id": identity, "name": "Pending draft", "address": "proxy.example.com",
                                "port": 1080, "auth": "credentials", "username": "", "password": "",
                                "expected_ip": ""})
        with mock.patch.object(self.manager, "install", side_effect=AssertionError("Must not install Xray")):
            self.manager.set_routing(["new.example.com"], "smart", ["video.example.cn"])
        state = self.manager.state
        self.assertEqual(self.manager.config_path.read_bytes(), xray)
        for key in ("managed_hash", "auto_id", "rule_token", "active_id", "applied_exits", "history"):
            self.assertEqual(state[key], previous[key], key)
        self.assertEqual(self.auto_fragment(), auto)
        self.assertEqual(state["exits"][0]["name"], "Pending draft")
        self.assertEqual(state["applied_exits"][0]["name"], "Exit A")
        self.assertEqual(state["direct_domains"], ["video.example.cn"])
        self.assertEqual(state["applied_direct_domains"], ["video.example.cn"])
        self.assertEqual(state["applied_domains"], ["new.example.com"])
        self.assertEqual(self.manager.rule_snapshot(state["rule_token"], "direct"),
                         routing.rule_payload(["video.example.cn"], "direct"))
        self.assertEqual(self.manager.rule_snapshot(state["rule_token"], "proxy"),
                         routing.rule_payload(["new.example.com"], "proxy"))
        public = self.manager.public_state()
        self.assertEqual(public["direct_domains"], ["video.example.cn"])
        self.assertTrue(public["routing_subscription"]["enabled"])
        self.assertEqual(public["routing_subscription"]["interval"], 300)
        self.assertTrue(public["dirty"])

    def test_routing_lists_normalize_reject_overlaps_and_keep_ip_check_proxied(self):
        self.manager.set_routing(["GitHub.com", "github.com", "api.ipify.org"], "smart", ["视频.cn", "视频.cn"])
        self.assertEqual(self.manager.state["domains"], ["github.com"])
        self.assertEqual(self.manager.state["direct_domains"], ["xn--cy2a840a.cn"])
        previous = copy.deepcopy(self.manager.state)
        for proxy, direct in ((["same.example.com"], ["same.example.com"]),
                              (["example.com"], ["video.example.com"]),
                              (["video.example.com"], ["example.com"]),
                              ([], ["api.ipify.org"]), ([], ["ipify.org"]),
                              ([], ["test.api.ipify.org"]), ([], ["example.com,DIRECT"])):
            with self.subTest(proxy=proxy, direct=direct):
                with self.assertRaises(server.PanelError):
                    self.manager.set_routing(proxy, "smart", direct)
                self.assertEqual(self.manager.state, previous)
        self.manager.set_routing(["a.example.com"], "smart", ["b.example.com"])
        self.assertEqual(self.manager.state["direct_domains"], ["b.example.com"])

    def test_website_links_persist_and_export_only_the_extracted_hostname(self):
        self.wait(self.manager.start_job("apply", server.SERVER_EXIT_ID))
        original = self.manager.config_path.read_bytes()
        study_url = ("https://mooc1.chaoxing.com/mycourse/studentstudy?"
                     "chapterId=1256244322&courseId=267613475&enc=private-course-token#chapter")
        self.manager.set_routing(["https://foreign.example.com/account?token=private-account-token"],
                                 "smart", [study_url])
        state = self.manager.state
        self.assertEqual(state["direct_domains"], ["mooc1.chaoxing.com"])
        self.assertEqual(state["applied_direct_domains"], ["mooc1.chaoxing.com"])
        self.assertEqual(state["domains"], ["foreign.example.com"])
        self.assertEqual(self.manager.public_state()["direct_domains"], ["mooc1.chaoxing.com"])
        direct_payload = self.manager.rule_snapshot(state["rule_token"], "direct")
        self.assertIn("DOMAIN-SUFFIX,mooc1.chaoxing.com", direct_payload)
        self.assertNotIn("DOMAIN-SUFFIX,chaoxing.com", direct_payload)
        serialized = self.manager.state_path.read_text(encoding="utf-8")
        for private in (study_url, "studentstudy", "chapterId", "private-course-token",
                        "private-account-token"):
            self.assertNotIn(private, serialized)
            self.assertNotIn(private, direct_payload)
            self.assertNotIn(private, state["profile"])
        reopened = server.Manager(self.directory, "8.8.8.8", self.manager.config_path, demo=True)
        self.assertEqual(reopened.state["direct_domains"], ["mooc1.chaoxing.com"])
        self.assertEqual(self.manager.config_path.read_bytes(), original)
        self.manager.set_routing(["passport.chaoxing.com"], "services", [study_url])
        self.assertIn("DOMAIN-SUFFIX,mooc1.chaoxing.com,DIRECT", self.manager.state["profile"])
        self.assertNotIn("DOMAIN-SUFFIX,chaoxing.com,DIRECT", self.manager.state["profile"])

    def test_website_link_normalization_keeps_overlap_and_ip_check_guards(self):
        self.manager.set_routing(["HTTPS://API.IPIFY.ORG:443/?token=discarded"], "smart", [])
        self.assertEqual(self.manager.state["domains"], [])
        previous = copy.deepcopy(self.manager.state)
        cases = [(["https://CHAoxing.com/account"], ["https://mooc1.chaoxing.com/study?enc=private"]),
                 (["mooc1.chaoxing.com:443/study"], ["//chaoxing.com/course"]),
                 ([], ["https://api.ipify.org/?format=json"]),
                 ([], ["https://ipify.org/account"]),
                 ([], ["//test.api.ipify.org/"])]
        for proxy, direct in cases:
            with self.subTest(proxy=proxy, direct=direct):
                with self.assertRaises(server.PanelError) as raised:
                    self.manager.set_routing(proxy, "smart", direct)
                self.assertNotIn("enc=private", str(raised.exception))
                self.assertNotIn("https://", str(raised.exception))
                self.assertEqual(self.manager.state, previous)

    def test_legacy_domain_api_keeps_direct_list_and_updates_subscription(self):
        self.wait(self.manager.start_job("apply", server.SERVER_EXIT_ID))
        self.manager.set_routing(["first.example.com"], "smart", ["example.cn"])
        original = self.manager.config_path.read_bytes()
        self.manager.set_domains(["second.example.com"])
        self.assertEqual(self.manager.state["direct_domains"], ["example.cn"])
        self.assertEqual(self.manager.state["applied_domains"], ["second.example.com"])
        self.assertEqual(self.manager.config_path.read_bytes(), original)
        self.assertFalse(self.manager.public_state()["dirty"])
        with self.assertRaises(server.PanelError):
            self.manager.set_domains(["video.example.cn"])

    def test_direct_list_pending_state_and_old_state_migration_persist_stable_token(self):
        self.manager.set_routing([], "smart", ["example.cn"])
        self.assertTrue(self.manager.public_state()["dirty"])
        original_xray = self.manager.config_path.read_bytes()
        old_state = copy.deepcopy(self.manager.state)
        for key in ("direct_domains", "applied_direct_domains", "rule_token", "routing_mode", "applied_routing_mode"):
            old_state.pop(key)
        old_state["history"] = [{"config": copy.deepcopy(old_state["base"]), "applied_exits": [],
                                 "active_id": None, "profile": None, "domains": [], "updated": None}]
        server.atomic_write(self.manager.state_path, server.json_bytes(old_state))
        restored = server.Manager(self.directory, "8.8.8.8", self.manager.config_path, demo=True)
        token = restored.state["rule_token"]
        self.assertGreaterEqual(len(token), 32)
        self.assertEqual(restored.state["direct_domains"], [])
        self.assertEqual(restored.state["applied_direct_domains"], [])
        self.assertEqual(restored.state["routing_mode"], "manual")
        self.assertEqual(restored.state["history"][0]["rule_token"], token)
        self.assertEqual(restored.state["history"][0]["direct_domains"], [])
        written = restored.state_path.read_bytes()
        reopened = server.Manager(self.directory, "8.8.8.8", self.manager.config_path, demo=True)
        self.assertEqual(reopened.state["rule_token"], token)
        self.assertEqual(reopened.state_path.read_bytes(), written)
        self.assertEqual(reopened.config_path.read_bytes(), original_xray)

    def test_routing_rollback_restores_lists_and_keeps_subscription_identity(self):
        self.wait(self.manager.start_job("apply", server.SERVER_EXIT_ID))
        self.manager.set_routing([], "smart", ["old.example.cn"])
        token = self.manager.state["rule_token"]
        auto = self.auto_fragment()
        self.wait(self.manager.start_job("apply", server.SERVER_EXIT_ID))
        self.manager.set_routing(["new.example.com"], "smart", ["new.example.cn"])
        result = self.wait(self.manager.start_job("rollback"))
        self.assertEqual(result["status"], "success")
        self.assertEqual(self.manager.state["domains"], [])
        self.assertEqual(self.manager.state["direct_domains"], ["old.example.cn"])
        self.assertEqual(self.manager.state["applied_direct_domains"], ["old.example.cn"])
        self.assertEqual(self.manager.state["rule_token"], token)
        self.assertEqual(self.auto_fragment(), auto)
        self.assertFalse(self.manager.public_state()["dirty"])
        reopened = server.Manager(self.directory, "8.8.8.8", self.manager.config_path, demo=True)
        self.assertEqual(reopened.state["direct_domains"], ["old.example.cn"])
        self.assertEqual(reopened.state["rule_token"], token)

    def test_old_state_and_rollback_restore_previous_routing_mode(self):
        identity = self.add_exit()
        self.wait(self.manager.start_job("apply", identity))
        self.manager.set_routing([], "services")
        self.wait(self.manager.start_job("apply", identity))
        self.manager.set_routing([], "manual")
        self.wait(self.manager.start_job("rollback"))
        self.assertEqual(self.manager.state["routing_mode"], "services")
        self.assertIn("rule-providers:", self.manager.state["profile"])

    @unittest.skipUnless(os.environ.get("XRAY_TEST_BINARY"), "No official test binary")
    def test_official_core_accepts_web_managed_config(self):
        identity = self.add_exit()
        config, _ = self.manager.build(self.manager.state, identity)
        path = self.directory / "candidate.json"
        path.write_bytes(server.json_bytes(config))
        result = base.command([os.environ["XRAY_TEST_BINARY"], "run", "-test", "-config", str(path)])
        self.assertIn("Configuration OK", result.stdout)

    @unittest.skipUnless(os.environ.get("MIHOMO_TEST_BINARY"), "No official Mihomo test binary")
    def test_official_mihomo_accepts_two_exit_unified_profile(self):
        identity = self.add_exit("Exit A", "proxy-a.example.com")
        self.add_exit("Exit B", "proxy-b.example.com")
        _, profile = self.manager.build(self.manager.state, identity)
        path = self.directory / "unified-test.yaml"
        path.write_text(profile, encoding="utf-8")
        result = subprocess.run(
            [os.environ["MIHOMO_TEST_BINARY"], "-t", "-d", str(self.directory), "-f", str(path)],
            capture_output=True, text=True, timeout=30, check=False,
        )
        self.assertEqual(result.returncode, 0, "Official Mihomo core rejected the unified two-exit profile.")


class HttpSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="panel-http-test-")
        self.addCleanup(self.temporary.cleanup)
        directory = Path(self.temporary.name)
        self.manager = server.Manager(directory, "8.8.8.8", directory / "xray.json", demo=True)
        self.httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        self.port = self.httpd.server_address[1]
        self.origin = f"http://127.0.0.1:{self.port}"
        self.httpd.application = server.Application(self.manager, self.origin, "/", True)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.cookie = ""
        self.csrf = ""

    def request(self, path, data=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        request_headers = {"Origin": self.origin, "Cookie": self.cookie, "X-CSRF-Token": self.csrf}
        if headers:
            request_headers.update(headers)
        if data is not None:
            request_headers["Content-Type"] = "application/json"
        connection.request("POST" if data is not None else "GET", path,
                           json.dumps(data) if data is not None else None, request_headers)
        response = connection.getresponse()
        body = response.read()
        result = (response.status, dict(response.getheaders()), body)
        connection.close()
        return result

    def login(self):
        status, headers, body = self.request("/api/login", {"username": "admin", "password": "demo-password-2026"})
        self.assertEqual(status, 200)
        self.cookie = headers["Set-Cookie"].split(";", 1)[0]
        self.csrf = json.loads(body)["csrf"]
        return headers

    def test_api_requires_login_and_mutations_require_csrf_and_same_origin(self):
        self.assertEqual(self.request("/api/state")[0], 401)
        headers = self.login()
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        self.assertIn("SameSite=Strict", headers["Set-Cookie"])
        self.assertEqual(self.request("/api/state")[0], 200)
        self.assertEqual(self.request("/api/domains", {"domains": []}, {"X-CSRF-Token": "bad"})[0], 403)
        self.assertEqual(self.request("/api/domains", {"domains": []}, {"Origin": "https://wrong.example"})[0], 403)
        self.assertEqual(self.request("/api/domains", {"domains": ["example.com"]})[0], 200)

    def test_private_files_are_not_served_and_login_is_rate_limited(self):
        self.login()
        self.assertEqual(self.request("/../auth.private.json")[0], 404)
        self.assertEqual(self.request("/state.private.json")[0], 404)
        for _ in range(6):
            self.assertEqual(self.request("/api/login", {"username": "admin", "password": "bad"})[0], 401)
        self.assertEqual(self.request("/api/login", {"username": "admin", "password": "bad"})[0], 429)

    def test_custom_rule_capability_is_read_only_and_does_not_need_login(self):
        self.manager.set_routing(["proxy.example.com"], "smart", ["direct.example.cn"])
        token = self.manager.state["rule_token"]
        for direction, domains in (("direct", ["direct.example.cn"]), ("proxy", ["proxy.example.com"])):
            with self.subTest(direction=direction):
                status, headers, body = self.request("/rules/custom/" + token + "/" + direction + ".yaml")
                self.assertEqual(status, 200)
                self.assertEqual(headers["Content-Type"], "application/yaml; charset=utf-8")
                self.assertEqual(headers["Cache-Control"], "no-store")
                self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
                self.assertEqual(body.decode(), routing.rule_payload(domains, direction))
                self.assertNotIn(token.encode(), body)
        self.assertEqual(self.request("/api/profile")[0], 401)
        self.assertEqual(self.request("/rules/custom/" + token + "/direct.yaml", {})[0], 401)
        self.manager.set_routing([], "smart", [])
        self.assertEqual(self.request("/rules/custom/" + token + "/direct.yaml")[2].decode(),
                         routing.rule_payload([], "direct"))

    def test_unknown_rule_tokens_and_directions_return_plain_404_without_lists(self):
        self.manager.set_routing(["hidden.example.com"], "smart", ["private.example.cn"])
        token = self.manager.state["rule_token"]
        paths = ["/rules/custom/wrong-token/direct.yaml", "/rules/custom/" + token + "/secrets.yaml",
                 "/rules/custom/" + token + "/direct.yaml/extra", "/rules/custom/" + token + "/../state.private.json",
                 "/rules/custom/%E8%A7%84%E5%88%99/direct.yaml"]
        for path in paths:
            with self.subTest(path=path):
                status, _, body = self.request(path)
                self.assertEqual(status, 404)
                for private in ("hidden.example.com", "private.example.cn", token):
                    self.assertNotIn(private.encode(), body)

    def test_routing_api_persists_direct_domains_and_requires_session_csrf_and_origin(self):
        request = {"mode": "smart", "domains": ["https://EXAMPLE.COM/path?token=private-proxy-token"],
                   "direct_domains": ["https://EXAMPLE.CN:443/course?token=private-direct-token"]}
        self.assertEqual(self.request("/api/routing", request)[0], 401)
        self.login()
        self.assertEqual(self.request("/api/routing", request, {"X-CSRF-Token": "bad"})[0], 403)
        self.assertEqual(self.request("/api/routing", request, {"Origin": "https://wrong.example"})[0], 403)
        self.assertEqual(self.request("/api/routing", request)[0], 200)
        public = json.loads(self.request("/api/state")[2])
        self.assertEqual(public["domains"], ["example.com"])
        self.assertEqual(public["direct_domains"], ["example.cn"])
        self.assertTrue(public["routing_subscription"]["enabled"])
        for private in ("private-proxy-token", "private-direct-token"):
            self.assertNotIn(private, self.manager.state_path.read_text(encoding="utf-8"))
        request["domains"] = ["https://video.example.cn/path"]
        self.assertEqual(self.request("/api/routing", request)[0], 400)
        self.assertEqual(self.manager.state["domains"], ["example.com"])

    def test_password_change_invalidates_old_sessions(self):
        self.login()
        result = self.request("/api/password", {"current": "demo-password-2026", "new": "new-test-password-2026"})
        self.assertEqual(result[0], 200)
        self.assertEqual(self.request("/api/state")[0], 401)
        self.assertEqual(self.request("/api/login", {"username": "admin", "password": "demo-password-2026"})[0], 401)
        self.assertEqual(self.request("/api/login", {"username": "admin", "password": "new-test-password-2026"})[0], 200)


if __name__ == "__main__":
    unittest.main()
