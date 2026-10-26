"""Dual transport accounting, lifecycle sampling and shared network controls."""

import ast
import copy
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

from panel import server, telemetry
from panel import test_operations as legacy


def hy2_counters(up, down):
    return {"hy2>>>traffic>>>uplink": up, "hy2>>>traffic>>>downlink": down}


class Hy2Provider:
    def __init__(self):
        self.statistics = {}
        self.epochs = {}
        self.failed = set()
        self.calls = []
        self.fail_enforce = False

    def query(self, record):
        if record["id"] in self.failed:
            raise RuntimeError("private endpoint unavailable")
        return (self.statistics.get(record["id"], hy2_counters(0, 0)), 2,
                self.epochs.get(record["id"], "MainPID=20;start=10"))

    def enforce(self, blocked, rates):
        self.calls.append((set(blocked), dict(rates)))
        if self.fail_enforce:
            self.fail_enforce = False
            raise RuntimeError("HY2 enforcement validation failed")


class DualTrafficTests(legacy.Fixture):
    run_command = legacy.TrafficTests.run_command

    def setUp(self):
        super().setUp()
        self.controls = legacy.Controls()
        self.statistics = {}
        self.fail_queries = False
        self.epoch = "MainPID=10\nExecMainStartTimestampMonotonic=1234"
        self.hy2 = Hy2Provider()
        self.traffic = telemetry.Telemetry(self.accounts, controls=self.controls,
            runner=self.run_command, clock=self.clock, hy2=self.hy2)

    def sample(self, tcp_up, tcp_down, udp_up, udp_down):
        self.statistics[self.member["port"]] = {"up": tcp_up, "down": tcp_down}
        self.hy2.statistics[self.member["id"]] = hy2_counters(udp_up, udp_down)
        self.traffic.tick()
        return self.traffic.snapshot(self.member["id"])

    def test_upload_download_direction_account_isolation_and_combined_rates(self):
        first = self.sample(100, 200, 300, 700)
        self.assertEqual((first["up_bytes"], first["down_bytes"], first["total_bytes"]), (400, 900, 1300))
        self.assertEqual(self.traffic.snapshot("admin")["total_bytes"], 0)
        self.clock_value += 10
        result = self.sample(200, 500, 600, 1400)
        self.assertEqual((result["up_rate"], result["down_rate"], result["connections"]), (40, 100, 3))
        self.assertEqual(result["sources"]["hy2"]["up_rate"], 30)
        self.assertEqual(result["sources"]["xray"]["down_rate"], 30)
        self.assertIn("QUIC", result["connection_scope"])
        self.assertIn("DIRECT", result["scope"])

    def test_only_restarted_source_resets_its_baseline(self):
        self.sample(100, 200, 300, 700)
        self.clock_value += 10
        self.hy2.epochs[self.member["id"]] = "MainPID=21;start=20"
        restarted = self.sample(150, 250, 400, 800)
        self.assertEqual(restarted["total_bytes"], 2600)
        self.clock_value += 10
        self.epoch = "MainPID=11\nExecMainStartTimestampMonotonic=4567"
        restarted = self.sample(200, 300, 450, 850)
        self.assertEqual(restarted["total_bytes"], 3200)

    def test_independent_counter_reset_and_persistent_baselines(self):
        self.sample(100, 200, 300, 700)
        self.clock_value += 10
        result = self.sample(100, 200, 30, 70)
        self.assertEqual(result["total_bytes"], 1400)
        reloaded = telemetry.Telemetry(self.accounts, controls=self.controls,
            runner=self.run_command, clock=self.clock, hy2=self.hy2)
        reloaded.tick()
        self.assertEqual(reloaded.snapshot(self.member["id"])["total_bytes"], 1400)
        telemetry.validate_store(json.loads(self.traffic.path.read_text(encoding="utf-8")))

    def test_legacy_xray_month_and_baseline_migrate_without_charging_twice(self):
        self.statistics[self.member["port"]] = {"up": 100, "down": 200}
        old = telemetry.Telemetry(self.accounts, controls=self.controls,
            runner=self.run_command, clock=self.clock)
        old.tick()
        data = json.loads(old.path.read_text(encoding="utf-8"))
        for item in data["users"].values():
            item.pop("sources", None)
        server.atomic_write(old.path, server.json_bytes(data))
        self.hy2.statistics[self.member["id"]] = hy2_counters(300, 700)
        updated = telemetry.Telemetry(self.accounts, controls=self.controls,
            runner=self.run_command, clock=self.clock, hy2=self.hy2)
        updated.tick()
        self.assertEqual(updated.snapshot(self.member["id"])["total_bytes"], 1300)

    def test_failed_hy2_preserves_totals_and_reports_unknown_aggregate(self):
        self.sample(100, 200, 300, 700)
        baseline = copy.deepcopy(self.traffic.data["users"][self.member["id"]]["sources"]["hy2"])
        self.hy2.failed.add(self.member["id"])
        self.clock_value += 10
        result = self.sample(200, 400, 500, 900)
        self.assertEqual(result["total_bytes"], 1600)
        self.assertFalse(result["available"])
        self.assertTrue(result["sources"]["xray"]["available"])
        self.assertFalse(result["sources"]["hy2"]["available"])
        self.assertIsNone(result["up_rate"])
        self.assertIsNone(result["down_rate"])
        self.assertIsNone(result["connections"])
        self.assertEqual(self.traffic.data["users"][self.member["id"]]["sources"]["hy2"], baseline)
        self.hy2.failed.clear()
        self.clock_value += 10
        result = self.sample(200, 400, 500, 900)
        self.assertEqual(result["total_bytes"], 2000)
        self.assertEqual(result["sources"]["hy2"]["up_rate"], 10)

    def test_failed_xray_still_accounts_hy2_and_recovers_its_own_delta(self):
        self.sample(100, 200, 300, 700)
        self.fail_queries = True
        self.clock_value += 10
        result = self.sample(200, 400, 500, 900)
        self.assertEqual(result["total_bytes"], 1700)
        self.assertTrue(result["sources"]["hy2"]["available"])
        self.assertIsNone(result["up_rate"])
        self.fail_queries = False
        self.clock_value += 10
        result = self.sample(200, 400, 500, 900)
        self.assertEqual(result["total_bytes"], 2000)

    def test_disabled_account_final_samples_are_not_skipped(self):
        self.sample(100, 200, 300, 700)
        self.accounts._record(self.member["id"])["enabled"] = False
        self.clock_value += 10
        result = self.sample(200, 400, 500, 900)
        self.assertEqual(result["total_bytes"], 2000)
        self.assertFalse(result["available"])
        self.assertEqual(result["reason"], "账号已停用")

    def test_lifecycle_final_sample_is_persisted_without_enforcement(self):
        self.sample(100, 200, 300, 700)
        previous_calls = len(self.controls.calls)
        self.hy2.statistics[self.member["id"]] = hy2_counters(500, 900)
        final = self.traffic.sample_user(self.member["id"])
        self.assertEqual(final["total_bytes"], 1700)
        self.assertEqual(len(self.controls.calls), previous_calls)
        reloaded = telemetry.Telemetry(self.accounts, controls=self.controls,
            runner=self.run_command, clock=self.clock, hy2=self.hy2)
        self.assertEqual(reloaded.snapshot(self.member["id"])["total_bytes"], 1700)

    def test_aggregate_quota_both_provider_plans_and_month_reset(self):
        self.sample(100, 200, 300, 700)
        result = self.traffic.set_limits(self.member["id"], 1200, 1000000)
        expected = ({1443}, {1443: 1000000})
        self.assertEqual(self.controls.calls[-1], expected)
        self.assertEqual(self.hy2.calls[-1], expected)
        self.assertTrue(result["quota_enforced"])
        self.assertTrue(result["rate_enforced"])
        self.clock_value += 40 * 86400
        self.traffic.tick()
        self.assertEqual(self.controls.calls[-1][0], set())
        self.assertEqual(self.hy2.calls[-1][0], set())
        self.assertTrue(self.accounts._record(self.member["id"])["enabled"])

    def test_failed_provider_plan_rolls_back_kernel_and_provider_and_saved_limits(self):
        self.traffic.set_limits(self.member["id"], 0, 1000000)
        before = self.traffic.path.read_bytes()
        self.hy2.fail_enforce = True
        with self.assertRaises(server.PanelError):
            self.traffic.set_limits(self.member["id"], 500, 2000000)
        self.assertEqual(self.traffic.path.read_bytes(), before)
        self.assertEqual(self.controls.calls[-1], (set(), {1443: 1000000}))
        self.assertEqual(self.hy2.calls[-1], (set(), {1443: 1000000}))
        self.assertTrue(self.traffic.snapshot(self.member["id"])["rate_enforced"])

    def test_failed_provider_reconciliation_never_reports_limits_as_enforced(self):
        self.sample(100, 200, 300, 700)
        self.traffic.set_limits(self.member["id"], 1400, 1000000)
        self.hy2.fail_enforce = True
        self.clock_value += 10
        with self.assertRaises(RuntimeError):
            self.sample(200, 400, 500, 900)
        result = self.traffic.snapshot(self.member["id"])
        self.assertTrue(result["over_quota"])
        self.assertFalse(result["quota_enforced"])
        self.assertFalse(result["rate_enforced"])
        self.assertIsNotNone(result["enforcement_error"])

    def test_malformed_provider_data_cannot_add_usage_or_expose_private_errors(self):
        self.sample(100, 200, 300, 700)
        self.hy2.statistics[self.member["id"]] = hy2_counters(-1, 900)
        self.clock_value += 10
        result = self.sample(100, 200, -1, 900)
        self.assertEqual(result["total_bytes"], 1300)
        self.assertFalse(result["sources"]["hy2"]["available"])
        self.assertNotIn("private endpoint", json.dumps(result))

    def test_source_store_rejects_unknown_provider_invalid_counters_and_epoch(self):
        self.sample(100, 200, 300, 700)
        for change in (lambda entry: entry["sources"].update(other={"counters": {}}),
                       lambda entry: entry["sources"]["hy2"]["counters"].update(bad=-1),
                       lambda entry: entry["sources"]["hy2"].update(epoch={"secret": "not accepted"}),
                       lambda entry: entry["sources"]["hy2"].update(sample_time=float("nan"))):
            candidate = copy.deepcopy(self.traffic.data)
            change(candidate["users"][self.member["id"]])
            with self.assertRaises(ValueError):
                telemetry.validate_store(candidate)


class PrivateForwardingTests(legacy.Fixture):
    def addon(self):
        config = telemetry.augment_config(self.owner.state["base"])
        port = config["inbounds"][0]["port"]
        config["inbounds"].append({"tag": "panel-hy2-socks", "listen": "127.0.0.1", "port": 15600 + port,
            "protocol": "socks", "settings": {"auth": "password", "accounts": [
                {"user": "panel-hy2", "pass": "synthetic-private-forwarding-secret"}], "udp": False}})
        return config

    def test_authenticated_loopback_socks_is_allowed_without_second_statistics(self):
        config = self.addon()
        original = copy.deepcopy(config)
        result = telemetry.augment_config(config)
        self.assertEqual(config, original)
        self.assertEqual(result["inbounds"][1], original["inbounds"][1])
        self.assertNotIn("email", result["inbounds"][1]["settings"]["accounts"][0])
        self.assertTrue(telemetry.validate_augmentation(result))

    def test_public_unknown_udp_or_unauthenticated_addons_are_rejected(self):
        mutations = [lambda extra: extra.update(listen="0.0.0.0"),
                     lambda extra: extra.update(port=1080),
                     lambda extra: extra.update(tag="external-socks"),
                     lambda extra: extra["settings"].update(udp=True),
                     lambda extra: extra["settings"].update(auth="noauth"),
                     lambda extra: extra["settings"].update(accounts=[]),
                     lambda extra: extra["settings"]["accounts"][0].update({"pass": ""}),
                     lambda extra: extra["settings"]["accounts"][0].update(email="count-twice@example"),
                     lambda extra: extra.update(sniffing={"enabled": True})]
        for mutate in mutations:
            config = self.addon()
            mutate(config["inbounds"][1])
            with self.assertRaises(ValueError):
                telemetry.validate_augmentation(config)
            config.pop("api")
            with self.assertRaises(ValueError):
                telemetry.validate_augmentation(config, allow_legacy=True)

    def test_inbound_statistics_double_counting_and_extra_entrances_rejected(self):
        config = self.addon()
        config["policy"]["system"] = {"statsInboundUplink": True}
        with self.assertRaises(ValueError):
            telemetry.validate_augmentation(config)
        config = self.addon()
        config["inbounds"].append(copy.deepcopy(config["inbounds"][1]))
        with self.assertRaises(ValueError):
            telemetry.validate_augmentation(config)


class SharedControlsTests(legacy.Fixture):
    def control(self, existing_actions=None):
        calls = []
        state = {"root": "qdisc pfifo_fast 0: dev eth0 root refcnt 2\n", "ingress": "",
                 "actions": set(existing_actions or [])}

        def runner(args, check=True):
            calls.append(args)
            output = b""
            if args[:3] == ["ip", "route", "show"]:
                output = b"default via 1.1.1.1 dev eth0\n"
            elif args[:3] == ["tc", "qdisc", "show"]:
                output = (state["root"] + state["ingress"]).encode()
            elif args[:3] == ["tc", "qdisc", "replace"]:
                if state["root"].startswith("qdisc htb 7a00:"):
                    raise RuntimeError("CentOS 7 rejects replacing an HTB root with existing classes")
                state["root"] = "qdisc htb 7a00: dev eth0 root refcnt 2\n"
            elif args[:3] == ["tc", "qdisc", "add"]:
                state["ingress"] = "qdisc ingress ffff: dev eth0 parent ffff:fff1\n"
            elif args[:3] == ["tc", "qdisc", "del"]:
                if args[-1] == "root":
                    state["root"] = "qdisc pfifo_fast 0: dev eth0 root refcnt 2\n"
                else:
                    state["ingress"] = ""
            elif args[:3] == ["tc", "actions", "list"]:
                output = "\n".join("police 0x%x rate 1Mbit" % index for index in state["actions"]).encode()
            elif args[:3] == ["tc", "actions", "replace"]:
                state["actions"].add(int(args[args.index("index") + 1]))
            elif args[:3] == ["tc", "actions", "del"]:
                state["actions"].discard(int(args[-1]))
            return SimpleNamespace(stdout=output, returncode=0)
        return telemetry.LinuxControls(self.owner.directory, runner=runner), calls, state

    def test_tcp_udp_share_download_class_and_single_upload_police_action(self):
        controls, calls, state = self.control()
        controls.apply(set(), {1443: 1000000})
        downstream = [args for args in calls if args[:3] == ["tc", "filter", "add"] and "7a00:" in args]
        upstream = [args for args in calls if args[:3] == ["tc", "filter", "add"] and "ffff:" in args]
        self.assertEqual(len(downstream), 2)
        self.assertEqual(len(upstream), 2)
        self.assertEqual({args[-1] for args in downstream}, {"7a00:10"})
        action = str(telemetry.POLICE_BASE + 1443)
        self.assertEqual({args[-1] for args in upstream}, {action})
        self.assertEqual(sum(args[:3] == ["tc", "actions", "replace"] for args in calls), 1)
        for direction in (downstream, upstream):
            self.assertTrue(any(["protocol", "6", "0xff"] == args[index:index + 3]
                                for args in direction for index in range(len(args) - 2)))
            self.assertTrue(any(["protocol", "17", "0xff"] == args[index:index + 3]
                                for args in direction for index in range(len(args) - 2)))

    def test_each_account_owns_independent_policer_and_unlimit_removes_only_owned(self):
        outsider = 123
        controls, calls, state = self.control({outsider})
        controls.apply(set(), {443: 1000000, 1443: 2000000})
        self.assertEqual(state["actions"], {outsider, telemetry.POLICE_BASE + 443, telemetry.POLICE_BASE + 1443})
        controls.apply(set(), {1443: 2000000})
        self.assertEqual(state["actions"], {outsider, telemetry.POLICE_BASE + 1443})
        controls.apply(set(), {})
        self.assertEqual(state["actions"], {outsider})
        self.assertFalse(controls.state.get("owned"))

    def test_reserved_existing_external_policer_is_never_replaced(self):
        collision = telemetry.POLICE_BASE + 1443
        controls, calls, state = self.control({collision})
        with self.assertRaises(server.PanelError):
            controls.apply(set(), {1443: 1000000})
        self.assertFalse(any(args[:3] == ["tc", "qdisc", "replace"] for args in calls))
        self.assertFalse(any(args[:3] == ["tc", "actions", "replace"] for args in calls))
        self.assertEqual(state["actions"], {collision})

    def test_repeated_rate_changes_and_quota_only_updates_keep_owned_root(self):
        controls, calls, state = self.control()
        controls.apply(set(), {1443: 1000000})
        controls.apply(set(), {1443: 1000000})
        controls.apply(set(), {1443: 2000000})
        controls.apply({1443}, {1443: 2000000})
        controls.apply(set(), {1443: 2000000})
        root_installs = [args for args in calls if args[:3] == ["tc", "qdisc", "replace"]]
        self.assertEqual(len(root_installs), 1)
        rate_updates = [args for args in calls if args[:3] == ["tc", "class", "replace"]
                        and "7a00:10" in args]
        self.assertEqual([args[args.index("rate") + 1] for args in rate_updates],
                         ["1000000bit", "1000000bit", "2000000bit", "2000000bit", "2000000bit"])
        policers = [args for args in calls if args[:3] == ["tc", "actions", "replace"]]
        self.assertEqual([args[args.index("rate") + 1] for args in policers],
                         ["1000000bit", "1000000bit", "2000000bit", "2000000bit", "2000000bit"])
        controls.apply(set(), {})
        self.assertFalse(controls.state.get("owned"))
        self.assertEqual(state["actions"], set())
        controls.apply(set(), {1443: 3000000})
        self.assertEqual(sum(args[:3] == ["tc", "qdisc", "replace"] for args in calls), 2)

    def test_quota_blocks_both_transports_and_preserves_loopback_and_rst_exceptions(self):
        controls, calls, state = self.control()
        controls.apply({443, 1443}, {})
        for chain, direction in ((telemetry.CHAIN_IN, "--dport"), (telemetry.CHAIN_OUT, "--sport")):
            rules = [args for args in calls if "-A" in args and chain in args]
            self.assertEqual(rules[0][-3:], ["lo", "-j", "RETURN"])
            for port in (443, 1443):
                reject = [args for args in rules if direction in args and str(port) in args]
                self.assertEqual(len(reject), 2)
                self.assertTrue(any(args[-1] == "tcp-reset" for args in reject))
                self.assertTrue(any(args[-1] == "icmp-port-unreachable" for args in reject))
            if chain == telemetry.CHAIN_OUT:
                self.assertIn("--tcp-flags", rules[1])

    def test_invalid_quota_port_never_mutates_netfilter(self):
        controls, calls, state = self.control()
        with self.assertRaises(ValueError):
            controls.quota({80})
        self.assertEqual(calls, [])

    def test_source_code_is_python36_compatible(self):
        source = Path(telemetry.__file__).read_text(encoding="utf-8")
        if sys.version_info >= (3, 8):
            ast.parse(source, feature_version=(3, 6))
        else:
            ast.parse(source)


if __name__ == "__main__":
    unittest.main()
