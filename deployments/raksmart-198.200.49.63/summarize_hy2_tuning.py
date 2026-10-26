"""Read existing sanitized HY2 tuning JSON; perform no network or service work.

Print compact evidence, including failed requests and covered load probes.
Comparisons to time-interpolated standard are descriptive, not causal estimates.
Cold select-only requests are never presented as production AUTO startup gains.
"""

import argparse
from collections import Counter
from datetime import datetime
import json
from pathlib import Path
import statistics


METRICS = ("ttfb_ms", "tls_ready_ms", "http_wait_after_pretransfer_ms")


def distribution(rows, metric):
    values = [r[metric] for r in rows if r.get("success")
              and isinstance(r.get(metric), (int, float))]
    return {"attempts": len(rows), "successes": len(values),
            "median": round(statistics.median(values), 3) if values else None,
            "range": [round(min(values), 3), round(max(values), 3)] if values else None,
            "error_categories": dict(Counter(r.get("error_category", "unknown")
                                            for r in rows if not r.get("success")))}


def regions(rows):
    counts = Counter()
    missing = 0
    for row in rows:
        ray = row.get("response_identifiers", {}).get("cf-ray", "")
        suffix = ray.rsplit("-", 1)[-1] if "-" in ray else ""
        if 2 <= len(suffix) <= 6 and suffix.isalpha():
            counts[suffix.upper()] += 1
        else:
            missing += 1
    return {"counts": dict(counts), "missing": missing}


def phase_summary(phase):
    probes = phase.get("probes", [])
    light_all = [r for r in probes if r.get("kind") == "light"]
    tcp_all = [r for r in probes if r.get("kind") == "physical_tcp443_connect"]
    light = [r for r in light_all if r.get("fully_within_load_window")]
    tcp = [r for r in tcp_all if r.get("fully_within_load_window")]
    transfers = phase.get("load_transfers", [])
    failed = [r for r in transfers if not r.get("success")]
    unexpected = [r for r in failed if not r.get("expected_window_end_partial")]
    return {"name": phase.get("name"),
            "mbps_including_request_overhead": phase.get("observed_load_mbps_including_request_overhead"),
            "actual_bytes": phase.get("actual_load_bytes"),
            "full_blocks": phase.get("completed_full_blocks"),
            "active_transfer_seconds": phase.get("actual_transfer_seconds"),
            "phase_wall_seconds": phase.get("phase_wall_seconds"),
            "sufficient_coverage": phase.get("sufficient_load_coverage"),
            "byte_cap_reached": phase.get("load_byte_cap_reached"),
            "transfer_attempts": len(transfers),
            "expected_window_end_partials": len(failed) - len(unexpected),
            "unexpected_transfer_errors": dict(Counter(r.get("error_category", "unknown") for r in unexpected)),
            "light_all": distribution(light_all, "ttfb_ms"),
            "light_covered": {k: distribution(light, k) for k in METRICS},
            "tcp_all": distribution(tcp_all, "tcp_connect_ms"),
            "tcp_covered": distribution(tcp, "tcp_connect_ms"),
            "light_regions": regions(light_all), "transfer_regions": regions(transfers)}


def report_summary(path, report):
    fresh = report.get("fresh_client", {}).get("samples", [])
    warm = report.get("established_client", {}).get("samples", [])
    return {"file": path.name, "label": report.get("label"), "mode": report.get("mode"),
            "success": report.get("success"), "measurement_valid": report.get("measurement_valid"),
            "started_at": report.get("started_at"), "finished_at": report.get("finished_at"),
            "account_port": report.get("account_port"), "client_profile": report.get("client_profile"),
            "account_limits": report.get("account_limits"),
            "server_profile": report.get("server_initial", {}).get("server_congestion", {}).get("bbrProfile"),
            "settings_preserved": report.get("all_settings_preserved"),
            "cleanup_ok": not report.get("cleanup_errors") and all(report.get(k) for k in
                ("own_mihomo_processes_terminated", "own_curl_processes_terminated", "temporary_private_files_removed")),
            "failure_stage": report.get("failure_stage"),
            "comparison_identity": {k: report.get(k) for k in
                ("core_sha256", "benchmark_script_sha256", "method_sha256", "node_sha256_excluding_bbr_profile",
                 "account_identifier_sha256", "physical_interface_index")},
            "fresh_select_only": {k: distribution(fresh, k) for k in METRICS},
            "warm": {k: distribution(warm, k) for k in METRICS},
            "light_regions": regions(fresh + warm),
            "phases": {p["name"]: phase_summary(p) for p in report.get("phases", [])},
            "idle_observations": [{"seconds": o.get("requested_idle_seconds"),
                "request_success": o.get("first_request_after_idle", {}).get("success"),
                "ttfb_ms": o.get("first_request_after_idle", {}).get("ttfb_ms"),
                "tls_ready_ms": o.get("first_request_after_idle", {}).get("tls_ready_ms"),
                "http_wait_ms": o.get("first_request_after_idle", {}).get("http_wait_after_pretransfer_ms"),
                "no_account_reconnect_observed": o.get("continuity_including_request", {}).get("no_account_reconnect_event_observed"),
                "connected_event_delta": o.get("continuity_including_request", {}).get("account_connected_event_delta"),
                "disconnected_event_delta": o.get("continuity_including_request", {}).get("account_disconnected_event_delta"),
                "isolated_session_proven": o.get("continuity_including_request", {}).get("isolated_quic_session_reuse_conclusively_verified")}
                for o in report.get("idle_observations", [])]}


def timestamp(report):
    try:
        start = datetime.fromisoformat(report["started_at"]).timestamp()
        end = datetime.fromisoformat(report["finished_at"]).timestamp()
        return (start + end) / 2
    except (TypeError, ValueError, KeyError):
        return None


def headline(report):
    values = {"warm_ttfb_ms": report["warm"]["ttfb_ms"]["median"]}
    for name, phase in report["phases"].items():
        if name != "idle":
            values[name + "_mbps"] = phase["mbps_including_request_overhead"]
        values[name + "_covered_ttfb_ms"] = phase["light_covered"]["ttfb_ms"]["median"]
        values[name + "_covered_tcp_ms"] = phase["tcp_covered"]["median"]
    return values


def percent(value, reference):
    return round((value / reference - 1) * 100, 2) if isinstance(value, (int, float)) and reference else None


def comparisons(reports):
    profiles = [r for r in reports if r.get("mode") == "profile"]
    by_label = {r["label"]: r for r in profiles}
    before = by_label.get("standard-initial")
    after = by_label.get("standard-final")
    result = {"bracketing_standard_available": bool(before and after), "candidate_comparisons": []}
    if not before or not after:
        return result
    a, b = headline(before), headline(after)
    result["standard_final_vs_initial_percent"] = {k: percent(b.get(k), v) for k, v in a.items()}
    t0, t1 = timestamp(before), timestamp(after)
    for r in profiles:
        if r is before or r is after:
            continue
        t = timestamp(r)
        inside = t is not None and t0 is not None and t1 is not None and t0 < t < t1
        weight = (t - t0) / (t1 - t0) if inside else None
        same = all(r["comparison_identity"].get(k) == before["comparison_identity"].get(k)
                   == after["comparison_identity"].get(k) and r["comparison_identity"].get(k) is not None
                   for k in before["comparison_identity"])
        candidate = {"label": r["label"], "identity_matches": same,
                     "within_baseline_time_bracket": inside, "measurement_success": r["success"],
                     "metrics": {}}
        for k, v in headline(r).items():
            av, bv = a.get(k), b.get(k)
            baseline = av + (bv - av) * weight if weight is not None and av is not None and bv is not None else None
            candidate["metrics"][k] = {"observed": v, "standard_initial": av, "standard_final": bv,
                "interpolated_standard": round(baseline, 3) if baseline is not None else None,
                "vs_interpolated_standard_percent": percent(v, baseline),
                "vs_initial_percent": percent(v, av), "vs_final_percent": percent(v, bv)}
        result["candidate_comparisons"].append(candidate)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--folder", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()
    reports, unreadable = [], []
    for path in sorted(args.folder.glob("tuning-*.json")):
        try:
            source = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            unreadable.append(path.name)
            continue
        if source.get("mode") in ("idle", "profile") and "fresh_client" in source:
            reports.append(report_summary(path, source))
    reports.sort(key=lambda r: r.get("started_at") or "")
    comparison = comparisons(reports)
    if args.compact:
        reports = [{k: r[k] for k in ("label", "success", "measurement_valid", "started_at", "finished_at",
            "client_profile", "server_profile", "settings_preserved", "cleanup_ok", "failure_stage")}
            | {"metrics": headline(r), "fresh_select_only_ttfb": r["fresh_select_only"]["ttfb_ms"],
               "warm_ttfb": r["warm"]["ttfb_ms"], "light_regions": r["light_regions"],
               "load_evidence": {name: {k: p[k] for k in ("full_blocks", "actual_bytes", "active_transfer_seconds",
                   "phase_wall_seconds", "sufficient_coverage", "expected_window_end_partials", "unexpected_transfer_errors",
                   "light_all", "tcp_all", "light_regions", "transfer_regions")}
                   | {"covered_light_successes": p["light_covered"]["ttfb_ms"]["successes"],
                      "covered_tcp_successes": p["tcp_covered"]["successes"]}
                   for name, p in r["phases"].items()}, "idle_observations": r["idle_observations"]}
            for r in reports]
    print(json.dumps({"reports": reports, "unreadable_files": unreadable,
        "comparison": comparison, "limits": [
            "Sequential profile trials may be confounded by network drift and target/CDN changes.",
            "Time interpolation is descriptive and cannot remove nonlinear drift.",
            "Fresh select-only client scores do not measure production AUTO startup gain.",
            "Load overlap proves concurrent active HTTP transfers, not sustained link saturation.",
            "Expected transfer cutoff timeouts are reported separately from unexpected failures.",
            "Account session counters cannot conclusively identify the isolated QUIC connection.",
            "Small sample counts do not support p95 or long-term bandwidth claims."]}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
