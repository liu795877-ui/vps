"""Record completed BBR trials without claiming an unproved improvement."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path


FOLDER = Path(__file__).resolve().parent
LABELS = ('standard-initial', 'conservative', 'aggressive', 'standard-final')


def read(name):
    return json.loads((FOLDER / name).read_bytes())


def main():
    initial = read('tuning-server-snapshot.json')
    final = read('tuning-server-final.json')
    idle = read('tuning-idle-standard.json')
    acceptance = read('tuning-final-acceptance.json')
    public = read('tuning-public-panel.json')
    restored = read('tuning-restore-standard.json')
    audit = read('tuning-evidence-audit.json')
    for item in (initial, final, idle, acceptance, public, restored):
        assert item['success'], 'A required final gate did not pass'
    assert initial['runtime_sha256'] == final['runtime_sha256']
    assert initial['source_sha256'] == final['source_sha256']
    assert final['profile'] == 'standard'
    assert final['runtime']['sysctls'] == {
        'net.core.rmem_max': 7340032, 'net.core.wmem_max': 7340032}
    assert acceptance['sources_verified'] == 6
    assert acceptance['settings_preserved'] and acceptance['limits_preserved']
    assert acceptance['protected_files_preserved'] and acceptance['monthly_totals_non_decreasing']
    assert acceptance['temporary_private_files_removed'] and acceptance['own_client_process_terminated']
    rows, evidence, cpu_peaks = [], [], []
    for label in LABELS:
        name = 'tuning-' + label + '.json'
        result = read(name)
        monitor_name = 'tuning-' + label + '-runtime.json'
        monitor = read(monitor_name)
        assert result['measurement_completed'] and result['all_settings_preserved']
        assert result['own_mihomo_processes_terminated'] and result['own_curl_processes_terminated']
        assert result['temporary_private_files_removed'] and not result['cleanup_errors']
        assert monitor['success']
        assert all(monitor['udp_total_delta'][key] == 0 for key in
                   ('InErrors', 'RcvbufErrors', 'SndbufErrors', 'InCsumErrors'))
        phases = {phase['name']: phase for phase in result['phases']}
        assert all(phases[key]['sufficient_load_coverage'] for key in ('download', 'upload'))
        rows.append({'label': label, 'server_profile': result['server_initial']['server_congestion']['bbrProfile'],
            'client_profile': result['client_profile'], 'complete_round_valid': result['measurement_valid'],
            'fresh_attempts': len(result['fresh_client']['samples']),
            'fresh_timeouts': sum(item['error_category'] == 'timeout' for item in result['fresh_client']['samples']),
            'warm_ttfb_ms': result['established_client']['stages']['ttfb_ms']['median'],
            'download_mbps': phases['download']['observed_load_mbps_including_request_overhead'],
            'upload_mbps': phases['upload']['observed_load_mbps_including_request_overhead'],
            'udp_buffer_errors': 0})
        cpu_peaks.append(max(sample['cpu_percent']['busy'] for sample in monitor['samples']))
        evidence.extend((name, monitor_name))
    assert read('tuning-aggressive.json')['measurement_valid']
    assert read('tuning-standard-final.json')['measurement_valid']
    evidence.extend(('tuning-server-snapshot.json', 'tuning-server-final.json', 'tuning-idle-standard.json',
        'tuning-apply-conservative.json', 'tuning-apply-aggressive.json', 'tuning-restore-standard.json',
        'tuning-final-acceptance.json', 'tuning-public-panel.json', 'tuning-comparison.json',
        'tuning-evidence-audit.json', 'tuning-idle-standard-failed-snapshot-20261010.json'))
    completed = datetime.now(timezone.utc).isoformat()
    report = {'success': True, 'status': 'evaluation_completed_original_settings_retained',
        'server': '198.200.49.63', 'completed_at': completed,
        'performance_gain_demonstrated': False,
        'decision': 'Keep server/client standard BBR defaults; retain verified 7 MiB UDP ceilings and existing keepalive.',
        'reason': 'Time drift exceeded the small apparent aggressive advantage over the final standard run; no reliable combined winner.',
        'original_runtime_bytes_restored': True, 'product_source_unchanged': True,
        'client_subscription_refresh_required': False, 'rows': rows,
        'idle_observations': [{'seconds': item['requested_idle_seconds'],
            'ttfb_ms': item['first_request_after_idle']['ttfb_ms'],
            'account_reconnect_events_observed': item['continuity_including_request']['reconnection_event_observed']}
            for item in idle['idle_observations']],
        'idle_warm_ttfb_ms': idle['established_client']['stages']['ttfb_ms']['median'],
        'server_cpu_peak_percent': max(cpu_peaks), 'all_monitor_udp_errors_zero': True,
        'buffer_ceiling_bytes': 7340032, 'six_public_transport_and_stat_sources_verified': True,
        'account_settings_and_limits_preserved': True, 'public_panel_https_status': public['status'],
        'checkpoint': restored['backup_dir'],
        'traffic_ledger_restored': False,
        'restart_accounting_limit': restored['restart']['tail_accounting_limitation'],
        'limits': ['Sequential WAN/CDN tests cannot establish small causal improvements.',
            'Initial standard and conservative rounds include 1 and 2 fresh timeouts; they did not pass complete-round validity.',
            'Fresh select-only clients are not production AUTO startup measurements.',
            'Short bounded multiblock speeds include HTTP/TLS overhead, not long-term saturated bandwidth.',
            'Account journal continuity does not uniquely identify the isolated QUIC session.'],
        'evidence_sha256': {name: hashlib.sha256((FOLDER / name).read_bytes()).hexdigest() for name in evidence}}
    (FOLDER / 'hy2-tuning-final.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    state = read('task-state.json')
    state['updated_at'] = completed
    state['latency_optimization']['bbr_followup'] = {key: report[key] for key in
        ('status', 'completed_at', 'performance_gain_demonstrated', 'decision', 'original_runtime_bytes_restored',
         'product_source_unchanged', 'client_subscription_refresh_required', 'all_monitor_udp_errors_zero',
         'six_public_transport_and_stat_sources_verified', 'account_settings_and_limits_preserved')}
    state['latency_optimization']['bbr_followup']['report'] = 'hy2-tuning-final.json'
    (FOLDER / 'task-state.json').write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    marker = '## HY2 保活与 BBR 档位复测（2026-10-10）'
    readme = FOLDER / 'README.md'
    text = readme.read_text(encoding='utf-8')
    if marker not in text:
        text += '\n' + marker + '\n\n'
        text += '本轮已完成实测及恢复验收，保留服务端和客户端 `standard` 档。未证明保守或激进档能稳定降低延迟或提高上下行速度；无需刷新配置订阅或重新导入。此前已部署的 7 MiB UDP 收发缓冲上限继续生效，四轮各 90 秒监控均无新增 UDP 缓冲错误，CPU 峰值为 20.89%。\n\n'
        text += '隔离客户端连续请求首字节中位数为 525 ms；空闲 30／60／180 秒后分别为 524／545／521 ms，出口匹配，账号在线数和进程保持，日志未观察到重连。Mihomo 原有每 10 秒保活和 AUTO 启动检查无需重复开启。这些账号层日志不能唯一标识隔离 QUIC 会话。\n\n'
        text += '| 测试顺序 | 下载 Mbps | 上传 Mbps | 连续请求首字节 ms |\n|---|---:|---:|---:|\n'
        for row in rows:
            text += '| ' + row['label'] + ' | ' + str(row['download_mbps']) + ' | ' + str(row['upload_mbps']) + ' | ' + str(row['warm_ttfb_ms']) + ' |\n'
        text += '\n同一标准档前后下载下降约 19%、上传下降约 32%，时段波动大于激进档相对末次标准档约 3%／5% 的表面优势。初始标准档和保守档各有 1／2 次首次连接超时，完整轮次未通过有效性检查；其有覆盖的负载阶段仅作为有限观察保留。首次请求使用无预热的 select 隔离配置，不等于生产 AUTO 启动体验。短时多块速度包含请求开销，不能当作长期饱和带宽。\n\n'
        text += '测试后原始运行配置按字节恢复，产品生成器未变更。三账号六条 HY2／TCP 公网出口、原生计数、最新正常账本采样与进程 epoch 均通过验收；账号、出口、规则、凭据及额度保留，月累计未下降。公网管理页 HTTPS 返回 200，临时客户端及私有测试文件已清理。重启前保存最终计数，不恢复旧账本；最终采样到服务停止之间的少量新流量存在未计入的可能，不承诺零字节计量损失。\n\n'
        text += '最终脱敏报告为 `hy2-tuning-final.json`，独立证据审计为 `tuning-evidence-audit.json`；三账号验收为 `tuning-final-acceptance.json`。本轮原配置 checkpoint 位于服务器 `/root/vps-hy2-bbr-20261010-tuning`。\n'
        readme.write_text(text, encoding='utf-8')
    print(json.dumps({'success': True, 'report': str(FOLDER / 'hy2-tuning-final.json'),
                      'performance_gain_demonstrated': False, 'client_update_required': False}))


if __name__ == '__main__':
    main()
