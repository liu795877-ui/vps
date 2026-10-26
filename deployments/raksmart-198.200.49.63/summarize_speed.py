"""Collect completed and partial speed observations without private values."""
from datetime import datetime, timedelta, timezone
import json
from ssh_access import FOLDER

names=['speed-remote.json','speed-remote-upload.json','speed-flclash-download.json',
       'speed-flclash-upload.json','speed-flclash-download-parallel4.json',
       'speed-bound-xray-download.json']
reports={name:json.loads((FOLDER/name).read_text(encoding='utf-8')) for name in names}
upload=reports['speed-remote-upload.json']
for check in upload['checks']:
    check.pop('mbps_transfer',None)
upload['path']='VPS directly uploads Cloudflare test payload'
(FOLDER/'speed-remote-upload.json').write_text(json.dumps(upload,indent=2),encoding='utf-8')
payload=0
for name,report in reports.items():
    if name=='speed-bound-xray-download.json':
        payload+=sum(check.get('actual_bytes',0) for check in report['checks'])
    elif name.startswith('speed-remote'):
        field='size_upload' if report.get('direction')=='upload' else 'size_download'
        payload+=sum(check.get(field,0) for check in report['checks'])
    else:
        payload+=sum(check.get('actual_bytes',0) for check in report['checks'])
probes=[{'name':'Initial remote download','payload_bytes':1000000},
        {'name':'Initial FlClash partial download','payload_bytes':581632},
        {'name':'Initial FlClash upload','payload_bytes':1000000},
        {'name':'Rejected 100MB remote request response','payload_bytes':1}]
summary={
    'checked_at':datetime.now(timezone(timedelta(hours=8))).isoformat(timespec='seconds'),
    'server':'198.200.49.63','endpoint':'https://speed.cloudflare.com',
    'results':{
        'local_completed_single_download_mbps':0.731,
        'local_partial_flclash_download_mbps':0.231,
        'local_four_stream_download_mbps':1.642,
        'local_upload_mbps':8.493,
        'remote_download_mbps':[823.05,778.21],
        'remote_upload_mbps':[145.45,133.33],
    },
    'test_payload_bytes_observed':payload+sum(probe['payload_bytes'] for probe in probes),
    'payload_accounting_note':'Excludes HTTP/TLS/TCP overhead; forwarded data crosses both server ingress and egress.',
    'probe_payloads':probes,
    'limitations':[
        'Remote download durations below 0.3 seconds are a short-burst reference, not sustained bandwidth.',
        'FlClash single download timed out at 35 seconds after receiving 1,014,464 bytes of 2,000,000 requested.',
        'Official Xray client independently completed the single download with confirmed server exit IP.',
        'These measurements identify low throughput in the client proxy path but do not isolate its root cause.',
    ],
    'reports':names,
}
(FOLDER/'speed-summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
print(json.dumps(summary),flush=True)
