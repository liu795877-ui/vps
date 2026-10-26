set -eu
python3 - <<'PY'
import hashlib, json, re, statistics, subprocess, time
series={}
for sample in range(25):
    output=subprocess.check_output(['ss','-tinH','( sport = :443 )']).decode('utf-8',errors='replace')
    lines=output.splitlines()
    for index,line in enumerate(lines):
        if line.lstrip().startswith(('cubic','westwood','hybla','reno')) and index:
            endpoints=lines[index-1].split()[-2:]
            identity=hashlib.sha256('|'.join(endpoints).encode()).hexdigest()[:10]
            data={'second':sample,'algorithm':line.split()[0]}
            for field in ('rto','rtt','mss','cwnd','ssthresh','bytes_acked','bytes_sent','unacked','send','pacing_rate','retrans','rcv_space','wscale'):
                match=re.search(r'\b'+field+r'[: ]([^ ]+)',line)
                if match:
                    data[field]=match.group(1)
            series.setdefault(identity,[]).append(data)
    time.sleep(1)
active=[]
for identity,rows in series.items():
    first,last=rows[0],rows[-1]
    acknowledged=int(last.get('bytes_acked','0'))-int(first.get('bytes_acked','0'))
    retrans=max(int(row.get('retrans','0/0').split('/')[-1]) for row in rows)
    if acknowledged>20000 or retrans>5:
        active.append({'id':identity,'acked_delta':acknowledged,'max_retrans':retrans,'samples':rows})
print(json.dumps({'samples_seconds':25,'observed_flows':len(series),'active_flows':active}))
PY
