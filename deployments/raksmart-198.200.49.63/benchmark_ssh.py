"""Compare SSH data throughput to the proxy without downloading a local file."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import time
from ssh_access import connect,FOLDER

client=connect()
checks=[]
try:
    for sample in range(2):
        channel=client.get_transport().open_session(timeout=10)
        channel.settimeout(30)
        channel.exec_command("head -c 1000000 /dev/urandom")
        received=0
        digest=hashlib.sha256()
        start=time.perf_counter()
        while True:
            data=channel.recv(65536)
            if not data:
                break
            received+=len(data)
            digest.update(data)
        elapsed=time.perf_counter()-start
        code=channel.recv_exit_status()
        checks.append({'sample':sample+1,'bytes_received':received,'seconds':round(elapsed,3),
                       'mbps':round(received*8/elapsed/1e6,3),'success':code==0 and received==1000000})
        channel.close()
        print(json.dumps(checks[-1]),flush=True)
        time.sleep(1)
    report={'checked_at':datetime.now(timezone(timedelta(hours=8))).isoformat(timespec='seconds'),
            'path':'SSH TCP47650 bound to physical WLAN; random bytes generated in server memory',
            'checks':checks}
    (FOLDER/'speed-ssh-download.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
finally:
    client.close()
