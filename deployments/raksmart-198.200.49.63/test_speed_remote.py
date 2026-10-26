"""Bounded direct Cloudflare download test on the VPS via existing private SSH."""
import argparse
import json
from datetime import datetime, timedelta, timezone
from ssh_access import connect, execute, FOLDER

parser=argparse.ArgumentParser()
parser.add_argument('--bytes',type=int,default=20000000)
parser.add_argument('--count',type=int,default=2)
parser.add_argument('--upload',action='store_true')
args=parser.parse_args()
script=r'''
import json, subprocess, time
format = '{"http_code":%{http_code},"size_download":%{size_download},"size_upload":%{size_upload},"speed_download":%{speed_download},"time_total":%{time_total},"time_starttransfer":%{time_starttransfer},"remote_ip":"%{remote_ip}"}'
checks=[]
for index in range(COUNT):
    command=['curl','--noproxy','*','-4','--silent','--show-error',
             '--connect-timeout','10','--max-time','40','--output','/dev/null','--write-out',format]
    if UPLOAD:
        command += ['--request','POST','--header','Content-Type: application/octet-stream',
                    '--header','Expect:','--data-binary','@-','https://speed.cloudflare.com/__up']
    else:
        command += ['https://speed.cloudflare.com/__down?bytes=BYTES']
    result=subprocess.run(command,input=b'\0'*BYTES if UPLOAD else None,
                          stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45)
    try:
        check=json.loads(result.stdout.decode('utf-8'))
    except ValueError:
        check={'raw_output':result.stdout.decode('utf-8',errors='replace')[:300]}
    check.update(exit_code=result.returncode,error=result.stderr.decode('utf-8',errors='replace').strip(),sample=index+1)
    size=check.get('size_upload' if UPLOAD else 'size_download',0)
    seconds=check.get('time_total',0)
    check['success']=result.returncode==0 and check.get('http_code')==200 and size==BYTES
    if seconds:
        check['mbps_including_startup']=round(size*8/seconds/1e6,2)
        if not UPLOAD:
            transfer_seconds=seconds-check.get('time_starttransfer',seconds)
            check['mbps_transfer']=round(size*8/transfer_seconds/1e6,2) if transfer_seconds>0 else None
    print(json.dumps(check),flush=True)
    checks.append(check)
    if not check['success']:
        break
    time.sleep(1)
'''.replace('COUNT',str(args.count)).replace('BYTES',str(args.bytes)).replace('UPLOAD',str(args.upload))
client=connect()
try:
    import shlex
    code,output,error=execute(client,'python3 -u -c '+shlex.quote(script),timeout=args.count*50)
    checks=[json.loads(line) for line in output.splitlines() if line.startswith('{')]
    report={'checked_at':datetime.now(timezone(timedelta(hours=8))).isoformat(timespec='seconds'),
            'server':'198.200.49.63','path':'VPS directly transfers a Cloudflare test payload',
            'target':'https://speed.cloudflare.com','checks':checks,
            'direction':'upload' if args.upload else 'download',
            'remote_exit':code,'remote_error':error}
    name='speed-remote-upload.json' if args.upload else 'speed-remote.json'
    (FOLDER/name).write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report),flush=True)
finally:
    client.close()
