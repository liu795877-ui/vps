"""Read-only server telemetry during one bounded latency benchmark."""
import argparse
import json
from pathlib import Path

from ssh_access import FOLDER, connect, execute


REMOTE = r'''
import json, os, subprocess, time
from pathlib import Path

def cpu():
    return list(map(int,Path('/proc/stat').read_text().splitlines()[0].split()[1:9]))

def udp():
    rows=[s.split()[1:] for s in Path('/proc/net/snmp').read_text().splitlines() if s.startswith('Udp:')]
    return dict(zip(rows[0],map(int,rows[1])))

def sockets():
    return subprocess.check_output(['ss','-u','-a','-n','-m','sport','=',':443','or','sport','=',':1443','or','sport','=',':2443'],universal_newlines=True,timeout=5)

def qdisc():
    return subprocess.check_output(['tc','-s','qdisc','show','dev','eth0'],universal_newlines=True,timeout=5)

rows=[]
started=time.monotonic()
previous_cpu=cpu()
previous_udp=udp()
initial_udp=dict(previous_udp)
while time.monotonic()-started < DURATION:
    time.sleep(2)
    current_cpu=cpu()
    current_udp=udp()
    delta=[b-a for a,b in zip(previous_cpu,current_cpu)]
    total=sum(delta)
    row={'at_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'elapsed_seconds':round(time.monotonic()-started,3),'cpu_percent':{'busy':round(100*(total-delta[3]-delta[4])/total,2) if total else 0,'steal':round(100*delta[7]/total,2) if total else 0},'udp_delta':{k:current_udp[k]-previous_udp[k] for k in previous_udp},'sockets':sockets()}
    if len(rows)%4==0:
        row['qdisc']=qdisc()
    rows.append(row)
    previous_cpu,previous_udp=current_cpu,current_udp
print(json.dumps({'success':True,'duration_seconds':round(time.monotonic()-started,3),'initial_udp':initial_udp,'final_udp':previous_udp,'udp_total_delta':{k:previous_udp[k]-initial_udp[k] for k in initial_udp},'samples':rows,'scope':'Read-only 2-second server counters during the corresponding test; global UDP counters include all users and services.'}))
'''


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--mode',choices=('baseline','after'),required=True)
    parser.add_argument('--seconds',type=int,default=150)
    parser.add_argument('--report',type=Path,
                        help='Separate report filename relative to this deployment; refuses overwrite.')
    args=parser.parse_args()
    if not 30<=args.seconds<=240:
        raise RuntimeError('Unexpected monitor duration')
    path=FOLDER/args.report if args.report is not None else FOLDER/('hy2-runtime-'+args.mode+'.json')
    if args.report is not None and (path.exists() or path.is_symlink()):
        raise RuntimeError('The requested report already exists')
    program='DURATION = '+str(args.seconds)+'\n'+REMOTE
    client=connect()
    try:
        code,out,_=execute(client,"python3 - <<'PY'\n"+program+"\nPY",timeout=args.seconds+25)
        if code:
            raise RuntimeError('Remote monitor failed')
        result=json.loads(out)
        with path.open('x' if args.report is not None else 'w',encoding='utf-8') as stream:
            stream.write(json.dumps(result,indent=2)+'\n')
        print(json.dumps({'success':True,'mode':args.mode,'samples':len(result['samples']),'udp_total_delta':result['udp_total_delta'],'report':str(path)}))
    finally:
        client.close()


if __name__=='__main__':
    main()
