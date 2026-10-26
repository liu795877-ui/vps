"""Bounded, authenticated echo check of unused member UDP ports over WLAN."""
import json
import secrets
import socket
import time
from datetime import datetime, timezone
from ssh_access import connect, FOLDER, HOST
from frontend_motion_access import physical_wifi

REMOTE = r'''
import json, select, socket, time
marker=bytes.fromhex(MARKER)
sockets={}
counts={str(port):0 for port in [1443,2443]}
try:
    for port in [1443,2443]:
        stream=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        stream.bind(('0.0.0.0',port))
        sockets[stream]=port
    print(json.dumps({'ready':True,'ports':[1443,2443]}),flush=True)
    deadline=time.monotonic()+18
    while time.monotonic()<deadline:
        ready,_,_=select.select(list(sockets),[],[],.2)
        for stream in ready:
            packet,source=stream.recvfrom(2048)
            port=sockets[stream]
            if packet.startswith(marker) and 64<=len(packet)<=1400 and counts[str(port)]<9:
                stream.sendto(packet,source)
                counts[str(port)]+=1
        if all(value>=6 for value in counts.values()):
            break
finally:
    for stream in sockets:stream.close()
print(json.dumps({'counts':counts,'listeners_closed':True}),flush=True)
'''


def main():
    report={'checked_at':datetime.now(timezone.utc).isoformat(),'server':HOST,
            'physical_wlan':True,'configuration_mutations':0,'checks':[]}
    client=connect()
    try:
        marker=secrets.token_bytes(32)
        command="python3 -u - <<'MEMBER_UDP_PROBE'\nMARKER="+repr(marker.hex())+'\n'+REMOTE+"\nMEMBER_UDP_PROBE\n"
        stdin,stdout,stderr=client.exec_command(command,timeout=25)
        stdin.close()
        ready=json.loads(stdout.readline())
        if not ready.get('ready'):raise RuntimeError('Member UDP ports unavailable')
        wifi=physical_wifi()
        for port in ready['ports']:
            samples=[]
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as stream:
                stream.setsockopt(socket.IPPROTO_IP,31,socket.htonl(wifi['InterfaceIndex']))
                stream.bind((wifi['IPAddress'],0));stream.connect((HOST,port))
                for index,size in enumerate([128,1200,1400]*2):
                    payload=marker+index.to_bytes(2,'big')+b'P'*(size-34)
                    start=time.monotonic();stream.send(payload)
                    success=False
                    try:
                        while time.monotonic()-start<.8:
                            stream.settimeout(max(.01,.8-(time.monotonic()-start)))
                            if stream.recv(2048)==payload:
                                success=True;break
                    except OSError:pass
                    samples.append({'bytes':size,'success':success,'rtt_ms':round((time.monotonic()-start)*1000,2) if success else None})
            report['checks'].append({'port':port,'samples':samples,'reachable':any(item['success'] for item in samples)})
        completion=stdout.read().decode('utf-8').strip()
        if completion:report['completion']=json.loads(completion)
        report['remote_exit_code']=stdout.channel.recv_exit_status()
        report['all_member_ports_reachable']=all(item['reachable'] for item in report['checks'])
    except Exception as error:
        report['error']=type(error).__name__
    finally:
        client.close()
        (FOLDER/'hy2-member-udp-preflight.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report))


if __name__=='__main__':main()
