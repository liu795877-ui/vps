set -eu
date -u
uptime
free -m
sysctl net.ipv4.tcp_congestion_control net.core.default_qdisc net.ipv4.tcp_slow_start_after_idle net.ipv4.tcp_mtu_probing
command -v tcpdump || true
vmstat 1 4
python3 - <<'PY'
import json, time
def traffic():
    for line in open('/proc/net/dev'):
        if line.strip().startswith('eth0:'):
            fields = line.split(':')[1].split()
            return int(fields[0]), int(fields[8])
before = traffic()
time.sleep(3)
after = traffic()
print('ETH0_MBIT_PER_SEC', json.dumps({'receive': round((after[0]-before[0])*8/3/1000000,3), 'transmit': round((after[1]-before[1])*8/3/1000000,3)}))
PY
nstat -az TcpRetransSegs TcpOutSegs TcpExtTCPSynRetrans TcpExtTCPTimeouts 2>/dev/null || true
ss -s
