set -eu
systemctl is-active xray
systemctl is-enabled xray
ss -lntp
iptables -S
ip -4 address show
ip -4 route show
journalctl -u xray --no-pager -n 30
curl -4 -sS --connect-timeout 10 --max-time 15 https://api.ipify.org
python3 - <<'PY'
import socket
for host in ('127.0.0.1', '198.200.49.63', '::1'):
    try:
        with socket.create_connection((host, 443), timeout=3):
            print('\nTCP', host, 443, 'CONNECTED')
    except OSError as error:
        print('\nTCP', host, 443, str(error))
PY
sysctl net.ipv6.bindv6only
