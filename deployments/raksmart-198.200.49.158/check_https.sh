set -u
curl --silent --show-error --noproxy '*' --connect-timeout 4 --max-time 8 --resolve 198-200-49-158.sslip.io:8443:127.0.0.1 --output /dev/null --write-out 'LOOPBACK_HTTP %{http_code} TLS %{time_appconnect}\n' https://198-200-49-158.sslip.io:8443/node-console/
find /var/lib/caddy/storage/certificates -type f -name '*.crt' 2>/dev/null
journalctl -u caddy.service --since '-5 minutes' --no-pager -o cat | tail -n 26
