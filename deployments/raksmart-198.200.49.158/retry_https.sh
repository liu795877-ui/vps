set -eu
systemctl restart caddy.service
systemctl is-active caddy.service
sleep 5
journalctl -u caddy.service --since '-15 seconds' --no-pager -o cat | tail -n 18
