set -eu
systemctl is-active raksmart-hy2.service xray.service
getcap /usr/local/bin/raksmart-hysteria2
ss -lunH
journalctl -u raksmart-hy2.service --since '-5 minutes' -n 30 --no-pager -o cat
sysctl net.core.rmem_max net.core.wmem_max
