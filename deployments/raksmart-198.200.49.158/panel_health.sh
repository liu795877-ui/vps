set -eu
systemctl is-active xray.service raksmart-hy2.service vps-panel.service caddy.service || true
systemctl is-enabled xray.service raksmart-hy2.service vps-panel.service caddy.service || true
ss -lntH
journalctl -u caddy.service -n 35 --no-pager -o cat
journalctl -u vps-panel.service -n 6 --no-pager -o cat
