set -eu
cat /root/raksmart-proxy-deploy-20261009/panel/last-command.private.log
tail -n 8 /root/raksmart-proxy-deploy-20261009/panel/linux-tests.private.log
systemctl is-active xray.service raksmart-hy2.service vps-panel.service caddy.service || true
ls -ld /etc/caddy /var/lib/caddy
getenforce || true
