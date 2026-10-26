set -eu
systemctl is-active --quiet raksmart-hy2.service
systemctl enable raksmart-hy2.service
systemctl is-enabled --quiet raksmart-hy2.service
systemctl restart raksmart-hy2.service
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  if systemctl is-active --quiet raksmart-hy2.service && ss -lunH | awk '{print $4}' | grep -qE ':443$'; then
    systemctl is-active --quiet xray.service
    printf 'HY2_ENABLED_UDP443\n'
    exit 0
  fi
  sleep 0.5
done
exit 23
