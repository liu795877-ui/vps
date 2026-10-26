set -eu
uname -r
openssl version
ss -lnuH
systemctl is-active firewalld || true
iptables -S INPUT
getenforce || true
test -d /root/raksmart-proxy-deploy-20261009
command -v curl
command -v python3
