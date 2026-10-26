set -eu
umask 077
stage=/root/raksmart-proxy-deploy-20261009/hysteria-v2.13.0
test ! -L "$stage"
mkdir -p "$stage"
cd "$stage"
if ! test -f hysteria-linux-amd64; then
  curl --fail --location --silent --show-error --connect-timeout 10 --max-time 50 --proto '=https' --proto-redir '=https' https://github.com/HyNetworks/hysteria/releases/download/app/v2.13.0/hysteria-linux-amd64 --output hysteria-linux-amd64.partial
  printf '907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691  hysteria-linux-amd64.partial\n' | sha256sum --check --status
  mv hysteria-linux-amd64.partial hysteria-linux-amd64
fi
printf '907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691  hysteria-linux-amd64\n' | sha256sum --check --status
chmod 0700 hysteria-linux-amd64
./hysteria-linux-amd64 version
