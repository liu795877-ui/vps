set -eu
cat /etc/resolv.conf
getent ahostsv4 www.gstatic.com
getent ahostsv4 www.google.com
curl --noproxy '*' -sS --connect-timeout 8 --max-time 15 -I -w '\nGSTATIC status:%{http_code} remote:%{remote_ip} dns:%{time_namelookup} connect:%{time_connect} tls:%{time_appconnect} firstbyte:%{time_starttransfer} total:%{time_total}\n' https://www.gstatic.com/generate_204 https://www.gstatic.com/generate_204
curl --noproxy '*' -sS --connect-timeout 8 --max-time 15 -w '\n' 'https://dns.google/resolve?name=www.gstatic.com&type=A'
curl --noproxy '*' -sS --connect-timeout 8 --max-time 15 -I -w '\nCLOUDFLARE status:%{http_code} remote:%{remote_ip} dns:%{time_namelookup} connect:%{time_connect} tls:%{time_appconnect} firstbyte:%{time_starttransfer} total:%{time_total}\n' https://www.cloudflare.com/cdn-cgi/trace
