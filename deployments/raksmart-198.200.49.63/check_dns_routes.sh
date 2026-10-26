set -eu
python3 - <<'PY'
import json, socket, time
from urllib.request import Request, urlopen
queries = [
 ('cloudflare_doh','https://cloudflare-dns.com/dns-query?name=www.gstatic.com&type=A'),
 ('google_doh_no_ecs','https://dns.google/resolve?name=www.gstatic.com&type=A&edns_client_subnet=0.0.0.0/0'),
 ('google_doh_us_ecs','https://dns.google/resolve?name=www.gstatic.com&type=A&edns_client_subnet=8.8.8.0/24'),
]
for name,url in queries:
    started=time.monotonic()
    try:
        request=Request(url, headers={'Accept':'application/dns-json'})
        with urlopen(request,timeout=10) as response:
            data=json.load(response)
        addresses = [answer['data'] for answer in data.get('Answer',[]) if answer['type']==1]
        timings=[]
        for address in addresses[:2]:
            begin=time.monotonic()
            with socket.create_connection((address,443),timeout=3):
                pass
            timings.append({'ip':address,'tcp_ms':round((time.monotonic()-begin)*1000,2)})
        print(json.dumps({'source':name,'addresses':addresses,'connect':timings,'dns_seconds':round(time.monotonic()-started,3)}),flush=True)
    except Exception as error:
        print(json.dumps({'source':name,'error':str(error)}),flush=True)
PY
