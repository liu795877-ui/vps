set -eu
python3 - <<'PY'
import json, time
from urllib.request import Request, urlopen
for host in ('1.1.1.1','1.0.0.1'):
    start=time.monotonic()
    request=Request('https://'+host+'/dns-query?name=www.gstatic.com&type=A',headers={'Accept':'application/dns-json'})
    with urlopen(request,timeout=8) as response:
        data=json.load(response)
    print(json.dumps({'doh_endpoint':host,'certificate_verified':True,'dns_status':data['Status'],
                     'ipv4_answers':[answer['data'] for answer in data.get('Answer',[]) if answer['type']==1],
                     'seconds':round(time.monotonic()-start,3)}))
PY
