from bs4 import BeautifulSoup
from pathlib import Path
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import json
import re
from urllib.parse import urljoin

root = Path(__file__).parent
dc_source = 'https://greencloudvps.com/data-centers.php'
budget_source = 'https://greencloudvps.com/billing/store/budget-kvm-sale'
dc = BeautifulSoup((root / 'us_datacenters_page_agent.html').read_text(encoding='utf-8'), 'html.parser')
budget = BeautifulSoup((root / 'us_budget_page_agent.html').read_text(encoding='utf-8'), 'html.parser')
prefixes = ['BudgetKVMLA', 'BudgetKVMSJC', 'BudgetKVMAZ', None, 'BudgetKVMVA', 'BudgetKVMTX', 'BudgetKVMIL1', 'BudgetKVMIL2', 'BudgetKVMJAX', 'BudgetKVMNY', 'BudgetKVMMO', 'BudgetKVMUT', 'BudgetKVMNYC']
locations = []
for tr, prefix in zip(dc.select('table tr')[1:14], prefixes):
    cols = tr.find_all('td')
    if not cols:
        raise RuntimeError('Unexpected data-center table structure')
    label = cols[0].get_text(' ', strip=True)
    ip4 = cols[1].get_text(' ', strip=True)
    ip6 = cols[2].get_text(' ', strip=True)
    download = cols[3].find('a')
    locations.append({
        'official_datacenter_label': label,
        'official_test_ipv4': ip4,
        'official_test_ipv6': ip6,
        'test_download_label': download.get_text(' ',strip=True) if download else None,
        'test_download_url': download['href'] if download else None,
        'budget_product_prefix': prefix,
        'budget_products': [],
    })

for product in budget.select('div.product'):
    name = product.select_one('header span[id$="-name"]').get_text(' ', strip=True)
    loc = next((x for x in locations if x['budget_product_prefix'] and name in [x['budget_product_prefix']+'-2', x['budget_product_prefix']+'-3']), None)
    if loc is None:
        continue
    features = {}
    for li in product.select('.product-desc li'):
        val_tag = li.select_one('.feature-value')
        if not val_tag:
            continue
        val = val_tag.get_text(' ', strip=True)
        key = li.get_text(' ', strip=True).removeprefix(val).strip()
        features[key] = val
    price = product.select_one('.price').get_text(' ', strip=True)
    stock = int(re.search(r'\d+', product.select_one('.qty').get_text(' ', strip=True)).group())
    loc['budget_products'].append({
        'name': name,
        'stock_available': stock,
        'annual_price_usd': float(re.search(r'\d+\.\d+', price).group()),
        'order_url': urljoin(budget_source, product.select_one('.btn-order-now')['href']),
        'features': features,
        'description': product.select_one('.product-desc p').get_text(' ', strip=True),
    })

now = datetime.now(timezone.utc)
inventory = {
    'queried_at_utc': now.isoformat(),
    'queried_at_Asia_Shanghai': now.astimezone(ZoneInfo('Asia/Shanghai')).isoformat(),
    'sources': [dc_source, budget_source],
    'retrieval': 'requests HTTPS with browser User-Agent; both HTTP 200; saved original HTML',
    'stock_note': 'Stock is a point-in-time snapshot and may change before ordering.',
    'american_locations': locations,
}
(root / 'us_inventory_agent.json').write_text(json.dumps(inventory,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(inventory,ensure_ascii=False,indent=2))
