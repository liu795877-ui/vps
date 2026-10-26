"""Cached IP location lookup for the managed server, independent of exit choice."""
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import threading
import time
from urllib.request import Request, urlopen

CACHE_SECONDS = 86400
RETRY_SECONDS = 300


def lookup_location(public_ip):
    address = ipaddress.ip_address(public_ip)
    if not address.is_global:
        raise ValueError('A public server address is required')
    providers = [
        ('ipwho.is', 'https://ipwho.is/' + str(address)),
        ('ipapi.co', 'https://ipapi.co/' + str(address) + '/json/'),
    ]
    for provider, url in providers:
        try:
            request = Request(url, headers={'User-Agent': 'Private-Node-Console'})
            with urlopen(request, timeout=3) as response:
                if not response.geturl().startswith('https://'):
                    continue
                data = json.loads(response.read(16384).decode('utf-8'))
            if (not isinstance(data, dict) or data.get('success') is False or data.get('error') or
                    ipaddress.ip_address(data.get('ip', '')) != address):
                continue
            country_code = data.get('country_code', '')
            if not isinstance(country_code, str) or not re.fullmatch(r'[A-Z]{2}', country_code):
                continue
            result = {'ip': str(address), 'country_code': country_code, 'provider': provider}
            for key in ('country', 'region', 'city'):
                value = data.get('country_name', data.get(key)) if key == 'country' else data.get(key)
                result[key] = value.strip()[:96] if isinstance(value, str) else ''
            result['looked_up_at'] = time.time()
            return result
        except (OSError, ValueError, TypeError):
            continue
    raise RuntimeError('IP location is temporarily unavailable')


class NodeInfo:
    def __init__(self, public_ip, cache_path, enabled=True):
        self.public_ip = public_ip
        self.cache_path = Path(cache_path)
        self.enabled = enabled
        self.lock = threading.Lock()
        self.location = None
        self.running = False
        self.next_attempt = 0
        try:
            cached = json.loads(self.cache_path.read_text(encoding='utf-8'))
            if (cached.get('ip') == public_ip and
                    re.fullmatch(r'[A-Z]{2}', cached.get('country_code', '')) and
                    isinstance(cached.get('looked_up_at'), (int, float))):
                self.location = cached
        except (OSError, ValueError, TypeError, AttributeError):
            pass

    def snapshot(self):
        with self.lock:
            now = time.time()
            fresh = (self.location is not None and
                     0 <= now - self.location['looked_up_at'] < CACHE_SECONDS)
            if self.enabled and not fresh and not self.running and now >= self.next_attempt:
                self.running = True
                worker = threading.Thread(target=self.refresh)
                worker.daemon = True
                worker.start()
            result = dict(self.location) if self.location else {}
            result['status'] = 'ready' if self.location else 'loading' if self.running else 'unavailable'
            return result

    def refresh(self):
        try:
            location = lookup_location(self.public_ip)
            with self.lock:
                self.location = location
            temporary = self.cache_path.with_name('.node-info-' + secrets.token_hex(8))
            try:
                with temporary.open('xb') as stream:
                    if os.name == 'posix':
                        os.fchmod(stream.fileno(), 0o600)
                    stream.write(json.dumps(location, ensure_ascii=False).encode('utf-8'))
                os.replace(str(temporary), str(self.cache_path))
            finally:
                if temporary.exists():
                    temporary.unlink()
        except (OSError, ValueError, RuntimeError):
            pass
        finally:
            with self.lock:
                self.running = False
                self.next_attempt = time.time() + RETRY_SECONDS


def protocol_label(inbound):
    protocol = inbound.get('protocol', '').upper()
    security = inbound.get('streamSettings', {}).get('security', '').upper()
    parts = [part for part in (protocol, security) if part and part != 'NONE']
    return ' + '.join(parts) or '代理节点'
