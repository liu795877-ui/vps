"""Trusted, physical-WLAN transport for the 63 frontend release tools.

Imports have no credential, network or application side effects.
"""

import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import time

FOLDER = Path(__file__).resolve().parent
IP = "198.200.49.63"
HOST = "198-200-49-63.sslip.io"
ORIGIN = "https://" + HOST + ":8443"
NO_WINDOW = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
cookie = None
_wifi = None


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def physical_wifi():
    global _wifi
    if _wifi is None:
        result = subprocess.run([
            "powershell.exe", "-NoProfile", "-Command",
            "Get-NetIPAddress -InterfaceAlias WLAN -AddressFamily IPv4 | "
            "Where-Object AddressState -eq Preferred | "
            "Select-Object -First 1 IPAddress,InterfaceIndex | ConvertTo-Json -Compress",
        ], capture_output=True, check=True, timeout=15, creationflags=NO_WINDOW)
        _wifi = json.loads(result.stdout.decode("utf-8-sig"))
        require(isinstance(_wifi, dict) and _wifi.get("IPAddress") and _wifi.get("InterfaceIndex"),
                "Physical WLAN has no usable IPv4 address")
    return _wifi


def physical_socket(port, timeout=12):
    wifi = physical_wifi()
    for attempt in range(3):
        stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            stream.settimeout(timeout)
            stream.setsockopt(socket.IPPROTO_IP, 31, socket.htonl(wifi["InterfaceIndex"]))
            stream.bind((wifi["IPAddress"], 0))
            stream.connect((IP, port))
            return stream
        except OSError:
            stream.close()
            if attempt == 2:
                raise
            time.sleep(.4)
        except Exception:
            stream.close()
            raise


class PhysicalHTTPS(http.client.HTTPSConnection):
    def connect(self):
        stream = physical_socket(self.port, self.timeout)
        try:
            self.sock = self._context.wrap_socket(stream, server_hostname=HOST)
        except Exception:
            stream.close()
            raise


def request(method, path, data=None, headers=None):
    extra = {"Origin": ORIGIN}
    if cookie:
        extra["Cookie"] = cookie
    if headers:
        extra.update(headers)
    body = json.dumps(data).encode("utf-8") if data is not None else None
    if body is not None:
        extra["Content-Type"] = "application/json"
    attempts = 3 if method == "GET" else 1
    for attempt in range(attempts):
        connection = PhysicalHTTPS(HOST, 8443, timeout=12, context=ssl.create_default_context())
        try:
            connection.request(method, "/node-console/" + path, body=body, headers=extra)
            response = connection.getresponse()
            result = response.status, dict(response.getheaders()), response.read()
            if method == "GET" and response.status in (502, 503, 504) and attempt + 1 < attempts:
                time.sleep(.4)
                continue
            return result
        except (OSError, http.client.HTTPException):
            if attempt + 1 == attempts:
                raise
            time.sleep(.4)
        finally:
            connection.close()
