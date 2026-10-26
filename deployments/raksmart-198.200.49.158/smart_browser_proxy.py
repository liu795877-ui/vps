"""Restricted CONNECT transport for the 158 smart routing browser verifier."""

import select
import socketserver

from smart_access import HOST, IP, physical_socket


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        upstream = None
        try:
            self.request.settimeout(10)
            header = b""
            while b"\r\n\r\n" not in header and len(header) < 8192:
                part = self.request.recv(1024)
                if not part:
                    return
                header += part
            request = header.split(b"\r\n", 1)[0].decode("ascii").split()
            if len(request) != 3 or request[0] != "CONNECT" or request[1] not in (HOST + ":8443", IP + ":8443"):
                self.request.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                return
            upstream = physical_socket(8443, 12)
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.request.settimeout(None)
            upstream.settimeout(None)
            while True:
                ready, _, _ = select.select([self.request, upstream], [], [], 25)
                if not ready:
                    return
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    target = upstream if source is self.request else self.request
                    target.sendall(data)
        except (OSError, UnicodeError):
            pass
        finally:
            if upstream:
                upstream.close()
