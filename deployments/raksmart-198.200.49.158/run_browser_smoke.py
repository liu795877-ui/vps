"""Run browser verification with an isolated CONNECT proxy on physical WLAN."""
import os
from pathlib import Path
import select
import socket
import socketserver
import subprocess
import threading
from verify_panel import wifi, HOST, IP

FOLDER=Path(__file__).resolve().parent
class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        upstream=None
        try:
            self.request.settimeout(10)
            header=b''
            while b'\r\n\r\n' not in header and len(header)<8192:
                part=self.request.recv(1024)
                if not part:return
                header+=part
            request=header.split(b'\r\n',1)[0].decode('ascii').split()
            if len(request)!=3 or request[0]!='CONNECT' or request[1] not in [HOST+':8443',IP+':8443']:
                self.request.sendall(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n');return
            upstream=socket.socket()
            upstream.settimeout(10)
            upstream.setsockopt(socket.IPPROTO_IP,31,socket.htonl(wifi['InterfaceIndex']))
            upstream.bind((wifi['IPAddress'],0));upstream.connect((IP,8443))
            self.request.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            self.request.settimeout(None);upstream.settimeout(None)
            while True:
                ready,_,_=select.select([self.request,upstream],[],[],15)
                if not ready:return
                for source in ready:
                    data=source.recv(65536)
                    if not data:return
                    target=upstream if source is self.request else self.request
                    target.sendall(data)
        except OSError:
            pass
        finally:
            if upstream:upstream.close()

server=socketserver.ThreadingTCPServer(('127.0.0.1',0),Handler)
server.daemon_threads=True
threading.Thread(target=server.serve_forever,daemon=True).start()
environment=os.environ.copy()
environment['NODE_CONSOLE_TEST_PROXY']='http://127.0.0.1:'+str(server.server_address[1])
try:
    result=subprocess.run(['node',str(FOLDER/'browser_smoke.mjs')],env=environment,timeout=100)
    raise SystemExit(result.returncode)
finally:
    server.shutdown();server.server_close()
