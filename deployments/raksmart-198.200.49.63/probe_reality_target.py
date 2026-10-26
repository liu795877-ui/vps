"""Verify TLS 1.3 and h2 through the VPS's outbound connection."""

import json
import ssl
from ssh_access import connect, FOLDER

client = connect()
results = []
try:
    for host in ["www.microsoft.com", "www.cloudflare.com", "www.apple.com"]:
        channel = client.get_transport().open_channel(
            "direct-tcpip", (host, 443), ("127.0.0.1", 0), timeout=12
        )
        channel.settimeout(12)
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(["h2", "http/1.1"])
        connection = context.wrap_bio(incoming, outgoing, server_hostname=host)
        try:
            while True:
                try:
                    connection.do_handshake()
                    if outgoing.pending:
                        channel.sendall(outgoing.read())
                    break
                except ssl.SSLWantReadError:
                    if outgoing.pending:
                        channel.sendall(outgoing.read())
                    data = channel.recv(32768)
                    if not data:
                        raise RuntimeError("TLS peer closed connection")
                    incoming.write(data)
            result = {"host": host, "tls": connection.version(),
                      "alpn": connection.selected_alpn_protocol(),
                      "certificate_verified": True}
        except Exception as error:
            result = {"host": host, "error": type(error).__name__ + ": " + str(error)}
        finally:
            channel.close()
        results.append(result)
        print(json.dumps(result), flush=True)
finally:
    client.close()
(FOLDER / "tls-target-check.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
