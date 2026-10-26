"""Finite proxy entrance catalog and the existing private-port layout.

Expanding this catalog never opens a firewall. Accounts allocates only from its
administrator-confirmed local pool; TCP and UDP reachability remains untested.
"""

import socket


DEFAULT_MEMBER_PORTS = (1443, 2443)
SUPPORTED_MEMBER_PORTS = DEFAULT_MEMBER_PORTS + (3444, 4444, 5444, 6445, 7445)
SUPPORTED_PUBLIC_PORTS = (443,) + SUPPORTED_MEMBER_PORTS
INTERNAL_OFFSETS = {"xray_stats": 15000, "hy2_socks": 15600, "hy2_stats": 18600}


def private_port(public_port, kind):
    if (type(public_port) is not int or not 1 <= public_port <= 65535
            or kind not in INTERNAL_OFFSETS):
        raise ValueError("Invalid proxy entrance or private service")
    result = public_port + INTERNAL_OFFSETS[kind]
    if result > 65535:
        raise ValueError("Private proxy service port is outside the valid range")
    return result


def bindings(public_port):
    """Return every listener reserved for one entrance, including both transports."""
    return ((socket.SOCK_STREAM, "0.0.0.0", public_port, "public_tcp"),
            (socket.SOCK_DGRAM, "0.0.0.0", public_port, "public_udp")) + tuple(
                (socket.SOCK_STREAM, "127.0.0.1", private_port(public_port, kind), kind)
                for kind in ("xray_stats", "hy2_socks", "hy2_stats"))


def validate_topology(public_ports):
    """Reject cross-account collisions in both public and private TCP listeners."""
    used = {}
    for public_port in public_ports:
        for protocol, address, port, service in bindings(public_port):
            # Wildcard public TCP also occupies its loopback address, so the
            # address cannot distinguish a public/private collision here.
            identity = (protocol, port)
            if identity in used:
                previous = used[identity]
                raise ValueError("入口 {0} 的 {1} 与入口 {2} 的 {3} 在端口 {4} 冲突。".format(
                    public_port, service, previous[0], previous[1], port))
            used[identity] = (public_port, service)
    return True


def validate_member_ports(member_ports, owner_port=443):
    if (not isinstance(member_ports, (list, tuple))
            or len(member_ports) > len(SUPPORTED_MEMBER_PORTS)
            or any(type(port) is not int for port in member_ports)):
        raise ValueError("请使用受支持的成员入口列表。")
    validate_topology((owner_port,) + tuple(member_ports))
    if any(port not in SUPPORTED_MEMBER_PORTS for port in member_ports):
        raise ValueError("成员入口不在可选端口列表中，请选择网页提供的入口。")
    return tuple(sorted(member_ports))


def probe_available(public_ports):
    """Only inspect bind availability; this does not prove public reachability."""
    for public_port in public_ports:
        for protocol, address, port, service in bindings(public_port):
            try:
                with socket.socket(socket.AF_INET, protocol) as probe:
                    probe.bind((address, port))
            except OSError as error:
                raise OSError("入口 {0} 的 {1} 端口 {2} 正在使用。".format(
                    public_port, service, port)) from error


def firewall_text(public_ports):
    ports = ", ".join(str(port) for port in public_ports)
    return ("请在云安全组和服务器本机防火墙允许 TCP 与 UDP 入口：" + ports +
            "。仅开放公网入口，不开放内部统计或转发端口。"
            "管理员确认放行仅用于预留资源，不代表公网连接已验证。")
