import socket
import struct
import time


ETHERNET_HEADER_LEN = 14
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58

PROTOCOL_NAMES = {
    IPPROTO_ICMP: "ICMP",
    IPPROTO_TCP: "TCP",
    IPPROTO_UDP: "UDP",
    IPPROTO_ICMPV6: "ICMPv6",
}


def parse_tcp_flags(flags_byte):
    flags = []

    if flags_byte & 0x01:
        flags.append("FIN")
    if flags_byte & 0x02:
        flags.append("SYN")
    if flags_byte & 0x04:
        flags.append("RST")
    if flags_byte & 0x08:
        flags.append("PSH")
    if flags_byte & 0x10:
        flags.append("ACK")
    if flags_byte & 0x20:
        flags.append("URG")

    return flags


class Packet:
    def __init__(
        self,
        raw,
        ts,
        src_ip,
        dst_ip,
        proto,
        src_port=None,
        dst_port=None,
        ip_version=None,
        ttl=None,
        hop_limit=None,
        tcp_seq=None,
        tcp_ack=None,
        tcp_flags=None,
        tcp_header_len=None,
        tcp_window=None,
        udp_len=None,
        udp_checksum=None,
        payload=b"",
        icmp_type=None,
        icmp_code=None,
    ):
        self.raw = raw
        self.ts = ts
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.proto = proto
        self.src_port = src_port
        self.dst_port = dst_port
        self.ip_version = ip_version
        self.ttl = ttl
        self.hop_limit = hop_limit
        self.tcp_seq = tcp_seq
        self.tcp_ack = tcp_ack
        self.tcp_flags = tcp_flags or []
        self.tcp_header_len = tcp_header_len
        self.tcp_window = tcp_window
        self.udp_len = udp_len
        self.udp_checksum = udp_checksum
        self.payload = payload
        self.icmp_type = icmp_type
        self.icmp_code = icmp_code

    @classmethod
    def from_bytes(cls, raw, ts=None):
        if len(raw) < ETHERNET_HEADER_LEN:
            raise ValueError("packet is shorter than an Ethernet header")

        ethertype = struct.unpack("!H", raw[12:14])[0]
        ip_start = ETHERNET_HEADER_LEN

        if ethertype == ETHERTYPE_IPV4:
            if len(raw) < ip_start + 20:
                raise ValueError("packet is shorter than an IPv4 header")

            first_ip_byte = raw[ip_start]
            version = first_ip_byte >> 4
            ihl = (first_ip_byte & 0x0F) * 4

            if version != 4:
                raise ValueError(f"unsupported IP version: {version}")
            if ihl < 20:
                raise ValueError(f"invalid IPv4 header length: {ihl}")
            if len(raw) < ip_start + ihl:
                raise ValueError(
                    "packet is shorter than the declared IPv4 header",
                )

            total_length = struct.unpack(
                "!H", raw[ip_start + 2:ip_start + 4],
            )[0]
            if total_length < ihl:
                raise ValueError(
                    "IPv4 total length is shorter than its header",
                )
            if len(raw) < ip_start + total_length:
                raise ValueError(
                    "packet is shorter than the declared IPv4 total length",
                )

            ip_version = 4
            proto = raw[ip_start + 9]
            ttl = raw[ip_start + 8]
            hop_limit = None
            src_ip = socket.inet_ntoa(raw[ip_start + 12:ip_start + 16])
            dst_ip = socket.inet_ntoa(raw[ip_start + 16:ip_start + 20])
            transport_start = ip_start + ihl
            packet_end = ip_start + total_length
        elif ethertype == ETHERTYPE_IPV6:
            if len(raw) < ip_start + 40:
                raise ValueError("packet is shorter than an IPv6 header")

            first_ip_byte = raw[ip_start]
            version = first_ip_byte >> 4
            if version != 6:
                raise ValueError(f"unsupported IP version: {version}")

            payload_length = struct.unpack(
                "!H", raw[ip_start + 4:ip_start + 6],
            )[0]
            total_length = 40 + payload_length
            if len(raw) < ip_start + total_length:
                raise ValueError(
                    "packet is shorter than the declared IPv6 length",
                )

            ip_version = 6
            proto = raw[ip_start + 6]
            ttl = None
            hop_limit = raw[ip_start + 7]
            src_ip = socket.inet_ntop(
                socket.AF_INET6, raw[ip_start + 8:ip_start + 24],
            )
            dst_ip = socket.inet_ntop(
                socket.AF_INET6, raw[ip_start + 24:ip_start + 40],
            )
            transport_start = ip_start + 40
            packet_end = ip_start + total_length
        else:
            raise ValueError(f"unsupported Ethernet type: 0x{ethertype:04x}")

        src_port = None
        dst_port = None
        tcp_seq = None
        tcp_ack = None
        tcp_flags = []
        tcp_header_len = None
        tcp_window = None
        udp_len = None
        udp_checksum = None
        payload = b""
        icmp_type = None
        icmp_code = None

        if proto == IPPROTO_TCP:
            if packet_end < transport_start + 20:
                raise ValueError("TCP packet is shorter than a TCP header")

            src_port, dst_port = struct.unpack(
                "!HH", raw[transport_start:transport_start + 4],
            )
            tcp_seq, tcp_ack = struct.unpack(
                "!II", raw[transport_start + 4:transport_start + 12],
            )
            tcp_header_len = (raw[transport_start + 12] >> 4) * 4

            if tcp_header_len < 20:
                raise ValueError(
                    f"invalid TCP header length: {tcp_header_len}",
                )
            if packet_end < transport_start + tcp_header_len:
                raise ValueError(
                    "packet is shorter than the declared TCP header",
                )

            flags_byte = raw[transport_start + 13]
            tcp_flags = parse_tcp_flags(flags_byte)
            tcp_window = struct.unpack(
                "!H", raw[transport_start + 14:transport_start + 16],
            )[0]
            payload = raw[transport_start + tcp_header_len:packet_end]
        elif proto == IPPROTO_UDP:
            if packet_end < transport_start + 8:
                raise ValueError("UDP packet is shorter than a UDP header")

            src_port, dst_port, udp_len, udp_checksum = struct.unpack(
                "!HHHH", raw[transport_start:transport_start + 8],
            )
            if udp_len < 8:
                raise ValueError(f"invalid UDP length: {udp_len}")
            if packet_end < transport_start + udp_len:
                raise ValueError(
                    "packet is shorter than the declared UDP length",
                )

            payload = raw[transport_start + 8:transport_start + udp_len]
        else:
            payload = raw[transport_start:packet_end]

        if proto in (IPPROTO_ICMP, IPPROTO_ICMPV6):
            icmp_body = raw[transport_start:packet_end]
            if len(icmp_body) >= 2:
                icmp_type = icmp_body[0]
                icmp_code = icmp_body[1]

        return cls(
            raw=raw,
            ts=time.time() if ts is None else ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            proto=proto,
            src_port=src_port,
            dst_port=dst_port,
            ip_version=ip_version,
            ttl=ttl,
            hop_limit=hop_limit,
            tcp_seq=tcp_seq,
            tcp_ack=tcp_ack,
            tcp_flags=tcp_flags,
            tcp_header_len=tcp_header_len,
            tcp_window=tcp_window,
            udp_len=udp_len,
            udp_checksum=udp_checksum,
            payload=payload,
            icmp_type=icmp_type,
            icmp_code=icmp_code,
        )

    def protocol_name(self):
        return PROTOCOL_NAMES.get(self.proto, str(self.proto))

    def summary(self):
        endpoints = f"{self.src_ip} -> {self.dst_ip}"

        if self.src_port is None or self.dst_port is None:
            return f"{self.protocol_name()} {endpoints}"

        endpoints = (
            f"{self.src_ip}:{self.src_port} -> "
            f"{self.dst_ip}:{self.dst_port}"
        )

        if self.proto == IPPROTO_TCP:
            flags = ",".join(self.tcp_flags) if self.tcp_flags else "-"
            return (
                f"TCP {endpoints} [{flags}] "
                f"seq={self.tcp_seq} ack={self.tcp_ack}"
            )

        if self.proto == IPPROTO_UDP:
            return f"UDP {endpoints} len={self.udp_len}"

        return f"{self.protocol_name()} {endpoints}"
