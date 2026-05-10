import socket
import struct
import time


ETHERNET_HEADER_LEN = 14
ETHERTYPE_IPV4 = 0x0800

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17

PROTOCOL_NAMES = {
    IPPROTO_ICMP: "ICMP",
    IPPROTO_TCP: "TCP",
    IPPROTO_UDP: "UDP",
}


class Packet:
    def __init__(self, raw, ts, src_ip, dst_ip, proto, src_port=None, dst_port=None):
        self.raw = raw
        self.ts = ts
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.proto = proto
        self.src_port = src_port
        self.dst_port = dst_port

    @classmethod
    def from_bytes(cls, raw, ts=None):
        if len(raw) < ETHERNET_HEADER_LEN:
            raise ValueError("packet is shorter than an Ethernet header")

        ethertype = struct.unpack("!H", raw[12:14])[0]
        if ethertype != ETHERTYPE_IPV4:
            raise ValueError(f"unsupported Ethernet type: 0x{ethertype:04x}")

        ip_start = ETHERNET_HEADER_LEN
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
            raise ValueError("packet is shorter than the declared IPv4 header")

        total_length = struct.unpack("!H", raw[ip_start + 2 : ip_start + 4])[0]
        if total_length < ihl:
            raise ValueError("IPv4 total length is shorter than its header")
        if len(raw) < ip_start + total_length:
            raise ValueError("packet is shorter than the declared IPv4 total length")

        proto = raw[ip_start + 9]
        src_ip = socket.inet_ntoa(raw[ip_start + 12 : ip_start + 16])
        dst_ip = socket.inet_ntoa(raw[ip_start + 16 : ip_start + 20])

        src_port = None
        dst_port = None
        transport_start = ip_start + ihl

        if proto in (IPPROTO_TCP, IPPROTO_UDP):
            if total_length < ihl + 4:
                name = PROTOCOL_NAMES[proto]
                raise ValueError(f"{name} packet is shorter than a port header")
            src_port, dst_port = struct.unpack(
                "!HH", raw[transport_start : transport_start + 4]
            )

        return cls(
            raw=raw,
            ts=time.time() if ts is None else ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            proto=proto,
            src_port=src_port,
            dst_port=dst_port,
        )

    def protocol_name(self):
        return PROTOCOL_NAMES.get(self.proto, str(self.proto))

    def summary(self):
        endpoints = f"{self.src_ip} -> {self.dst_ip}"

        if self.src_port is None or self.dst_port is None:
            return f"{self.protocol_name()} {endpoints}"

        return (
            f"{self.protocol_name()} "
            f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}"
        )
