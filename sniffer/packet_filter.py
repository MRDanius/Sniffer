from sniffer.packet import IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP


PROTOCOLS = {
    "ICMP": IPPROTO_ICMP,
    "ICMPV6": IPPROTO_ICMPV6,
    "TCP": IPPROTO_TCP,
    "UDP": IPPROTO_UDP,
}


class PacketFilter:
    def __init__(self, proto=None, port=None, ip=None):
        self.proto = self._normalize_proto(proto)
        self.port = port
        self.ip = ip

    def matches(self, packet):
        return (
            self._match_proto(packet)
            and self._match_port(packet)
            and self._match_ip(packet)
        )

    def _normalize_proto(self, proto):
        if proto is None:
            return None

        proto = proto.upper()
        if proto not in PROTOCOLS:
            raise ValueError("unknown protocol")

        return PROTOCOLS[proto]

    def _match_proto(self, packet):
        if self.proto is None:
            return True

        return packet.proto == self.proto

    def _match_port(self, packet):
        if self.port is None:
            return True

        return packet.src_port == self.port or packet.dst_port == self.port

    def _match_ip(self, packet):
        if self.ip is None:
            return True

        return packet.src_ip == self.ip or packet.dst_ip == self.ip
