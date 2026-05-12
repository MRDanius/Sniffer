import unittest

from sniffer.packet import Packet
from sniffer.packet_filter import PacketFilter


ETHERNET_IPV4 = bytes.fromhex(
    "001122334455"
    "66778899aabb"
    "0800"
)

TCP_PACKET = ETHERNET_IPV4 + bytes.fromhex(
    "450000280001000040060000c0a8010a08080808"
    "3039005000000000000000005002200000000000"
)

UDP_PACKET = ETHERNET_IPV4 + bytes.fromhex(
    "4500001c00020000401100000a00000101010101"
    "14e9003500080000"
)

ICMP_PACKET = ETHERNET_IPV4 + bytes.fromhex(
    "4500001c0003000040010000ac10000508080404"
    "0800000000010001"
)


class PacketFilterTest(unittest.TestCase):
    def test_empty_filter_matches_any_packet(self):
        packet = Packet.from_bytes(TCP_PACKET)
        packet_filter = PacketFilter()

        self.assertTrue(packet_filter.matches(packet))

    def test_matches_protocol(self):
        packet = Packet.from_bytes(TCP_PACKET)

        self.assertTrue(PacketFilter(proto="tcp").matches(packet))
        self.assertFalse(PacketFilter(proto="udp").matches(packet))

    def test_matches_source_or_destination_port(self):
        packet = Packet.from_bytes(TCP_PACKET)

        self.assertTrue(PacketFilter(port=12345).matches(packet))
        self.assertTrue(PacketFilter(port=80).matches(packet))
        self.assertFalse(PacketFilter(port=443).matches(packet))

    def test_port_filter_does_not_match_icmp(self):
        packet = Packet.from_bytes(ICMP_PACKET)

        self.assertFalse(PacketFilter(port=80).matches(packet))

    def test_matches_source_or_destination_ip(self):
        packet = Packet.from_bytes(UDP_PACKET)

        self.assertTrue(PacketFilter(ip="10.0.0.1").matches(packet))
        self.assertTrue(PacketFilter(ip="1.1.1.1").matches(packet))
        self.assertFalse(PacketFilter(ip="8.8.8.8").matches(packet))

    def test_matches_all_conditions(self):
        packet = Packet.from_bytes(TCP_PACKET)
        packet_filter = PacketFilter(proto="tcp", port=80, ip="8.8.8.8")

        self.assertTrue(packet_filter.matches(packet))

    def test_rejects_unknown_protocol(self):
        with self.assertRaisesRegex(ValueError, "unknown protocol"):
            PacketFilter(proto="arp")


if __name__ == "__main__":
    unittest.main()
