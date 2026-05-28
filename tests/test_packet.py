import unittest

from sniffer.packet import IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP, Packet


ETHERNET_IPV4 = bytes.fromhex(
    "001122334455"
    "66778899aabb"
    "0800"
)


class PacketTest(unittest.TestCase):
    def test_parse_tcp_packet(self):
        raw = ETHERNET_IPV4 + bytes.fromhex(
            "450000280001000040060000c0a8010a08080808"
            "3039005000000000000000005002200000000000"
        )

        packet = Packet.from_bytes(raw, ts=123.0)

        self.assertEqual(packet.raw, raw)
        self.assertEqual(packet.ts, 123.0)
        self.assertEqual(packet.src_ip, "192.168.1.10")
        self.assertEqual(packet.dst_ip, "8.8.8.8")
        self.assertEqual(packet.proto, IPPROTO_TCP)
        self.assertEqual(packet.src_port, 12345)
        self.assertEqual(packet.dst_port, 80)
        self.assertEqual(packet.summary(), "TCP 192.168.1.10:12345 -> 8.8.8.8:80 [SYN] seq=0 ack=0")

    def test_parse_udp_packet(self):
        raw = ETHERNET_IPV4 + bytes.fromhex(
            "4500001c00020000401100000a00000101010101"
            "14e9003500080000"
        )

        packet = Packet.from_bytes(raw)

        self.assertEqual(packet.src_ip, "10.0.0.1")
        self.assertEqual(packet.dst_ip, "1.1.1.1")
        self.assertEqual(packet.proto, IPPROTO_UDP)
        self.assertEqual(packet.src_port, 5353)
        self.assertEqual(packet.dst_port, 53)
        self.assertEqual(packet.summary(), "UDP 10.0.0.1:5353 -> 1.1.1.1:53 len=8")

    def test_parse_icmp_packet(self):
        raw = ETHERNET_IPV4 + bytes.fromhex(
            "4500001c0003000040010000ac10000508080404"
            "0800000000010001"
        )

        packet = Packet.from_bytes(raw)

        self.assertEqual(packet.src_ip, "172.16.0.5")
        self.assertEqual(packet.dst_ip, "8.8.4.4")
        self.assertEqual(packet.proto, IPPROTO_ICMP)
        self.assertIsNone(packet.src_port)
        self.assertIsNone(packet.dst_port)
        self.assertEqual(packet.summary(), "ICMP 172.16.0.5 -> 8.8.4.4")

    def test_rejects_non_ipv4_ethernet_frame(self):
        raw = bytes.fromhex(
            "001122334455"
            "66778899aabb"
            "86dd"
            "0000000000000000000000000000000000000000"
        )

        with self.assertRaisesRegex(ValueError, "packet is shorter than an IPv6 header"):
            Packet.from_bytes(raw)

    def test_rejects_truncated_ipv4_packet(self):
        raw = ETHERNET_IPV4 + bytes.fromhex("45000028000100004006")

        with self.assertRaisesRegex(ValueError, "IPv4 header"):
            Packet.from_bytes(raw)


if __name__ == "__main__":
    unittest.main()
