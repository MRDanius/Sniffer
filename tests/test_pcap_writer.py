import os
import struct
import tempfile
import unittest

from sniffer.packet import Packet
from sniffer.pcap_writer import PcapWriter


ETHERNET_IPV4 = bytes.fromhex(
    "001122334455"
    "66778899aabb"
    "0800"
)

TCP_PACKET = ETHERNET_IPV4 + bytes.fromhex(
    "450000280001000040060000c0a8010a08080808"
    "3039005000000000000000005002200000000000"
)


class PcapWriterTest(unittest.TestCase):
    def test_writes_global_header_and_packet(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "capture.pcap")
            packet = Packet.from_bytes(TCP_PACKET, ts=123.456789)
            writer = PcapWriter(path)

            writer.open()
            writer.write(packet)
            writer.close()

            with open(path, "rb") as file:
                data = file.read()

        global_header = data[:24]
        record_header = data[24:40]
        payload = data[40:]

        self.assertEqual(
            global_header,
            struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1),
        )
        self.assertEqual(
            record_header,
            struct.pack("<IIII", 123, 456789, len(TCP_PACKET), len(TCP_PACKET)),
        )
        self.assertEqual(payload, TCP_PACKET)
        self.assertEqual(writer.pkt_count, 1)

    def test_write_requires_open_file(self):
        packet = Packet.from_bytes(TCP_PACKET, ts=1.0)
        writer = PcapWriter("capture.pcap")

        with self.assertRaisesRegex(ValueError, "not open"):
            writer.write(packet)

    def test_close_can_be_called_more_than_once(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "capture.pcap")
            writer = PcapWriter(path)

            writer.open()
            writer.close()
            writer.close()

            self.assertIsNone(writer.file)


if __name__ == "__main__":
    unittest.main()
