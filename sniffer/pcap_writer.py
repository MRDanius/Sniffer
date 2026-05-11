import struct


PCAP_MAGIC = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_SNAPLEN = 65535
PCAP_LINKTYPE_ETHERNET = 1


class PcapWriter:
    def __init__(self, path):
        self.path = path
        self.file = None
        self.pkt_count = 0

    def open(self):
        if self.file is not None:
            raise ValueError("pcap file is already open")

        self.file = open(self.path, "wb")
        self._write_header()

    def close(self):
        if self.file is not None:
            self.file.close()
            self.file = None

    def write(self, packet):
        if self.file is None:
            raise ValueError("pcap file is not open")

        self._write_record(packet)
        self.pkt_count += 1

    def _write_header(self):
        header = struct.pack(
            "<IHHIIII",
            PCAP_MAGIC,
            PCAP_VERSION_MAJOR,
            PCAP_VERSION_MINOR,
            0,
            0,
            PCAP_SNAPLEN,
            PCAP_LINKTYPE_ETHERNET,
        )
        self.file.write(header)

    def _write_record(self, packet):
        ts_sec = int(packet.ts)
        ts_usec = int((packet.ts - ts_sec) * 1000000)
        packet_len = len(packet.raw)

        record_header = struct.pack(
            "<IIII",
            ts_sec,
            ts_usec,
            packet_len,
            packet_len,
        )

        self.file.write(record_header)
        self.file.write(packet.raw)
