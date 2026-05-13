import socket

from sniffer.packet import Packet


ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800


class PacketCapture:
    def __init__(self, iface, count=None):
        self.iface = iface
        self.count = count
        self.sock = None
        self.running = False
        self.captured = 0

    def start(self):
        if not hasattr(socket, "AF_PACKET"):
            raise OSError("packet capture is supported only on Linux")

        self.sock = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(ETH_P_ALL),
        )
        try:
            self.sock.setsockopt(
                socket.SOL_SOCKET,
                getattr(socket, "SO_BINDTODEVICE", 25),
                self.iface.encode() + b"\0",
            )
        except OSError as error:
            self.stop()
            raise OSError(f"cannot use interface {self.iface}: {error}") from error

        self.running = True

    def stop(self):
        self.running = False

        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def capture(self):
        if not self.running:
            return None

        raw = self.sock.recv(65535)
        self.captured += 1

        return Packet.from_bytes(raw)
