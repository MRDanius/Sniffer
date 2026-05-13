import errno
import signal

from sniffer.logger import Logger
from sniffer.packet_capture import PacketCapture
from sniffer.packet_filter import PacketFilter
from sniffer.pcap_writer import PcapWriter


class SnifferApp:
    def __init__(self, config, logger=None):
        self.config = config
        self.capture = PacketCapture(config.interface, config.count)
        self.filter = PacketFilter(config.protocol, config.port, config.ip)
        self.writer = PcapWriter(config.output)
        self.logger = logger or Logger(config.verbose)

    def run(self):
        signal.signal(signal.SIGINT, self.stop)

        try:
            self.writer.open()
            self.capture.start()
            self.logger.info("Capture started")

            while self.capture.running:
                try:
                    packet = self.capture.capture()
                except ValueError as error:
                    self.logger.info(f"Skipped packet: {error}")
                    continue

                if packet is None:
                    break

                if self.filter.matches(packet):
                    self.writer.write(packet)
                    self.logger.packet(packet)

                    if self.config.count is not None and self.writer.pkt_count >= self.config.count:
                        self.capture.stop()

            self.logger.info(f"Capture finished, saved packets: {self.writer.pkt_count}")
            return 0
        except KeyboardInterrupt:
            self.logger.info(f"Capture stopped, saved packets: {self.writer.pkt_count}")
            return 0
        except PermissionError:
            self.logger.error("No permission for raw socket. Run with sudo or CAP_NET_RAW.")
            return 1
        except OSError as error:
            self.logger.error(self._format_os_error(error))
            return 1
        finally:
            self.capture.stop()
            self.writer.close()

    def stop(self, sig=None, frame=None):
        self.capture.stop()

        if sig is not None:
            raise KeyboardInterrupt

    def _format_os_error(self, error):
        if getattr(error, "errno", None) == errno.EPERM:
            return "No permission for raw socket. Run with sudo or CAP_NET_RAW."

        if getattr(error, "filename", None):
            return f"File error: {error.filename}: {error.strerror}"

        return f"Error: {error}"
