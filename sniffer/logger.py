import logging

from sniffer.icmp_codes import describe_icmp
from sniffer.packet import IPPROTO_ICMP, IPPROTO_ICMPV6


class Logger:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self._log = logging.getLogger("sniffer")
        self.setup(verbose)

    def setup(self, verbose=False):
        self.verbose = verbose

        if not self._log.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._log.addHandler(handler)

        self._log.setLevel(logging.INFO)

    def info(self, msg):
        self._log.info(msg)

    def error(self, msg):
        self._log.error(msg)

    def packet(self, packet, http=None):
        if self.verbose:
            self.info(packet.summary())

            is_icmp = packet.proto in (IPPROTO_ICMP, IPPROTO_ICMPV6)
            if is_icmp and packet.icmp_type is not None:
                desc = describe_icmp(
                    packet.proto, packet.icmp_type, packet.icmp_code,
                )
                self.info(f"  ICMP: {desc}")

            if http is not None:
                self.http(http)

    def http(self, http):
        if http["type"] == "request":
            self.info(
                f"  HTTP request: {http['method']} {http['path']} "
                f"{http['version']}",
            )
        else:
            status = f"{http['version']} {http['status']}"
            if http["reason"]:
                status = f"{status} {http['reason']}"
            self.info(f"  HTTP response: {status}")

        for name, value in http["headers"].items():
            self.info(f"    {name}: {value}")
