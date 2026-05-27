import argparse

from sniffer.sniffer_app import SnifferApp


class CLI:
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog="sniffer",
            description="Simple Linux packet sniffer",
        )
        self._setup_args()

    def _setup_args(self):
        self.parser.add_argument(
            "-i",
            "--interface",
            required=True,
            help="network interface name, for example eth0",
        )
        self.parser.add_argument(
            "-o",
            "--output",
            default="capture.pcap",
            help="output pcap file",
        )
        self.parser.add_argument(
            "-p",
            "--protocol",
            choices=["tcp", "udp", "icmp", "icmpv6"],
            help="filter by protocol",
        )
        self.parser.add_argument(
            "--port",
            type=int,
            help="filter by source or destination port",
        )
        self.parser.add_argument(
            "--ip",
            help="filter by source or destination IP address",
        )
        self.parser.add_argument(
            "-c",
            "--count",
            type=int,
            help="maximum number of captured packets",
        )
        self.parser.add_argument(
            "-v",
            "--verbose",
            action="store_true",
            help="print short info for each saved packet",
        )

    def parse(self, args=None):
        config = self.parser.parse_args(args)

        if config.port is not None and (
            config.port < 1 or config.port > 65535
        ):
            self.parser.error("--port must be in range 1..65535")

        if config.count is not None and config.count < 1:
            self.parser.error("--count must be greater than 0")

        return config

    def run(self, args=None):
        config = self.parse(args)
        app = SnifferApp(config)
        return app.run()
