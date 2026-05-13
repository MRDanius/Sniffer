import logging


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

    def packet(self, packet):
        if self.verbose:
            self.info(packet.summary())
