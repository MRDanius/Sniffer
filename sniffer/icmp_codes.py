ICMP_DESCRIPTIONS = {
    (0, 0): "Echo Reply",
    (3, 0): "Destination Unreachable: Net Unreachable",
    (3, 1): "Destination Unreachable: Host Unreachable",
    (3, 2): "Destination Unreachable: Protocol Unreachable",
    (3, 3): "Destination Unreachable: Port Unreachable",
    (3, 6): "Destination Unreachable: Network Unknown",
    (3, 7): "Destination Unreachable: Host Unknown",
    (4, 0): "Source Quench",
    (5, 0): "Redirect: Network",
    (5, 1): "Redirect: Host",
    (8, 0): "Echo Request",
    (11, 0): "Time Exceeded: TTL Exceeded in Transit",
    (11, 1): "Time Exceeded: Fragment Reassembly Time Exceeded",
    (12, 0): "Parameter Problem",
}

ICMPV6_DESCRIPTIONS = {
    (1, 0): "Destination Unreachable: No Route",
    (1, 1): "Destination Unreachable: Administratively Prohibited",
    (1, 3): "Destination Unreachable: Address Unreachable",
    (1, 4): "Destination Unreachable: Port Unreachable",
    (2, 0): "Packet Too Big",
    (3, 0): "Time Exceeded: Hop Limit Exceeded",
    (3, 1): "Time Exceeded: Fragment Reassembly Time Exceeded",
    (4, 0): "Parameter Problem: Erroneous Header Field",
    (128, 0): "Echo Request",
    (129, 0): "Echo Reply",
    (133, 0): "Router Solicitation",
    (134, 0): "Router Advertisement",
    (135, 0): "Neighbor Solicitation",
    (136, 0): "Neighbor Advertisement",
}


def describe_icmp(proto, icmp_type, icmp_code):
    from sniffer.packet import IPPROTO_ICMPV6

    table = (
        ICMPV6_DESCRIPTIONS
        if proto == IPPROTO_ICMPV6
        else ICMP_DESCRIPTIONS
    )
    return table.get(
        (icmp_type, icmp_code),
        f"type={icmp_type} code={icmp_code}",
    )
