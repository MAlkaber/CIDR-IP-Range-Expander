#!/usr/bin/env python3
"""
CIDR / IP Range Expander
=========================
Turns a CIDR block (e.g. 192.168.1.0/24) or an IP range (e.g.
192.168.1.10-192.168.1.20) into a flat list of individual IP addresses,
using Python's built-in `ipaddress` module.

Project 02 of a pentest/red-team learning portfolio.
Read README.md first for the concept walkthrough.

Usage:
    python3 cidr_expander.py <target> [--include-net-broadcast] [-o FILE]

Examples:
    python3 cidr_expander.py 192.168.1.0/24
    python3 cidr_expander.py 10.0.0.0/30 --include-net-broadcast
    python3 cidr_expander.py 192.168.1.10-192.168.1.20
"""

import argparse
import ipaddress
import sys


def expand_cidr(cidr: str, include_net_broadcast: bool) -> list[str]:
    """
    Expand a single CIDR block into a list of IP address strings.

    ipaddress.ip_network() parses "192.168.1.0/24" into an IPv4Network
    object that knows its network address, broadcast address, and every
    address in between - all computed from the prefix length (/24) via
    bitwise math on the 32-bit integer form of the address. That's the
    exact same math a router performs to decide whether a destination is
    on the local subnet.

    .hosts() yields only the *usable* addresses (skips the network and
    broadcast address for anything bigger than a /31) - what you want for
    scanning almost every time, since those two addresses aren't hosts.
    """
    network = ipaddress.ip_network(cidr, strict=False)

    if include_net_broadcast:
        return [str(ip) for ip in network]
    return [str(ip) for ip in network.hosts()]


def expand_range(range_str: str) -> list[str]:
    """
    Expand "start-end" (e.g. "192.168.1.10-192.168.1.20") into a list of
    IP address strings, inclusive of both ends.

    Handy when a target range doesn't align to a clean CIDR boundary -
    engagement scopes are often written this way instead of as a subnet.
    Each address is converted to its integer form, walked one at a time,
    then converted back to dotted-quad notation.
    """
    start_str, end_str = range_str.split("-", 1)
    start = ipaddress.ip_address(start_str.strip())
    end = ipaddress.ip_address(end_str.strip())

    if int(start) > int(end):
        start, end = end, start

    return [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]


def expand_target(target: str, include_net_broadcast: bool) -> list[str]:
    """Dispatch to the right expander based on the target string's format."""
    if "/" in target:
        return expand_cidr(target, include_net_broadcast)
    if "-" in target:
        return expand_range(target)
    # A single bare IP - just validate it and echo it back.
    return [str(ipaddress.ip_address(target))]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Expand a CIDR block or IP range into individual addresses."
    )
    parser.add_argument(
        "target",
        help="CIDR block (192.168.1.0/24), range (10.0.0.1-10.0.0.10), or single IP",
    )
    parser.add_argument(
        "--include-net-broadcast",
        action="store_true",
        help="Include the network and broadcast addresses (CIDR targets only)",
    )
    parser.add_argument(
        "-o", "--output",
        help="Write one IP per line to this file instead of stdout",
    )
    args = parser.parse_args()

    try:
        addresses = expand_target(args.target, args.include_net_broadcast)
    except ValueError as exc:
        parser.error(f"Invalid target '{args.target}': {exc}")

    if args.output:
        with open(args.output, "w") as f:
            f.write("\n".join(addresses) + "\n")
        print(f"[+] Wrote {len(addresses)} address(es) to {args.output}")
    else:
        for ip in addresses:
            print(ip)
        print(f"\n[+] {len(addresses)} address(es) total", file=sys.stderr)


if __name__ == "__main__":
    main()
