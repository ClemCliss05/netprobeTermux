
"""Command-line interface for NetProbe."""

import argparse

from netprobe.dns import lookup_host
from netprobe.scanner import scan_ports


def parse_ports(value: str) -> list[int]:
    """Parse a comma-separated list of TCP ports."""

    try:
        ports = [int(port.strip()) for port in value.split(",")]
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "Ports must be comma-separated integers"
        ) from exc

    if not ports:
        raise argparse.ArgumentTypeError("At least one port is required")

    if any(port < 1 or port > 65535 for port in ports):
        raise argparse.ArgumentTypeError("Ports must be between 1 and 65535")

    return ports


def main(argv: list[str] | None = None) -> int:
    """Run the NetProbe command-line interface."""

    parser = argparse.ArgumentParser(
        prog="netprobe",
        description="Lightweight network diagnostics tool",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan TCP ports on a host",
    )

    scan_parser.add_argument("host", help="Target hostname or IP address")
    scan_parser.add_argument(
        "--ports",
        type=parse_ports,
        default=[80, 443],
        help="Comma-separated TCP ports (default: 80,443)",
    )
    scan_parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0)",
    )

    dns_parser = subparsers.add_parser(
        "dns",
        help="Resolve a hostname using DNS",
    )

    dns_parser.add_argument(
        "host",
        help="Target hostname or IP address",
    )

    args = parser.parse_args(argv)

    if args.command == "dns":
        try:
            result = lookup_host(args.host)
        except ValueError as exc:
            parser.error(str(exc))

        print(f"\nNetProbe - DNS lookup: {result.host}\n")

        print("IPv4:")
        if result.ipv4:
            for address in result.ipv4:
                print(f"  {address}")
        else:
            print("  No IPv4 address found")

        print("\nIPv6:")
        if result.ipv6:
            for address in result.ipv6:
                print(f"  {address}")
        else:
            print("  No IPv6 address found")

        print(f"\nResolution time: {result.latency_ms:.2f} ms")

        if result.error:
            print(f"DNS error: {result.error}")
            print(f"Error code: {result.error_code}")

        print()

    if args.command == "scan":
        try:
            results = scan_ports(
                args.host,
                args.ports,
                timeout=args.timeout,
            )
        except ValueError as exc:
            parser.error(str(exc))

        print(f"\nNetProbe - TCP scan: {args.host}\n")
        print(f"{'PORT':<8} {'ADDRESS':<40} {'STATE':<14} {'LATENCY':>10}")
        print("-" * 76)

        for result in results:
            address = result.address or "-"
            state = result.state.value.upper()
            latency = f"{result.latency_ms:.2f} ms"

            print(
                f"{result.port:<8} "
                f"{address:<40} "
                f"{state:<14} "
                f"{latency:>10}"
            )

            if result.error_code is not None:
                print(f"         Error code: {result.error_code}")

        print(f"\n{len(results)} connection result(s)\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

