"""Async Port Scanner with banner grabbing.

Author: Faraz Mustafa Seyed
"""

import asyncio
import argparse
import json
import sys
import socket
import time
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class PortResult:
    port: int
    state: str
    service: str = ""
    banner: str = ""
    response_time_ms: float = 0.0
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    target: str
    scan_start: str = ""
    scan_end: str = ""
    total_ports_scanned: int = 0
    open_ports: list = field(default_factory=list)
    scan_duration_ms: float = 0.0
    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "scan_start": self.scan_start,
            "scan_end": self.scan_end,
            "total_ports_scanned": self.total_ports_scanned,
            "open_ports": [p.to_dict() for p in self.open_ports],
            "scan_duration_ms": round(self.scan_duration_ms, 2),
        }


COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https",
    993: "imaps", 995: "pop3s", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 27017: "mongodb", 2375: "docker",
    1433: "mssql", 1883: "mqtt", 6660: "irc",
}

BANNER_TIMEOUT = 2.0


async def resolve_target(target: str) -> str:
    loop = asyncio.get_event_loop()
    try:
        res = await loop.getaddrinfo(target, None, family=socket.AF_INET)
        if res:
            return res[0][4][0]
    except socket.gaierror:
        pass
    return target


async def scan_port(target: str, port: int, timeout: float) -> PortResult:
    result = PortResult(port=port, state="closed", service=COMMON_SERVICES.get(port, "unknown"))
    start = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(target, port), timeout=timeout)
        elapsed = (time.monotonic() - start) * 1000
        result.state = "open"
        result.response_time_ms = round(elapsed, 2)
        try:
            if port in (80, 8080, 443, 8443):
                writer.write(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\nConnection: close\r\n\r\n")
                await writer.drain()
            else:
                writer.write(b"\r\n")
                await writer.drain()
            banner_bytes = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            if banner_bytes:
                banner = banner_bytes.decode("utf-8", errors="replace").strip()
                if len(banner) > 200:
                    banner = banner[:200] + "..."
                result.banner = banner
        except (asyncio.TimeoutError, Exception):
            pass
        writer.close()
        await writer.wait_closed()
    except asyncio.TimeoutError:
        result.state = "filtered"
        result.response_time_ms = round((time.monotonic() - start) * 1000, 2)
    except (ConnectionRefusedError, OSError):
        result.state = "closed"
        result.response_time_ms = round((time.monotonic() - start) * 1000, 2)
    except Exception:
        result.state = "closed"
    return result


async def run_scan(target: str, ports: list[int], concurrency: int = 100, timeout: float = 1.0) -> ScanResult:
    resolved = await resolve_target(target)
    print(f"[*] Resolved {target} -> {resolved}")
    print(f"[*] Scanning {len(ports)} ports with concurrency={concurrency}, timeout={timeout}s")
    scan = ScanResult(target=target)
    scan.scan_start = datetime.utcnow().isoformat() + "Z"
    scan.total_ports_scanned = len(ports)
    sem = asyncio.Semaphore(concurrency)
    scan_start = time.monotonic()
    async def bounded_scan(port):
        async with sem:
            return await scan_port(resolved, port, timeout)
    tasks = [asyncio.create_task(bounded_scan(p)) for p in ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    scan.scan_duration_ms = (time.monotonic() - scan_start) * 1000
    scan.scan_end = datetime.utcnow().isoformat() + "Z"
    for r in results:
        if isinstance(r, PortResult) and r.state == "open":
            scan.open_ports.append(r)
    scan.open_ports.sort(key=lambda p: p.port)
    return scan


def print_results(scan: ScanResult) -> None:
    print(f"\n{'=' * 60}")
    print(f"  Port Scan Results — {scan.target}")
    print(f"  Scanned: {scan.total_ports_scanned} ports")
    print(f"  Duration: {scan.scan_duration_ms:.0f}ms")
    print(f"{'=' * 60}\n")
    if not scan.open_ports:
        print("  No open ports found.\n")
        return
    print(f"  {'PORT':<10} {'STATE':<12} {'SERVICE':<15} {'RESP TIME'}")
    print(f"  {'-'*10} {'-'*12} {'-'*15} {'-'*12}")
    for port in scan.open_ports:
        print(f"  {port.port:<10} {port.state:<12} {port.service:<15} {port.response_time_ms:.0f}ms")
        if port.banner:
            print(f"            banner: {port.banner.replace(chr(10), ' | ')[:80]}")
    print()


def parse_port_range(port_str: str) -> list[int]:
    ports: set[int] = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            low, high = part.split("-", 1)
            low, high = int(low.strip()), int(high.strip())
            if low > high:
                low, high = high, low
            ports.update(range(low, high + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def main() -> None:
    parser = argparse.ArgumentParser(description="Async TCP Port Scanner with Banner Grabbing")
    parser.add_argument("target", help="Target host")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range to scan")
    parser.add_argument("-c", "--concurrency", type=int, default=100, help="Max concurrent connections")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Connection timeout")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--show-closed", action="store_true", help="Include closed ports")
    args = parser.parse_args()
    ports = parse_port_range(args.ports)
    if not ports:
        print("Error: No valid ports specified.", file=sys.stderr)
        sys.exit(1)
    scan = asyncio.run(run_scan(args.target, ports, args.concurrency, args.timeout))
    if args.json:
        print(json.dumps(scan.to_dict(), indent=2))
    else:
        print_results(scan)


if __name__ == "__main__":
    main()
