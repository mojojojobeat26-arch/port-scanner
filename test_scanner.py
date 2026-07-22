"""Tests for port scanner."""
from port_scanner import PortResult, ScanResult, parse_port_range

def test_port_result_to_dict():
    r = PortResult(port=80, state="open", service="http", banner="Apache/2.4", response_time_ms=100.0)
    d = r.to_dict()
    assert d["port"] == 80
    assert d["state"] == "open"
    assert d["banner"] == "Apache/2.4"
    print("ok: PortResult.to_dict")

def test_parse_port_range():
    assert parse_port_range("80") == [80]
    assert parse_port_range("1-1024") == list(range(1, 1025))
    assert parse_port_range("80,443,8080") == [80, 443, 8080]
    assert parse_port_range("22,80,443,8000-8100") == [22, 80, 443] + list(range(8000, 8101))
    print("ok: parse_port_range")

def test_empty_scan_result():
    scan = ScanResult(target="empty.test", total_ports_scanned=100, open_ports=[])
    assert scan.to_dict()["open_ports"] == []
    print("ok: empty scan")

def test_scan_result_to_dict():
    scan = ScanResult(target="example.com", total_ports_scanned=1024,
        open_ports=[PortResult(port=80,state="open"), PortResult(port=443,state="open")])
    d = scan.to_dict()
    assert d["total_ports_scanned"] == 1024
    assert len(d["open_ports"]) == 2
    print("ok: ScanResult.to_dict")

if __name__ == "__main__":
    test_port_result_to_dict()
    test_parse_port_range()
    test_empty_scan_result()
    test_scan_result_to_dict()
    print("\nAll tests passed!")