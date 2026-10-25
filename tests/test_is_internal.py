"""Unit tests for the IPv4/IPv6 internal-address helper."""
from __future__ import annotations

import pytest
from scapy.all import IP, TCP, Ether, IPv6

from pcaplens.analyze import is_internal, l3_addrs


# IPv4 stays RFC 1918-only (RFC 5737 docs ranges and 127.0.0.1 stay external).
# IPv6 covers ULA (fc00::/7), link-local (fe80::/10), and loopback (::1).
@pytest.mark.parametrize(
    "ip,expected",
    [
        ("10.10.0.21", True),
        ("172.16.5.1", True),
        ("192.168.1.1", True),
        ("10.0.0.0", True),
        ("10.255.255.255", True),
        ("172.16.0.0", True),
        ("172.31.255.255", True),
        ("192.168.0.0", True),
        ("192.168.255.255", True),
        ("11.0.0.0", False),
        ("172.15.255.255", False),
        ("172.32.0.0", False),
        ("192.169.0.1", False),
        ("203.0.113.66", False),
        ("198.51.100.23", False),
        ("192.0.2.80", False),
        ("8.8.8.8", False),
        ("127.0.0.1", False),
        ("169.254.1.1", False),
        ("0.0.0.0", False),
        ("255.255.255.255", False),
        ("224.0.0.1", False),
        ("239.255.255.250", False),
        ("fd00:10:10::21", True),
        ("fc00::1", True),
        ("fc00::", True),
        ("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", True),
        ("fe80::1", True),
        ("fe80::", True),
        ("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", True),
        ("::1", True),
        ("0:0:0:0:0:0:0:1", True),
        ("FE80::1", True),
        ("fe00::", False),
        ("fec0::1", False),
        ("::2", False),
        ("::", False),
        ("2001:db8::1", False),
        ("2001:4860:4860::8888", False),
        ("ff02::1", False),
        ("ff05::2", False),
        # IPv4-mapped IPv6 uses the embedded IPv4 rules (RFC 1918 only).
        ("::ffff:10.0.0.1", True),
        ("::ffff:a00:1", True),
        ("::ffff:192.168.1.1", True),
        ("::ffff:172.16.0.1", True),
        ("::FFFF:10.10.0.21", True),
        ("::ffff:8.8.8.8", False),
        ("::ffff:203.0.113.66", False),
        ("::ffff:127.0.0.1", False),
        ("::ffff:169.254.1.1", False),
        ("::ffff:0.0.0.0", False),
        # %zone names a local interface; the address is unchanged.
        ("fe80::1%eth0", True),
        ("fe80::21%12", True),
        ("fd00:10:10::21%wlan0", True),
        ("2001:db8::1%eth0", False),
        ("::ffff:10.0.0.1%eth0", True),
        ("::ffff:8.8.8.8%eth0", False),
    ],
)
def test_is_internal_v4_and_v6(ip: str, expected: bool):
    assert is_internal(ip) is expected


@pytest.mark.parametrize("ip", ["not-an-ip", "", "256.1.1.1", "gggg::1", "1.2.3", "%"])
def test_is_internal_rejects_malformed(ip: str):
    with pytest.raises(ValueError):
        is_internal(ip)


def test_l3_addrs_ipv4_ipv6_or_neither():
    v4 = IP(src="10.0.0.1", dst="8.8.8.8") / TCP()
    assert l3_addrs(v4) == ("10.0.0.1", "8.8.8.8")
    v6 = IPv6(src="fd00::1", dst="2001:db8::1") / TCP()
    assert l3_addrs(v6) == ("fd00::1", "2001:db8::1")
    assert l3_addrs(Ether()) is None
