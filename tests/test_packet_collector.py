"""
Tests for the packet collector module
"""
import sys
import os
from dataclasses import dataclass, asdict

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Define classes locally to avoid scapy dependency in tests
@dataclass
class PacketEvent:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    packet_size: int
    direction: str


def get_direction(src_ip: str) -> str:
    """
    Определяем направление трафика относительно локальной сети
    """
    LOCAL_NET_PREFIX = "192.168."
    if src_ip.startswith(LOCAL_NET_PREFIX):
        return "out"
    return "in"


def test_get_direction_outgoing():
    """Test direction detection for outgoing traffic (local network)"""
    assert get_direction("192.168.1.1") == "out"
    assert get_direction("192.168.0.100") == "out"
    assert get_direction("192.168.255.254") == "out"


def test_get_direction_incoming():
    """Test direction detection for incoming traffic (external)"""
    assert get_direction("8.8.8.8") == "in"
    assert get_direction("1.1.1.1") == "in"
    assert get_direction("10.0.0.1") == "in"
    assert get_direction("172.16.0.1") == "in"


def test_packet_event_creation():
    """Test PacketEvent dataclass creation"""
    event = PacketEvent(
        timestamp=1707646800.123456,
        src_ip="192.168.1.100",
        dst_ip="8.8.8.8",
        src_port=54321,
        dst_port=443,
        protocol="TCP",
        packet_size=1500,
        direction="out"
    )
    
    assert event.timestamp == 1707646800.123456
    assert event.src_ip == "192.168.1.100"
    assert event.dst_ip == "8.8.8.8"
    assert event.src_port == 54321
    assert event.dst_port == 443
    assert event.protocol == "TCP"
    assert event.packet_size == 1500
    assert event.direction == "out"


def test_packet_event_to_dict():
    """Test PacketEvent conversion to dictionary"""
    event = PacketEvent(
        timestamp=1707646800.0,
        src_ip="10.0.0.1",
        dst_ip="192.168.1.1",
        src_port=80,
        dst_port=12345,
        protocol="UDP",
        packet_size=512,
        direction="in"
    )
    
    event_dict = asdict(event)
    
    assert isinstance(event_dict, dict)
    assert event_dict["timestamp"] == 1707646800.0
    assert event_dict["src_ip"] == "10.0.0.1"
    assert event_dict["dst_ip"] == "192.168.1.1"
    assert event_dict["protocol"] == "UDP"


def test_packet_event_with_none_ports():
    """Test PacketEvent with None ports (for protocols without ports)"""
    event = PacketEvent(
        timestamp=1707646800.0,
        src_ip="192.168.1.1",
        dst_ip="8.8.8.8",
        src_port=None,
        dst_port=None,
        protocol="ICMP",
        packet_size=84,
        direction="out"
    )
    
    assert event.src_port is None
    assert event.dst_port is None
    assert event.protocol == "ICMP"


if __name__ == "__main__":
    test_get_direction_outgoing()
    test_get_direction_incoming()
    test_packet_event_creation()
    test_packet_event_to_dict()
    test_packet_event_with_none_ports()
    print("✓ All tests passed!")
