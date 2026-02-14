from scapy.all import sniff, IP, TCP, UDP, ICMP
from dataclasses import dataclass, asdict
import time
import json
import socket

LOCAL_NET_PREFIX = ""  # можно изменить под вашу сеть


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
    if src_ip.startswith(LOCAL_NET_PREFIX):
        return "out"
    return "in"


def process_packet(packet):
    if not packet.haslayer(IP):
        return

    ip = packet[IP]

    protocol = "OTHER"
    src_port = None
    dst_port = None

    if packet.haslayer(TCP):
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    elif packet.haslayer(ICMP):
        protocol = "ICMP"

    event = PacketEvent(
        timestamp=time.time(),
        src_ip=ip.src,
        dst_ip=ip.dst,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        packet_size=len(packet),
        direction=get_direction(ip.src)
    )

    emit_event(event)


def emit_event(event: PacketEvent):
    """
    Здесь мы пока просто печатаем событие в JSON.
    Позже заменим на очередь / БД / сокет.
    """
    print(json.dumps(asdict(event), ensure_ascii=False))


def start_collector(interface: str):
    print(f"[+] Starting packet collector on {interface}")
    sniff(
        iface=interface,
        prn=process_packet,
        store=False
    )


if __name__ == "__main__":
    # Linux: eth0, wlan0
    # Windows: "Ethernet", "Wi-Fi"
    start_collector(interface="wlo1")
