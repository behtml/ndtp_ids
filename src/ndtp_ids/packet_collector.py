from scapy.all import sniff, IP, TCP, UDP, ICMP
from dataclasses import dataclass, asdict
import time
import json
import socket

# Список локальных подсетей (RFC 1918 + loopback)
LOCAL_PREFIXES = [
    "10.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
    "127.",
]


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


def is_local_ip(ip: str) -> bool:
    """Проверяет, является ли IP локальным (RFC 1918 / loopback)"""
    return any(ip.startswith(prefix) for prefix in LOCAL_PREFIXES)


def get_direction(src_ip: str, dst_ip: str) -> str:
    """
    Определяем направление трафика:
    - out: из локальной сети наружу
    - in: из внешней сети внутрь
    - internal: оба адреса локальные
    - external: оба адреса внешние (транзит / захват на шлюзе)
    """
    src_local = is_local_ip(src_ip)
    dst_local = is_local_ip(dst_ip)
    
    if src_local and dst_local:
        return "internal"
    elif src_local and not dst_local:
        return "out"
    elif not src_local and dst_local:
        return "in"
    else:
        return "external"


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
        direction=get_direction(ip.src, ip.dst)
    )

    emit_event(event)


def emit_event(event: PacketEvent):
    """
     печатаем событие в JSON.
    """
    print(json.dumps(asdict(event), ensure_ascii=False))


def start_collector(interface: str = None):
    """
    Запуск сборщика пакетов.
    
    Args:
        interface: Сетевой интерфейс. Если None — слушает на всех интерфейсах.
    """
    if interface:
        print(f"[+] Starting packet collector on {interface}")
        sniff(iface=interface, prn=process_packet, store=False)
    else:
        print(f"[+] Starting packet collector on ALL interfaces")
        sniff(prn=process_packet, store=False)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Packet Collector — сбор сетевых пакетов")
    parser.add_argument(
        "--iface", "-i",
        default=None,
        help="Сетевой интерфейс (по умолчанию: все интерфейсы)"
    )
    args = parser.parse_args()
    
    # Linux: eth0, wlan0
    # Windows: "Ethernet", "Wi-Fi"
    start_collector(interface=args.iface)