#!/usr/bin/env python3
"""
Симулятор атак для тестирования NDTP IDS
Все атаки направлены ТОЛЬКО на localhost (127.0.0.1)

Запуск:
    python scripts/attack_simulator.py --attack port_scan
    python scripts/attack_simulator.py --attack ssh_bruteforce
    python scripts/attack_simulator.py --attack all
    python scripts/attack_simulator.py --attack all --target 192.168.1.100
"""
import socket
import time
import random
import argparse
from datetime import datetime


def log(msg):
    """Логирование с timestamp"""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


# =====================================================================
#  АТАКА 1: Port Scan (сканирование портов)
# =====================================================================

def attack_port_scan(target: str = "127.0.0.1",
                     port_range: tuple = (1, 1024),
                     delay: float = 0.01):
    """
    Симуляция сканирования портов (как nmap -sT)

    Что ловит IDS:
    - Suricata: SID:1000003 "Connection to Privileged Port" (многократно)
    - Z-Score: unique_ports резко вырастет (z >> 3)
    - ML: вектор [high_conn, HIGH_ports, 1_dst_ip, low_bytes, small_packets]

    Ожидаемый severity: CRITICAL (все 3 слоя)
    """
    log(f"=== PORT SCAN на {target}:{port_range[0]}-{port_range[1]} ===")

    open_ports = []
    scanned = 0

    for port in range(port_range[0], port_range[1] + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            result = sock.connect_ex((target, port))

            if result == 0:
                open_ports.append(port)
                log(f"  [OPEN] Порт {port}")

            sock.close()
            scanned += 1

            if scanned % 100 == 0:
                log(f"  Просканировано: {scanned}/{port_range[1] - port_range[0] + 1}")

            time.sleep(delay)

        except socket.error:
            pass

    log(f"Сканирование завершено. Открытые порты: {open_ports}")
    log(f"Всего просканировано: {scanned}")
    return open_ports


# =====================================================================
#  АТАКА 2: Connection Flood (TCP флуд)
# =====================================================================

def attack_connection_flood(target: str = "127.0.0.1",
                            port: int = 80,
                            count: int = 500,
                            delay: float = 0.001):
    """
    Симуляция SYN/Connection Flood

    Что ловит IDS:
    - Suricata: если порт привилегированный → SID:1000003
    - Z-Score: connections_count резко вырастет (z >> 3)
    - ML: вектор [VERY_HIGH_conn, 1_port, 1_ip, medium_bytes, small_packets]

    Ожидаемый severity: CRITICAL
    """
    log(f"=== CONNECTION FLOOD на {target}:{port} ({count} соединений) ===")

    successful = 0
    failed = 0

    for i in range(count):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.05)
            sock.connect_ex((target, port))
            sock.close()
            successful += 1
        except socket.error:
            failed += 1

        if (i + 1) % 100 == 0:
            log(f"  Отправлено: {i + 1}/{count}")

        time.sleep(delay)

    log(f"Flood завершён. Успешных: {successful}, Ошибок: {failed}")


# =====================================================================
#  АТАКА 3: Slow Port Scan (медленное сканирование)
# =====================================================================

def attack_slow_scan(target: str = "127.0.0.1",
                     ports: list = None,
                     delay: float = 5.0):
    """
    Медленное сканирование — 1 порт каждые N секунд

    Что ловит IDS:
    - Suricata: ❌ слишком редкие соединения
    - Z-Score: ❌ connections_count ≈ норма
    - ML: ✅ необычная комбинация (мало соединений + разные порты + мало байт)

    Ожидаемый severity: LOW (только ML)
    """
    if ports is None:
        ports = [22, 23, 25, 80, 110, 143, 443, 445, 993, 995,
                 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9090]

    log(f"=== SLOW SCAN на {target} ({len(ports)} портов, задержка {delay}с) ===")

    for i, port in enumerate(ports):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            status = "OPEN" if result == 0 else "CLOSED"
            log(f"  [{i + 1}/{len(ports)}] Порт {port}: {status}")
            sock.close()
        except socket.error as e:
            log(f"  [{i + 1}/{len(ports)}] Порт {port}: ERROR ({e})")

        time.sleep(delay)

    log("Slow scan завершён.")


# =====================================================================
#  АТАКА 4: Горизонтальное сканирование
# =====================================================================

def attack_horizontal_scan(subnet: str = "127.0.0",
                           port: int = 80,
                           host_range: tuple = (1, 50),
                           delay: float = 0.05):
    """
    Горизонтальное сканирование — один порт на множество хостов

    Что ловит IDS:
    - Suricata: зависит от порта
    - Z-Score: unique_dst_ips резко вырастет
    - ML: необычный паттерн [low_conn, 1_port, MANY_ips, low_bytes]

    Ожидаемый severity: HIGH
    """
    log(f"=== HORIZONTAL SCAN {subnet}.{host_range[0]}-{host_range[1]}:{port} ===")

    for i in range(host_range[0], host_range[1] + 1):
        target = f"{subnet}.{i}"
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect_ex((target, port))
            sock.close()
        except socket.error:
            pass

        if (i - host_range[0] + 1) % 10 == 0:
            log(f"  Просканировано: {i - host_range[0] + 1}/{host_range[1] - host_range[0] + 1}")

        time.sleep(delay)

    log("Horizontal scan завершён.")


# =====================================================================
#  АТАКА 5: SSH Brute-Force
# =====================================================================

def attack_ssh_bruteforce(target: str = "127.0.0.1",
                          port: int = 22,
                          attempts: int = 100,
                          delay: float = 0.1):
    """
    Имитация SSH brute-force — множество соединений на порт 22

    Что ловит IDS:
    - Suricata: ✅ SID:1000001 "SSH Connection Attempt" × N
    - Z-Score: ✅ connections_count вырастет
    - ML: ✅ аномальный паттерн

    Ожидаемый severity: CRITICAL (все 3 слоя)
    """
    log(f"=== SSH BRUTE-FORCE на {target}:{port} ({attempts} попыток) ===")

    for i in range(attempts):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.2)
            sock.connect_ex((target, port))
            try:
                sock.send(b"SSH-2.0-OpenSSH_8.0\r\n")
            except Exception:
                pass
            sock.close()
        except socket.error:
            pass

        if (i + 1) % 20 == 0:
            log(f"  Попыток: {i + 1}/{attempts}")

        time.sleep(delay)

    log(f"SSH brute-force завершён. Попыток: {attempts}")


# =====================================================================
#  АТАКА 6: RDP сканирование
# =====================================================================

def attack_rdp_scan(target: str = "127.0.0.1",
                    count: int = 50,
                    delay: float = 0.1):
    """
    Сканирование RDP порта 3389

    Что ловит IDS:
    - Suricata: ✅ SID:1000007 "RDP Connection Attempt"
    - Z-Score: ✅ connections_count вырастет
    - ML: ✅ аномальный паттерн

    Ожидаемый severity: CRITICAL
    """
    log(f"=== RDP SCAN на {target}:3389 ({count} соединений) ===")

    for i in range(count):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.2)
            sock.connect_ex((target, 3389))
            sock.close()
        except socket.error:
            pass

        time.sleep(delay)

    log("RDP scan завершён.")


# =====================================================================
#  АТАКА 7: DNS Flood
# =====================================================================

def attack_dns_flood(target: str = "127.0.0.1",
                     count: int = 200,
                     delay: float = 0.01):
    """
    DNS flood — множество UDP запросов на порт 53

    Что ловит IDS:
    - Suricata: ✅ SID:1000005 "DNS Request" × N
    - Z-Score: ✅ connections_count вырастет
    - ML: ✅ аномальный паттерн

    Ожидаемый severity: HIGH-CRITICAL
    """
    log(f"=== DNS FLOOD на {target}:53 ({count} запросов) ===")

    # Простой DNS запрос
    dns_query = (
        b'\xaa\xbb'   # Transaction ID
        b'\x01\x00'   # Flags: Standard query
        b'\x00\x01'   # Questions: 1
        b'\x00\x00'   # Answer RRs: 0
        b'\x00\x00'   # Authority RRs: 0
        b'\x00\x00'   # Additional RRs: 0
        b'\x07example\x03com\x00'  # Query: example.com
        b'\x00\x01'   # Type: A
        b'\x00\x01'   # Class: IN
    )

    sent = 0
    for i in range(count):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.05)
            sock.sendto(dns_query, (target, 53))
            sock.close()
            sent += 1
        except socket.error:
            pass

        if (i + 1) % 50 == 0:
            log(f"  Отправлено: {i + 1}/{count}")

        time.sleep(delay)

    log(f"DNS flood завершён. Отправлено: {sent}")


# =====================================================================
#  АТАКА 8: Data Exfiltration
# =====================================================================

def attack_data_exfiltration(target: str = "127.0.0.1",
                             port: int = 8888,
                             total_mb: int = 10,
                             chunk_size: int = 65536):
    """
    Симуляция выгрузки данных — генерация большого трафика на один хост

    Что ловит IDS:
    - Suricata: ❌ (нестандартный порт)
    - Z-Score: ✅ total_bytes резко вырастет
    - ML: ✅ необычная комбинация [few_conn, 1_port, 1_ip, HUGE_bytes, big_packets]

    Ожидаемый severity: HIGH (Z-Score + ML)
    """
    log(f"=== DATA EXFILTRATION на {target}:{port} ({total_mb} MB) ===")

    total_bytes_target = total_mb * 1024 * 1024
    sent = 0

    try:
        while sent < total_bytes_target:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((target, port))
                data = bytes(random.getrandbits(8) for _ in range(chunk_size))
                sock.sendall(data)
                sent += chunk_size
                sock.close()

                if sent % (1024 * 1024) == 0:
                    log(f"  Отправлено: {sent // (1024 * 1024)} MB / {total_mb} MB")

            except (ConnectionRefusedError, socket.error):
                sent += chunk_size
                time.sleep(0.001)

        log(f"Exfiltration завершена. Отправлено: {sent // (1024 * 1024)} MB")

    except KeyboardInterrupt:
        log(f"Прервано. Отправлено: {sent // (1024 * 1024)} MB")


# =====================================================================
#  АТАКА 9: SMB Scan (порт 445)
# =====================================================================

def attack_smb_scan(target: str = "127.0.0.1",
                    count: int = 50,
                    delay: float = 0.1):
    """
    Сканирование SMB порта 445 (EternalBlue, WannaCry)

    Что ловит IDS:
    - Suricata: ✅ SID:1000008 "SMB Connection"
    - Z-Score: ✅ connections_count вырастет
    - ML: ✅ аномальный паттерн

    Ожидаемый severity: CRITICAL
    """
    log(f"=== SMB SCAN на {target}:445 ({count} соединений) ===")

    for i in range(count):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.2)
            sock.connect_ex((target, 445))
            sock.close()
        except socket.error:
            pass

        time.sleep(delay)

    log("SMB scan завершён.")


# =====================================================================
#  ЗАПУСК ВСЕХ АТАК ПОСЛЕДОВАТЕЛЬНО
# =====================================================================

def run_all_attacks(target: str = "127.0.0.1", pause: int = 30):
    """Запуск всех атак последовательно с паузами"""

    log("=" * 60)
    log("ЗАПУСК ПОЛНОГО ТЕСТОВОГО НАБОРА АТАК")
    log(f"Цель: {target}")
    log(f"Пауза между атаками: {pause}с")
    log("=" * 60)

    attacks = [
        ("Port Scan (1-100)",     lambda: attack_port_scan(target, (1, 100), 0.01)),
        ("SSH Brute-Force",       lambda: attack_ssh_bruteforce(target, 22, 50, 0.05)),
        ("RDP Scan",              lambda: attack_rdp_scan(target, 30, 0.1)),
        ("SMB Scan",              lambda: attack_smb_scan(target, 30, 0.1)),
        ("Connection Flood",      lambda: attack_connection_flood(target, 80, 200, 0.005)),
        ("DNS Flood",             lambda: attack_dns_flood(target, 100, 0.01)),
        ("Slow Scan",             lambda: attack_slow_scan(target, delay=2.0)),
        ("Horizontal Scan",       lambda: attack_horizontal_scan("127.0.0", 80, (1, 20), 0.1)),
    ]

    for i, (name, attack_fn) in enumerate(attacks, 1):
        log(f"\n{'=' * 60}")
        log(f"АТАКА {i}/{len(attacks)}: {name}")
        log(f"{'=' * 60}")

        try:
            attack_fn()
        except Exception as e:
            log(f"ОШИБКА: {e}")

        if i < len(attacks):
            log(f"\nПауза {pause} секунд перед следующей атакой...")
            time.sleep(pause)

    log("\n" + "=" * 60)
    log("ВСЕ АТАКИ ЗАВЕРШЕНЫ")
    log("Проверьте результаты:")
    log("  - Веб-интерфейс: http://127.0.0.1:5000")
    log("  - Алерты:        http://127.0.0.1:5000/alerts")
    log("  - Гибридный:     http://127.0.0.1:5000/hybrid")
    log("  - Результаты:    python scripts/check_results.py")
    log("=" * 60)


# =====================================================================
#  MAIN
# =====================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Симулятор атак для тестирования NDTP IDS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Доступные атаки:
  port_scan       - Сканирование портов 1-1024
  ssh_bruteforce  - SSH brute-force (порт 22)
  rdp_scan        - RDP сканирование (порт 3389)
  smb_scan        - SMB сканирование (порт 445, EternalBlue)
  conn_flood      - TCP Connection Flood
  dns_flood       - DNS UDP Flood
  slow_scan       - Медленное сканирование (1 порт / 5 сек)
  horizontal      - Горизонтальное сканирование (много хостов)
  data_exfil      - Симуляция выгрузки данных
  all             - Все атаки последовательно

Примеры:
  python scripts/attack_simulator.py --attack port_scan
  python scripts/attack_simulator.py --attack all
  python scripts/attack_simulator.py --attack ssh_bruteforce --target 192.168.1.100
        """
    )

    parser.add_argument(
        "--attack", "-a",
        required=True,
        choices=[
            'port_scan', 'ssh_bruteforce', 'rdp_scan', 'smb_scan',
            'conn_flood', 'dns_flood', 'slow_scan',
            'horizontal', 'data_exfil', 'all'
        ],
        help="Тип атаки"
    )
    parser.add_argument(
        "--target", "-t",
        default="127.0.0.1",
        help="Целевой IP (по умолчанию: 127.0.0.1)"
    )
    parser.add_argument(
        "--pause", "-p",
        type=int,
        default=30,
        help="Пауза между атаками в секундах при --attack all (по умолчанию: 30)"
    )

    args = parser.parse_args()

    attack_map = {
        'port_scan':      lambda: attack_port_scan(args.target),
        'ssh_bruteforce': lambda: attack_ssh_bruteforce(args.target),
        'rdp_scan':       lambda: attack_rdp_scan(args.target),
        'smb_scan':       lambda: attack_smb_scan(args.target),
        'conn_flood':     lambda: attack_connection_flood(args.target),
        'dns_flood':      lambda: attack_dns_flood(args.target),
        'slow_scan':      lambda: attack_slow_scan(args.target),
        'horizontal':     lambda: attack_horizontal_scan(),
        'data_exfil':     lambda: attack_data_exfiltration(args.target),
        'all':            lambda: run_all_attacks(args.target, args.pause),
    }

    print()
    print("⚠️  ВНИМАНИЕ: Все атаки направлены ТОЛЬКО на указанный IP!")
    print(f"    Цель: {args.target}")
    print(f"    Атака: {args.attack}")
    print()

    try:
        attack_map[args.attack]()
    except KeyboardInterrupt:
        log("\nПрервано пользователем.")
