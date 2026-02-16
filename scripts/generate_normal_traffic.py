#!/usr/bin/env python3
"""
Генерация нормального трафика для обучения ML-модели

Открывает соединения к популярным сервисам — имитирует
обычную работу пользователя. Используйте когда нужно
быстро набрать training samples без ручной работы.

Запуск:
    python scripts/generate_normal_traffic.py
    python scripts/generate_normal_traffic.py --duration 30   # 30 минут
    python scripts/generate_normal_traffic.py --fast           # ускоренный режим
"""
import socket
import time
import random
import argparse
from datetime import datetime, timedelta


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


# Типичные действия пользователя
NORMAL_ACTIONS = [
    {
        "name": "HTTP/HTTPS запрос (веб-сёрфинг)",
        "targets": [
            ("93.184.216.34", 80),     # example.com
            ("93.184.216.34", 443),    # example.com HTTPS
        ],
        "count": (1, 3),
        "delay": (0.5, 2.0),
    },
    {
        "name": "DNS запрос",
        "targets": [
            ("8.8.8.8", 53),           # Google DNS
            ("1.1.1.1", 53),           # Cloudflare DNS
        ],
        "count": (1, 2),
        "delay": (0.1, 0.5),
        "proto": "udp",
    },
    {
        "name": "Локальное соединение",
        "targets": [
            ("127.0.0.1", 80),
            ("127.0.0.1", 443),
            ("127.0.0.1", 8080),
        ],
        "count": (1, 2),
        "delay": (0.2, 1.0),
    },
]


def do_tcp_connection(host: str, port: int, timeout: float = 0.5):
    """Открыть и закрыть TCP-соединение"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect_ex((host, port))
        sock.close()
        return True
    except socket.error:
        return False


def do_udp_send(host: str, port: int, data: bytes = b'\x00' * 20):
    """Отправить UDP пакет"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.2)
        sock.sendto(data, (host, port))
        sock.close()
        return True
    except socket.error:
        return False


def generate_normal_traffic(duration_minutes: int = 60, fast: bool = False):
    """
    Генерация нормального трафика

    Args:
        duration_minutes: Длительность генерации в минутах
        fast: Ускоренный режим (меньше задержек)
    """
    end_time = datetime.now() + timedelta(minutes=duration_minutes)

    log("=" * 55)
    log("ГЕНЕРАЦИЯ НОРМАЛЬНОГО ТРАФИКА")
    log(f"Длительность: {duration_minutes} мин")
    log(f"Режим: {'ускоренный' if fast else 'обычный'}")
    log(f"Завершение: {end_time.strftime('%H:%M:%S')}")
    log("=" * 55)

    total_connections = 0
    cycle = 0

    try:
        while datetime.now() < end_time:
            cycle += 1

            # Выбираем случайное действие
            action = random.choice(NORMAL_ACTIONS)
            target = random.choice(action["targets"])
            count = random.randint(*action["count"])
            delay_range = action["delay"]
            proto = action.get("proto", "tcp")

            for _ in range(count):
                if proto == "udp":
                    do_udp_send(target[0], target[1])
                else:
                    do_tcp_connection(target[0], target[1])
                total_connections += 1

                delay = random.uniform(*delay_range)
                if fast:
                    delay *= 0.2
                time.sleep(delay)

            # Пауза между действиями (имитация чтения страницы)
            if not fast:
                pause = random.uniform(3.0, 10.0)
            else:
                pause = random.uniform(0.5, 2.0)
            time.sleep(pause)

            # Логирование каждые 10 циклов
            if cycle % 10 == 0:
                remaining = (end_time - datetime.now()).total_seconds() / 60
                log(f"  Цикл {cycle}: {total_connections} соединений, "
                    f"осталось {remaining:.1f} мин")

    except KeyboardInterrupt:
        log("\nПрервано пользователем.")

    log(f"\nГенерация завершена.")
    log(f"  Всего соединений: {total_connections}")
    log(f"  Циклов: {cycle}")
    log(f"\nПроверьте прогресс: python scripts/check_progress.py")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Генерация нормального трафика для обучения ML"
    )
    parser.add_argument("--duration", "-d", type=int, default=60,
                        help="Длительность в минутах (по умолчанию: 60)")
    parser.add_argument("--fast", "-f", action="store_true",
                        help="Ускоренный режим (меньше задержек)")

    args = parser.parse_args()
    generate_normal_traffic(duration_minutes=args.duration, fast=args.fast)
