#!/usr/bin/env python3
"""
Запуск всех компонентов NDTP IDS

Запускает в отдельных процессах:
1. Packet Collector + Aggregator (пайплайн)
2. Anomaly Detector (z-score + ML)
3. Hybrid Scorer (3-слойный скоринг)
4. Web Interface (Flask дашборд)

Запуск:
    python scripts/run_all.py
    python scripts/run_all.py --iface "Wi-Fi" --window 1
    python scripts/run_all.py --no-web        # без веб-интерфейса
    python scripts/run_all.py --no-collector   # без коллектора (только анализ)
"""
import os
import sys
import subprocess
import signal
import argparse
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Список запущенных процессов для корректного завершения
processes = []


def cleanup(signum=None, frame=None):
    """Остановка всех процессов"""
    print("\n[run_all] Остановка всех компонентов...")
    for name, proc in processes:
        try:
            proc.terminate()
            proc.wait(timeout=5)
            print(f"  [OK] {name} остановлен")
        except Exception:
            try:
                proc.kill()
                print(f"  [KILL] {name} принудительно убит")
            except Exception:
                pass
    print("[run_all] Все компоненты остановлены.")
    sys.exit(0)


signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)


def start_component(name: str, cmd: list, cwd: str = None) -> subprocess.Popen:
    """Запуск компонента в фоне"""
    print(f"  [START] {name}")
    print(f"          {' '.join(cmd)}")

    proc = subprocess.Popen(
        cmd,
        cwd=cwd or PROJECT_ROOT,
        stdout=subprocess.PIPE if name != "Web Interface" else None,
        stderr=subprocess.PIPE if name != "Web Interface" else None,
    )
    processes.append((name, proc))
    return proc


def main():
    parser = argparse.ArgumentParser(
        description="Запуск всех компонентов NDTP IDS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  python scripts/run_all.py                          # всё по умолчанию
  python scripts/run_all.py --iface "Wi-Fi"          # указать интерфейс
  python scripts/run_all.py --window 1               # 1-минутное окно (быстрое обучение)
  python scripts/run_all.py --no-web                 # без веб-интерфейса
  python scripts/run_all.py --no-collector            # только детекция (БД уже заполнена)
        """
    )

    parser.add_argument("--iface", "-i", default=None, help="Сетевой интерфейс")
    parser.add_argument("--window", "-w", type=int, default=1,
                        help="Окно агрегации в минутах (по умолчанию: 1)")
    parser.add_argument("--db", default="ids.db", help="Путь к БД")
    parser.add_argument("--threshold", type=float, default=3.0, help="Порог z-score")
    parser.add_argument("--interval", type=int, default=30,
                        help="Интервал детекции в секундах (по умолчанию: 30)")
    parser.add_argument("--port", type=int, default=5000, help="Порт веб-интерфейса")
    parser.add_argument("--no-web", action="store_true", help="Не запускать веб-интерфейс")
    parser.add_argument("--no-collector", action="store_true", help="Не запускать коллектор")
    parser.add_argument("--no-hybrid", action="store_true", help="Не запускать гибридный скорер")

    args = parser.parse_args()

    python = sys.executable  # Путь к текущему интерпретатору Python

    print("=" * 60)
    print("NDTP IDS — Запуск всех компонентов")
    print("=" * 60)
    print(f"  Python:    {python}")
    print(f"  БД:        {args.db}")
    print(f"  Окно:      {args.window} мин")
    print(f"  Интервал:  {args.interval} сек")
    print(f"  Порог:     {args.threshold}")
    if args.iface:
        print(f"  Интерфейс: {args.iface}")
    print()

    # 1. Packet Collector → Aggregator
    if not args.no_collector:
        collector_cmd = [python, "-m", "ndtp_ids.packet_collector"]
        if args.iface:
            collector_cmd.extend(["--iface", args.iface])

        aggregator_cmd = [python, "-m", "ndtp_ids.aggregator",
                          "--db", args.db, "--window", str(args.window)]

        # На Windows используем пайплайн через shell
        if sys.platform == "win32":
            full_cmd = f'"{python}" -m ndtp_ids.packet_collector'
            if args.iface:
                full_cmd += f' --iface "{args.iface}"'
            full_cmd += f' | "{python}" -m ndtp_ids.aggregator --db {args.db} --window {args.window}'

            print(f"  [START] Collector + Aggregator (pipeline)")
            print(f"          {full_cmd}")

            proc = subprocess.Popen(
                full_cmd,
                cwd=PROJECT_ROOT,
                shell=True,
            )
            processes.append(("Collector+Aggregator", proc))
        else:
            # На Linux/Mac — пайплайн через pipe
            print(f"  [START] Collector + Aggregator (pipeline)")
            collector_proc = subprocess.Popen(
                collector_cmd,
                cwd=PROJECT_ROOT,
                stdout=subprocess.PIPE,
            )
            aggregator_proc = subprocess.Popen(
                aggregator_cmd,
                cwd=PROJECT_ROOT,
                stdin=collector_proc.stdout,
            )
            collector_proc.stdout.close()
            processes.append(("Collector", collector_proc))
            processes.append(("Aggregator", aggregator_proc))

        time.sleep(2)  # Даём время на инициализацию

    # 2. Anomaly Detector
    detector_cmd = [python, "-m", "ndtp_ids.anomaly_detector",
                    "--db", args.db,
                    "--threshold", str(args.threshold),
                    "--interval", str(args.interval)]
    start_component("Anomaly Detector", detector_cmd)
    time.sleep(1)

    # 3. Hybrid Scorer
    if not args.no_hybrid:
        hybrid_cmd = [python, "-m", "ndtp_ids.hybrid_scorer",
                      "--db", args.db,
                      "--interval", str(args.interval)]
        start_component("Hybrid Scorer", hybrid_cmd)
        time.sleep(1)

    # 4. Web Interface
    if not args.no_web:
        web_cmd = [python, "-m", "ndtp_ids.web_interface",
                   "--host", "127.0.0.1",
                   "--port", str(args.port),
                   "--db", args.db]
        start_component("Web Interface", web_cmd)

    print()
    print("=" * 60)
    print("Все компоненты запущены!")
    print()
    if not args.no_web:
        print(f"  Дашборд:         http://127.0.0.1:{args.port}")
        print(f"  Алерты:          http://127.0.0.1:{args.port}/alerts")
        print(f"  Обучение:        http://127.0.0.1:{args.port}/training")
        print(f"  Гибридный:       http://127.0.0.1:{args.port}/hybrid")
    print()
    print("  Ctrl+C для остановки всех компонентов")
    print("=" * 60)

    # Ожидаем завершения (Ctrl+C)
    try:
        while True:
            # Проверяем что все процессы живы
            for name, proc in processes:
                if proc.poll() is not None:
                    print(f"  [!] {name} завершился с кодом {proc.returncode}")

            time.sleep(5)

    except KeyboardInterrupt:
        cleanup()


if __name__ == "__main__":
    main()
