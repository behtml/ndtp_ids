#!/usr/bin/env python3
"""
Проверка прогресса сбора обучающих данных

Показывает:
- Сколько временных окон собрано
- Сколько хостов обнаружено
- Сколько ML training samples готово
- Последние агрегированные метрики
- Готовность к обучению ML-модели

Запуск:
    python scripts/check_progress.py
    python scripts/check_progress.py --db my_ids.db
"""
import os
import sys
import sqlite3
import argparse
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def check_progress(db_path: str = "ids.db"):
    """Проверка прогресса сбора данных"""

    if not os.path.exists(db_path):
        print(f"[!] БД не найдена: {db_path}")
        print("    Запустите систему сначала — см. scripts/run_all.py")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    print("=" * 55)
    print("ПРОГРЕСС СБОРА ДАННЫХ")
    print("=" * 55)

    # 1. Общие события
    try:
        cursor.execute("SELECT COUNT(*) FROM raw_events")
        total_events = cursor.fetchone()[0]
    except Exception:
        total_events = 0

    print(f"\n  Сырых событий (пакетов): {total_events}")

    # 2. Временные окна
    try:
        cursor.execute("SELECT COUNT(DISTINCT window_start) FROM aggregated_metrics")
        total_windows = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(DISTINCT src_ip) FROM aggregated_metrics")
        total_hosts = cursor.fetchone()[0]

        cursor.execute("""
            SELECT MIN(datetime(window_start, 'unixepoch', 'localtime')),
                   MAX(datetime(window_end, 'unixepoch', 'localtime'))
            FROM aggregated_metrics
        """)
        time_range = cursor.fetchone()
    except Exception:
        total_windows = 0
        total_hosts = 0
        time_range = (None, None)

    print(f"  Временных окон:          {total_windows}")
    print(f"  Уникальных хостов:       {total_hosts}")
    if time_range[0]:
        print(f"  Период:                  {time_range[0]} — {time_range[1]}")

    # 3. ML training data
    ml_samples = 0
    ml_min_required = 50
    try:
        cursor.execute("SELECT COUNT(*) FROM ml_training_data WHERE is_normal = 1")
        ml_samples = cursor.fetchone()[0]
    except Exception:
        pass

    print(f"\n  ML training samples:     {ml_samples} / {ml_min_required}")

    # Полоска прогресса
    pct = min(100, int(ml_samples / ml_min_required * 100))
    bar_len = 30
    filled = int(bar_len * pct / 100)
    bar = "█" * filled + "░" * (bar_len - filled)
    print(f"  Прогресс:  [{bar}] {pct}%")

    ready = ml_samples >= ml_min_required
    if ready:
        print(f"\n  ✅ ГОТОВО К ОБУЧЕНИЮ ML!")
        print(f"     Запустите: python scripts/train_model.py")
        print(f"     или через веб: http://127.0.0.1:5000/training → «Обучить»")
    else:
        remaining = ml_min_required - ml_samples
        print(f"\n  ⏳ Ещё нужно: {remaining} samples")
        print(f"     Продолжайте работу, пока пакетный коллектор захватывает трафик")

    # 4. Профили хостов
    try:
        cursor.execute("SELECT src_ip, is_learning, samples_count FROM host_profiles")
        profiles = cursor.fetchall()
        if profiles:
            print(f"\n  Профили хостов:")
            for ip, learning, samples in profiles:
                mode = "🟡 обучение" if learning else "🟢 детекция"
                print(f"    {ip:20s} {mode}  ({samples} samples)")
    except Exception:
        pass

    # 5. Последние метрики
    try:
        cursor.execute("""
            SELECT src_ip, metric_name, metric_value,
                   datetime(timestamp, 'unixepoch', 'localtime') as time
            FROM aggregated_metrics
            ORDER BY timestamp DESC
            LIMIT 10
        """)
        recent = cursor.fetchall()
        if recent:
            print(f"\n  Последние метрики:")
            for row in recent:
                print(f"    {row[3]} | {row[0]:15s} | {row[1]:20s} = {row[2]:.1f}")
    except Exception:
        pass

    # 6. Алерты
    try:
        cursor.execute("SELECT COUNT(*) FROM alerts")
        total_alerts = cursor.fetchone()[0]
        print(f"\n  Всего алертов (z-score): {total_alerts}")
    except Exception:
        pass

    try:
        cursor.execute("SELECT COUNT(*) FROM ml_alerts")
        ml_alerts = cursor.fetchone()[0]
        print(f"  Всего алертов (ML):      {ml_alerts}")
    except Exception:
        pass

    print("=" * 55)
    conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Проверка прогресса сбора данных NDTP IDS")
    parser.add_argument("--db", default="ids.db", help="Путь к БД (по умолчанию: ids.db)")
    args = parser.parse_args()

    os.chdir(PROJECT_ROOT)
    check_progress(db_path=args.db)
