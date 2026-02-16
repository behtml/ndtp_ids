#!/usr/bin/env python3
"""
Проверка результатов тестирования — что поймала IDS

Показывает алерты от всех трёх слоёв:
- Z-Score (статистический)
- ML (Isolation Forest)
- Suricata (сигнатурный)
И гибридные вердикты.

Запуск:
    python scripts/check_results.py
    python scripts/check_results.py --db my_ids.db
"""
import os
import sys
import sqlite3
import argparse
from collections import Counter

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def check_results(db_path: str = "ids.db"):
    """Проверка результатов тестирования"""

    if not os.path.exists(db_path):
        print(f"[!] БД не найдена: {db_path}")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    print("=" * 70)
    print("РЕЗУЛЬТАТЫ ТЕСТИРОВАНИЯ NDTP IDS")
    print("=" * 70)

    total_all_alerts = 0

    # ===== 1. Z-Score алерты =====
    print("\n--- СЛОЙ 1: Статистический анализ (Z-Score) ---")

    try:
        cursor.execute("SELECT COUNT(*) FROM alerts")
        total_stat = cursor.fetchone()[0]
        total_all_alerts += total_stat

        cursor.execute("""
            SELECT severity, COUNT(*) FROM alerts
            GROUP BY severity ORDER BY COUNT(*) DESC
        """)
        stat_by_sev = cursor.fetchall()

        cursor.execute("""
            SELECT anomaly_type, COUNT(*), AVG(score)
            FROM alerts GROUP BY anomaly_type
            ORDER BY COUNT(*) DESC
        """)
        stat_by_type = cursor.fetchall()

        print(f"  Всего алертов: {total_stat}")
        if stat_by_sev:
            print(f"  По severity:")
            for sev, cnt in stat_by_sev:
                print(f"    {sev:10s}: {cnt}")
        if stat_by_type:
            print(f"  По типу аномалии:")
            for atype, cnt, avg_score in stat_by_type:
                print(f"    {atype:25s}: {cnt:4d} алертов (avg z-score: {avg_score:.2f})")
    except Exception as e:
        print(f"  Таблица alerts: {e}")

    # ===== 2. ML алерты =====
    print("\n--- СЛОЙ 2: ML-детектор (Isolation Forest) ---")

    try:
        cursor.execute("SELECT COUNT(*) FROM ml_alerts")
        total_ml = cursor.fetchone()[0]
        total_all_alerts += total_ml

        cursor.execute("""
            SELECT severity, COUNT(*) FROM ml_alerts
            GROUP BY severity ORDER BY COUNT(*) DESC
        """)
        ml_by_sev = cursor.fetchall()

        cursor.execute("""
            SELECT AVG(ml_score), AVG(stat_score), AVG(combined_score)
            FROM ml_alerts
        """)
        avg_scores = cursor.fetchone()

        print(f"  Всего ML-алертов: {total_ml}")
        if ml_by_sev:
            print(f"  По severity:")
            for sev, cnt in ml_by_sev:
                print(f"    {sev:10s}: {cnt}")
        if avg_scores and avg_scores[0] is not None:
            print(f"  Средние скоры:")
            print(f"    ML score:       {avg_scores[0]:.4f}")
            print(f"    Stat score:     {avg_scores[1]:.4f}")
            print(f"    Combined score: {avg_scores[2]:.4f}")
    except Exception as e:
        print(f"  Таблица ml_alerts: {e}")

    # ===== 3. Suricata алерты =====
    print("\n--- СЛОЙ 3: Suricata (сигнатуры) ---")

    try:
        cursor.execute("SELECT COUNT(*) FROM suricata_alerts")
        total_sur = cursor.fetchone()[0]

        cursor.execute("""
            SELECT msg, COUNT(*), severity
            FROM suricata_alerts
            GROUP BY msg
            ORDER BY COUNT(*) DESC
            LIMIT 15
        """)
        sur_by_msg = cursor.fetchall()

        print(f"  Всего Suricata-алертов: {total_sur}")
        if sur_by_msg:
            print(f"  Топ правила:")
            for msg, cnt, sev in sur_by_msg:
                print(f"    [{sev:8s}] {msg}: {cnt}")
    except Exception as e:
        print(f"  Таблица suricata_alerts: {e}")

    # ===== 4. Гибридные вердикты =====
    print("\n--- ГИБРИДНЫЙ СКОРИНГ ---")

    total_hybrid = 0
    try:
        cursor.execute("SELECT COUNT(*) FROM hybrid_verdicts")
        total_hybrid = cursor.fetchone()[0]

        cursor.execute("""
            SELECT severity, confidence, COUNT(*)
            FROM hybrid_verdicts
            GROUP BY severity, confidence
            ORDER BY COUNT(*) DESC
        """)
        hybrid_dist = cursor.fetchall()

        cursor.execute("""
            SELECT src_ip, combined_score, suricata_score, stat_score, ml_score,
                   severity, confidence, description
            FROM hybrid_verdicts
            ORDER BY combined_score DESC
            LIMIT 10
        """)
        top_verdicts = cursor.fetchall()

        print(f"  Всего вердиктов: {total_hybrid}")
        if hybrid_dist:
            print(f"  Распределение:")
            for sev, conf, cnt in hybrid_dist:
                print(f"    {sev:10s} ({conf:6s}): {cnt}")

        if top_verdicts:
            print(f"\n  Топ-10 вердиктов (максимальный threat score):")
            for v in top_verdicts:
                print(f"    {v[0]:15s}: combined={v[1]:.3f} "
                      f"[SIG={v[2]:.2f}, STAT={v[3]:.2f}, ML={v[4]:.2f}] "
                      f"-> {v[5]} ({v[6]})")
    except Exception as e:
        print(f"  Таблица hybrid_verdicts: {e}")

    # ===== 5. Общая статистика =====
    print("\n--- ОБЩАЯ СТАТИСТИКА ---")

    try:
        cursor.execute("SELECT COUNT(*) FROM raw_events")
        total_events = cursor.fetchone()[0]
    except Exception:
        total_events = 0

    try:
        cursor.execute("SELECT COUNT(DISTINCT src_ip) FROM aggregated_metrics")
        total_hosts = cursor.fetchone()[0]
    except Exception:
        total_hosts = 0

    try:
        cursor.execute("SELECT COUNT(DISTINCT window_start) FROM aggregated_metrics")
        total_windows = cursor.fetchone()[0]
    except Exception:
        total_windows = 0

    try:
        cursor.execute("SELECT COUNT(*) FROM ml_training_data WHERE is_normal = 1")
        ml_samples = cursor.fetchone()[0]
    except Exception:
        ml_samples = 0

    print(f"  Всего событий (пакетов): {total_events}")
    print(f"  Уникальных хостов:       {total_hosts}")
    print(f"  Временных окон:           {total_windows}")
    print(f"  ML training samples:      {ml_samples}")

    # ===== Итог =====
    print("\n" + "=" * 70)
    print("ИТОГО:")

    if total_all_alerts > 0:
        print(f"  Обнаружено {total_all_alerts} аномалий")
    else:
        print(f"  Аномалий не обнаружено — убедитесь что детекторы запущены")

    if total_hybrid > 0:
        print(f"  Гибридный скорер: {total_hybrid} вердиктов")
    else:
        print(f"  Гибридный скорер не запущен или нет вердиктов")

    print("=" * 70)
    conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Проверка результатов NDTP IDS")
    parser.add_argument("--db", default="ids.db", help="Путь к БД (по умолчанию: ids.db)")
    args = parser.parse_args()

    os.chdir(PROJECT_ROOT)
    check_results(db_path=args.db)
