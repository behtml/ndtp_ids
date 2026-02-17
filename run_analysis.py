#!/usr/bin/env python3
"""Полный анализ с обученной моделью"""
from ndtp_ids.ml_detector import MLAnomalyDetector
from ndtp_ids.anomaly_detector import AnomalyDetector
from ndtp_ids.hybrid_scorer import HybridScorer

DB_PATH = "ids.db"

print("=" * 70)
print("NDTP IDS - Анализ с обученной ML-моделью")
print("=" * 70)

# ========== ML-детекция ==========
print("\n[1] ML Detector - Запуск детекции...")
ml_detector = MLAnomalyDetector(db_path=DB_PATH, z_threshold=3.0)
ml_detector.run_detection()

ml_stats = ml_detector.get_ml_alerts_stats()
ml_alerts = ml_detector.get_recent_ml_alerts(limit=15)

print(f"\n📊 ML Результаты:")
print(f"  • Всего алертов: {ml_stats['total']}")
print(f"  • За последний час: {ml_stats['last_hour']}")
print(f"  • По severity: {ml_stats['by_severity']}")
print(f"  • Средний combined_score: {ml_stats['avg_combined_score']:.4f}")

if ml_alerts:
    print(f"\n🔥 Топ-15 ML алертов:")
    for i, a in enumerate(ml_alerts, 1):
        print(f"{i:2}. [{a['severity']:8}] {a['src_ip']:15} | "
              f"combined={a['combined_score']:.3f} "
              f"(ML={a['ml_score']:.3f}, STAT={a['stat_score']:.3f})")
        # Показываем топ-3 аномальных признака
        if a.get('top_features'):
            for feat in a['top_features'][:3]:
                print(f"    ↳ {feat['feature']:20}: current={feat['current']:.1f}, "
                      f"mean={feat['mean']:.1f}, z={feat['z_score']:.2f}")

# ========== Z-Score детекция ==========
print(f"\n[2] Z-Score Detector - Запуск статистического анализа...")
anomaly_detector = AnomalyDetector(db_path=DB_PATH, z_threshold=3.0, use_ml=False)
anomaly_detector.run_detection()

stat_alerts = anomaly_detector.get_recent_alerts(limit=15)
print(f"\n📊 Z-Score Результаты:")
print(f"  • Всего алертов: {len(stat_alerts)}")

if stat_alerts:
    print(f"\n⚠️  Топ-15 статистических алертов:")
    for i, a in enumerate(stat_alerts, 1):
        print(f"{i:2}. [{a['severity']:8}] {a['src_ip']:15} | "
              f"z-score={a['score']:.2f} | {a['anomaly_type']}")

# ========== Гибридный анализ ==========
print(f"\n[3] Hybrid Scorer - Запуск гибридного скоринга (3 слоя)...")
scorer = HybridScorer(db_path=DB_PATH, w_sig=0.40, w_stat=0.25, w_ml=0.35)

# Проверяем статус слоёв
layers = scorer.get_layer_status()
print(f"\n🔧 Статус слоёв:")
for name, info in layers.items():
    status = "✓" if info['active'] else "✗"
    print(f"  {status} {name:10} (вес={info['weight']:.2f})")

scorer.run_scoring_cycle()

hybrid_stats = scorer.get_hybrid_stats()
verdicts = scorer.get_recent_verdicts(limit=15)

print(f"\n📊 Гибридные результаты:")
print(f"  • Всего вердиктов: {hybrid_stats['total_verdicts']}")
print(f"  • За последний час: {hybrid_stats['last_hour']}")
print(f"  • По severity: {hybrid_stats['by_severity']}")
print(f"  • По confidence: {hybrid_stats['by_confidence']}")
print(f"  • Средние скоры:")
for score_type, value in hybrid_stats['avg_scores'].items():
    print(f"    - {score_type:10}: {value:.4f}")

if verdicts:
    print(f"\n🎯 Топ-15 гибридных вердиктов:")
    for i, v in enumerate(verdicts, 1):
        print(f"{i:2}. [{v['severity']:8}] ({v['confidence']:6}) {v['src_ip']:15}")
        print(f"    ↳ Combined={v['combined_score']:.3f} "
              f"[SIG={v['suricata_score']:.2f}, "
              f"STAT={v['stat_score']:.2f}, "
              f"ML={v['ml_score']:.2f}]")

# ========== Сводка ==========
print("\n" + "=" * 70)
print("✓ Анализ завершён!")
print("=" * 70)

# Топ-10 самых опасных хостов
import sqlite3
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

cursor.execute("""
    SELECT src_ip, 
           AVG(combined_score) as avg_score,
           MAX(combined_score) as max_score,
           COUNT(*) as verdict_count,
           MAX(severity) as max_severity
    FROM hybrid_verdicts
    GROUP BY src_ip
    ORDER BY avg_score DESC
    LIMIT 10
""")

print("\n🚨 Топ-10 самых подозрительных хостов:")
print(f"{'Ранг':<5} {'IP':^15} {'Avg Score':>10} {'Max Score':>10} {'Вердикты':>10} {'Max Severity':>12}")
print("-" * 70)
for i, row in enumerate(cursor.fetchall(), 1):
    print(f"{i:<5} {row[0]:^15} {row[1]:>10.3f} {row[2]:>10.3f} {row[3]:>10} {row[4]:>12}")

conn.close()

print(f"\n💡 Для визуализации запустите веб-интерфейс:")
print(f"   python -m ndtp_ids.web_interface --host 127.0.0.1 --port 5000")
print(f"\n📁 Результаты сохранены в базе: {DB_PATH}")