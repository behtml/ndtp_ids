#!/usr/bin/env python3
"""
Создание БД с ПРАВИЛЬНОЙ структурой, совместимой с adaptive_trainer.py и всеми модулями.

ВАЖНО: Используется ids.db — единый файл БД для всех компонентов.
"""
import sqlite3
import time
import sys

DB = "ids.db"

try:
    conn = sqlite3.connect(DB)
    c = conn.cursor()
except Exception as e:
    print(f"Ошибка подключения к БД: {e}")
    sys.exit(1)

print("🗄️  Создание БД с правильной структурой...")
print("=" * 60)

# ========== AGGREGATED_METRICS (нормализованная) ==========
print("📊 1/7: aggregated_metrics (нормализованная)...")
c.execute('''
    CREATE TABLE IF NOT EXISTS aggregated_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL NOT NULL,
        src_ip TEXT NOT NULL,
        metric_name TEXT NOT NULL,
        metric_value REAL NOT NULL,
        window_start REAL,
        window_end REAL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')
c.execute('CREATE INDEX IF NOT EXISTS idx_agg_timestamp ON aggregated_metrics(timestamp)')
c.execute('CREATE INDEX IF NOT EXISTS idx_agg_src_ip ON aggregated_metrics(src_ip)')
c.execute('CREATE INDEX IF NOT EXISTS idx_agg_metric ON aggregated_metrics(metric_name)')

# ========== METRICS_HISTORY (для adaptive_trainer — плоская схема) ==========
print("📊 2/7: metrics_history...")
c.execute('''
    CREATE TABLE IF NOT EXISTS metrics_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        src_ip TEXT,
        timestamp REAL,
        connections_count INTEGER,
        unique_ports INTEGER,
        unique_dst_ips INTEGER,
        total_bytes INTEGER,
        avg_packet_size REAL,
        is_anomaly INTEGER DEFAULT 0,
        FOREIGN KEY (src_ip) REFERENCES host_profiles(src_ip)
    )
''')
c.execute('CREATE INDEX IF NOT EXISTS idx_hist_timestamp ON metrics_history(timestamp)')
c.execute('CREATE INDEX IF NOT EXISTS idx_hist_src_ip ON metrics_history(src_ip)')

# ========== DEVICE_PROFILES ==========
print("👤 3/7: device_profiles...")
c.execute('''
    CREATE TABLE IF NOT EXISTS device_profiles (
        src_ip TEXT NOT NULL,
        metric_name TEXT NOT NULL,
        mean REAL DEFAULT 0.0,
        std REAL DEFAULT 0.0,
        min_value REAL,
        max_value REAL,
        sample_count INTEGER DEFAULT 0,
        last_updated REAL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (src_ip, metric_name)
    )
''')

# ========== HOST_PROFILES (плоская схема, совместимая с adaptive_trainer.py) ==========
print("👤 4/7: host_profiles...")
c.execute('''
    CREATE TABLE IF NOT EXISTS host_profiles (
        src_ip TEXT PRIMARY KEY,
        connections_mean REAL DEFAULT 0.0,
        connections_std REAL DEFAULT 0.0,
        unique_ports_mean REAL DEFAULT 0.0,
        unique_ports_std REAL DEFAULT 0.0,
        unique_dst_ips_mean REAL DEFAULT 0.0,
        unique_dst_ips_std REAL DEFAULT 0.0,
        total_bytes_mean REAL DEFAULT 0.0,
        total_bytes_std REAL DEFAULT 0.0,
        avg_packet_size_mean REAL DEFAULT 0.0,
        avg_packet_size_std REAL DEFAULT 0.0,
        samples_count INTEGER DEFAULT 0,
        last_updated REAL,
        is_learning INTEGER DEFAULT 1
    )
''')

# ========== ALERTS ==========
print("🚨 5/7: alerts...")
c.execute('''
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL NOT NULL,
        src_ip TEXT NOT NULL,
        anomaly_type TEXT NOT NULL,
        score REAL NOT NULL,
        severity TEXT NOT NULL,
        description TEXT,
        metric_value REAL,
        baseline_mean REAL,
        baseline_std REAL,
        resolved BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')
c.execute('CREATE INDEX IF NOT EXISTS idx_alert_timestamp ON alerts(timestamp)')
c.execute('CREATE INDEX IF NOT EXISTS idx_alert_src_ip ON alerts(src_ip)')
c.execute('CREATE INDEX IF NOT EXISTS idx_alert_severity ON alerts(severity)')

# ========== SYSTEM_CONFIG ==========
print("⚙️  6/7: system_config...")
c.execute('''
    CREATE TABLE IF NOT EXISTS system_config (
        key TEXT PRIMARY KEY,
        value TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')
c.execute("INSERT OR IGNORE INTO system_config VALUES ('training_day', '1', datetime('now'))")
c.execute("INSERT OR IGNORE INTO system_config VALUES ('z_threshold', '3.0', datetime('now'))")
c.execute("INSERT OR IGNORE INTO system_config VALUES ('window_minutes', '10', datetime('now'))")

# ========== TRAINING_CONFIG (совместимая с adaptive_trainer.py — 2 столбца) ==========
print("⚙️  7/7: training_config...")
c.execute('''
    CREATE TABLE IF NOT EXISTS training_config (
        key TEXT PRIMARY KEY,
        value TEXT
    )
''')
c.execute("INSERT OR IGNORE INTO training_config VALUES ('training_day', '1')")
c.execute("INSERT OR IGNORE INTO training_config VALUES ('z_threshold', '3.0')")
c.execute("INSERT OR IGNORE INTO training_config VALUES ('window_minutes', '10')")

conn.commit()

print("\n✅ БД создана с правильной структурой!")
print("\n📊 Таблицы:")
c.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
for row in c.fetchall():
    print(f"  - {row[0]}")

print("\n🔍 Структура host_profiles:")
c.execute("PRAGMA table_info(host_profiles)")
for col in c.fetchall():
    print(f"  {col[1]:<25} {col[2]}")

conn.close()
