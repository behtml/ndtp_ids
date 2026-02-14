#!/usr/bin/env python3
"""
Создание БД с ПРАВИЛЬНОЙ нормализованной структурой
"""
import sqlite3

DB = "ndtp_ids.db"
conn = sqlite3.connect(DB)
c = conn.cursor()

print("🗄️  Создание БД с нормализованной структурой...")
print("=" * 60)

# ========== AGGREGATED_METRICS (нормализованная) ==========
print("📊 1/7: aggregated_metrics (нормализованная)...")
c.execute('''
    CREATE TABLE aggregated_metrics (
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
c.execute('CREATE INDEX idx_agg_timestamp ON aggregated_metrics(timestamp)')
c.execute('CREATE INDEX idx_agg_src_ip ON aggregated_metrics(src_ip)')
c.execute('CREATE INDEX idx_agg_metric ON aggregated_metrics(metric_name)')

# ========== METRICS_HISTORY (то же самое) ==========
print("📊 2/7: metrics_history...")
c.execute('''
    CREATE TABLE metrics_history (
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
c.execute('CREATE INDEX idx_hist_timestamp ON metrics_history(timestamp)')
c.execute('CREATE INDEX idx_hist_src_ip ON metrics_history(src_ip)')
c.execute('CREATE INDEX idx_hist_metric ON metrics_history(metric_name)')

# ========== DEVICE_PROFILES ==========
print("👤 3/7: device_profiles...")
c.execute('''
    CREATE TABLE device_profiles (
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

# ========== HOST_PROFILES ==========
print("👤 4/7: host_profiles...")
c.execute('''
    CREATE TABLE host_profiles (
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

# ========== ALERTS ==========
print("🚨 5/7: alerts...")
c.execute('''
    CREATE TABLE alerts (
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
c.execute('CREATE INDEX idx_alert_timestamp ON alerts(timestamp)')
c.execute('CREATE INDEX idx_alert_src_ip ON alerts(src_ip)')
c.execute('CREATE INDEX idx_alert_severity ON alerts(severity)')

# ========== SYSTEM_CONFIG ==========
print("⚙️  6/7: system_config...")
c.execute('''
    CREATE TABLE system_config (
        key TEXT PRIMARY KEY,
        value TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')
c.execute("INSERT INTO system_config VALUES ('training_day', '1', datetime('now'))")
c.execute("INSERT INTO system_config VALUES ('z_threshold', '3.0', datetime('now'))")
c.execute("INSERT INTO system_config VALUES ('window_minutes', '10', datetime('now'))")

# ========== TRAINING_CONFIG ==========
print("⚙️  7/7: training_config...")
c.execute('''
    CREATE TABLE training_config (
        key TEXT PRIMARY KEY,
        value TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')
c.execute("INSERT INTO training_config VALUES ('training_day', '1', datetime('now'))")
c.execute("INSERT INTO training_config VALUES ('z_threshold', '3.0', datetime('now'))")
c.execute("INSERT INTO training_config VALUES ('window_minutes', '10', datetime('now'))")

conn.commit()
conn.close()

print("\n✅ БД создана с правильной структурой!")
print("\n📊 Таблицы:")
import subprocess
subprocess.call(['sqlite3', DB, '.tables'])

print("\n🔍 Структура aggregated_metrics:")
subprocess.call(['sqlite3', DB, 'PRAGMA table_info(aggregated_metrics);'])
print()
