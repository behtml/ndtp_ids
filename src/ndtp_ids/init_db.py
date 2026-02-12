"""
Утилита для инициализации и проверки базы данных NDTP IDS

Этот скрипт создает все необходимые таблицы и индексы для работы системы.
Может быть запущен отдельно: python -m ndtp_ids.init_db
"""
import sqlite3
import sys
from pathlib import Path


def init_database(db_path: str = "ndtp_ids.db"):
    """
    Инициализация всех таблиц и индексов базы данных
    
    Args:
        db_path: Путь к файлу базы данных SQLite
    """
    print(f"[init_db] Initializing database: {db_path}", file=sys.stderr)
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # === Таблицы для агрегатора ===
        
        # Таблица для агрегированных метрик
        print("[init_db] Creating aggregated_metrics table...", file=sys.stderr)
        cursor.execute('''
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
        
        # Индексы для aggregated_metrics
        print("[init_db] Creating indexes for aggregated_metrics...", file=sys.stderr)
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_metrics_timestamp 
            ON aggregated_metrics(timestamp)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_metrics_src_ip 
            ON aggregated_metrics(src_ip)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_metrics_name 
            ON aggregated_metrics(metric_name)
        ''')
        
        # Таблица для необработанных событий
        print("[init_db] Creating raw_events table...", file=sys.stderr)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS raw_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                packet_size INTEGER,
                direction TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # === Таблицы для детектора аномалий ===
        
        # Таблица для профилей устройств
        print("[init_db] Creating device_profiles table...", file=sys.stderr)
        cursor.execute('''
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
        
        # Таблица для алертов
        print("[init_db] Creating alerts table...", file=sys.stderr)
        cursor.execute('''
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
        
        # Индексы для alerts
        print("[init_db] Creating indexes for alerts...", file=sys.stderr)
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp 
            ON alerts(timestamp)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_alerts_src_ip 
            ON alerts(src_ip)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_alerts_severity 
            ON alerts(severity)
        ''')
        
        conn.commit()
        
        # Выводим информацию о структуре БД
        print("\n[init_db] Database structure:", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = cursor.fetchall()
        
        for (table_name,) in tables:
            cursor.execute(f"PRAGMA table_info({table_name})")
            columns = cursor.fetchall()
            
            print(f"\nTable: {table_name}", file=sys.stderr)
            print("-" * 60, file=sys.stderr)
            for col in columns:
                col_id, col_name, col_type, not_null, default, pk = col
                pk_str = " PRIMARY KEY" if pk else ""
                not_null_str = " NOT NULL" if not_null else ""
                default_str = f" DEFAULT {default}" if default else ""
                print(f"  {col_name}: {col_type}{pk_str}{not_null_str}{default_str}", file=sys.stderr)
            
            # Показываем индексы
            cursor.execute(f"PRAGMA index_list({table_name})")
            indexes = cursor.fetchall()
            if indexes:
                print(f"  Indexes:", file=sys.stderr)
                for idx in indexes:
                    idx_name = idx[1]
                    print(f"    - {idx_name}", file=sys.stderr)
        
        print("\n" + "=" * 60, file=sys.stderr)
        print("[init_db] Database initialized successfully!", file=sys.stderr)
        
        # Статистика
        cursor.execute("SELECT COUNT(*) FROM aggregated_metrics")
        metrics_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM alerts")
        alerts_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM device_profiles")
        profiles_count = cursor.fetchone()[0]
        
        print(f"\nDatabase statistics:", file=sys.stderr)
        print(f"  Aggregated metrics: {metrics_count}", file=sys.stderr)
        print(f"  Alerts: {alerts_count}", file=sys.stderr)
        print(f"  Device profiles: {profiles_count}", file=sys.stderr)
        
        conn.close()
        
        return True
        
    except Exception as e:
        print(f"[init_db] Error initializing database: {e}", file=sys.stderr)
        return False


def main():
    """Точка входа для запуска скрипта"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Инициализация базы данных NDTP IDS"
    )
    parser.add_argument(
        "--db",
        default="ndtp_ids.db",
        help="Путь к базе данных SQLite (по умолчанию: ndtp_ids.db)"
    )
    
    args = parser.parse_args()
    
    success = init_database(args.db)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
