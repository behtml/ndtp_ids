#!/usr/bin/env python3
"""
Исправление структуры таблицы host_profiles
"""
import sqlite3
import time

DB_PATH = "ids.db"

def fix_host_profiles_table():
    """Пересоздаем host_profiles с правильной структурой"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    print("🔧 Исправление таблицы host_profiles...\n")
    
    # 1. Удаляем старую таблицу (она пустая и с неправильной структурой)
    print("❌ Удаляем старую таблицу host_profiles...")
    cursor.execute("DROP TABLE IF EXISTS host_profiles")
    print("   ✓ Удалена\n")
    
    # 2. Создаем новую с правильной структурой
    print("📝 Создаем новую таблицу host_profiles с правильной структурой...")
    cursor.execute('''
        CREATE TABLE host_profiles (
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
            is_learning BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    print("   ✓ Таблица создана\n")
    
    # 3. Проверяем структуру
    print("🔍 Проверка структуры новой таблицы:")
    cursor.execute("PRAGMA table_info(host_profiles)")
    columns = cursor.fetchall()
    for col in columns:
        print(f"   ✓ {col[1]:<25} {col[2]:<10}")
    
    # 4. Заполняем данными из aggregated_metrics (если есть)
    print("\n📊 Заполнение начальными данными из aggregated_metrics...")
    
    # Получаем уникальные IP адреса
    cursor.execute("""
        SELECT DISTINCT src_ip 
        FROM aggregated_metrics 
        WHERE src_ip IS NOT NULL
    """)
    ips = [row[0] for row in cursor.fetchall()]
    print(f"   Найдено уникальных IP: {len(ips)}")
    
    # Для каждого IP создаем начальный профиль
    for ip in ips:
        # Получаем последние метрики для этого IP
        cursor.execute("""
            SELECT 
                metric_name,
                AVG(metric_value) as avg_val,
                COUNT(*) as cnt
            FROM aggregated_metrics
            WHERE src_ip = ?
            GROUP BY metric_name
        """, (ip,))
        
        metrics = {}
        total_samples = 0
        for row in cursor.fetchall():
            metrics[row[0]] = row[1]
            total_samples = max(total_samples, row[2])
        
        # Вставляем профиль
        cursor.execute("""
            INSERT INTO host_profiles (
                src_ip,
                connections_mean, connections_std,
                unique_ports_mean, unique_ports_std,
                unique_dst_ips_mean, unique_dst_ips_std,
                total_bytes_mean, total_bytes_std,
                avg_packet_size_mean, avg_packet_size_std,
                samples_count, last_updated, is_learning
            ) VALUES (?, ?, 1.0, ?, 1.0, ?, 1.0, ?, 1.0, ?, 1.0, ?, ?, 1)
        """, (
            ip,
            metrics.get('connections_count', 0.0),
            metrics.get('unique_ports', 0.0),
            metrics.get('unique_dst_ips', 0.0),
            metrics.get('total_bytes', 0.0),
            metrics.get('avg_packet_size', 0.0),
            total_samples,
            time.time()  # last_updated — текущее время
        ))
    
    conn.commit()
    
    # 5. Финальная проверка
    print(f"\n✅ Таблица исправлена!")
    cursor.execute("SELECT COUNT(*) FROM host_profiles")
    count = cursor.fetchone()[0]
    print(f"📈 Создано профилей хостов: {count}")
    
    if count > 0:
        print("\n🔹 Примеры профилей:")
        cursor.execute("SELECT src_ip, samples_count, is_learning FROM host_profiles LIMIT 5")
        for row in cursor.fetchall():
            status = "🟡 Обучение" if row[2] else "🟢 Детекция"
            print(f"   {row[0]:<20} | Наблюдений: {row[1]:<5} | {status}")
    
    conn.close()
    
    print("\n🚀 Готово! Теперь можно запускать веб-интерфейс:")
    print("   python -m ndtp_ids.web_interface --port 5000")


if __name__ == "__main__":
    import sys
    try:
        fix_host_profiles_table()
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Ошибка: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)