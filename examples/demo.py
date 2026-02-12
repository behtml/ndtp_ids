#!/usr/bin/env python3
"""
Пример использования NDTP IDS
Демонстрирует работу коллектора, агрегатора и детектора аномалий
"""

import subprocess
import time
import sys
from pathlib import Path

def print_header(text):
    """Печать красивого заголовка"""
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60 + "\n")

def example_1_collector_only():
    """
    Пример 1: Запуск только коллектора пакетов
    """
    print_header("Пример 1: Коллектор пакетов")
    print("Запускаем коллектор для захвата сетевых пакетов...")
    print("Нажмите Ctrl+C для остановки")
    print()
    
    # Для примера используем интерфейс eth0 (может отличаться)
    # На Windows используйте "Ethernet" или "Wi-Fi"
    interface = "eth0"
    
    try:
        subprocess.run([
            sys.executable, "-m", "ndtp_ids.packet_collector"
        ])
    except KeyboardInterrupt:
        print("\n✓ Коллектор остановлен")

def example_2_collector_with_aggregator():
    """
    Пример 2: Коллектор + Агрегатор (через pipe)
    """
    print_header("Пример 2: Коллектор + Агрегатор")
    print("Запускаем коллектор с передачей данных в агрегатор...")
    print("События будут агрегироваться в БД ndtp_ids.db")
    print("Нажмите Ctrl+C для остановки")
    print()
    
    try:
        # Запускаем коллектор и передаем вывод в агрегатор
        collector = subprocess.Popen(
            [sys.executable, "-m", "ndtp_ids.packet_collector"],
            stdout=subprocess.PIPE,
            text=True
        )
        
        aggregator = subprocess.Popen(
            [sys.executable, "-m", "ndtp_ids.aggregator"],
            stdin=collector.stdout
        )
        
        # Ждем завершения
        aggregator.wait()
        
    except KeyboardInterrupt:
        print("\n✓ Система остановлена")
        collector.terminate()
        aggregator.terminate()

def example_3_full_system():
    """
    Пример 3: Полная система (Коллектор + Агрегатор + Детектор)
    """
    print_header("Пример 3: Полная система IDS")
    print("Запускаем полную систему обнаружения вторжений:")
    print("  1. Коллектор - захват пакетов")
    print("  2. Агрегатор - агрегация метрик")
    print("  3. Детектор - обнаружение аномалий")
    print()
    print("Нажмите Ctrl+C для остановки")
    print()
    
    try:
        # 1. Запускаем коллектор
        collector = subprocess.Popen(
            [sys.executable, "-m", "ndtp_ids.packet_collector"],
            stdout=subprocess.PIPE,
            text=True
        )
        
        # 2. Запускаем агрегатор (получает данные от коллектора)
        aggregator = subprocess.Popen(
            [sys.executable, "-m", "ndtp_ids.aggregator", "--window", "1"],
            stdin=collector.stdout
        )
        
        # 3. Запускаем детектор аномалий (работает отдельно)
        detector = subprocess.Popen(
            [sys.executable, "-m", "ndtp_ids.anomaly_detector", 
             "--interval", "30", "--threshold", "3.0"]
        )
        
        print("✓ Все компоненты запущены!")
        print()
        
        # Ждем завершения
        detector.wait()
        
    except KeyboardInterrupt:
        print("\n✓ Система остановлена")
        collector.terminate()
        aggregator.terminate()
        detector.terminate()

def example_4_view_statistics():
    """
    Пример 4: Просмотр статистики из БД
    """
    print_header("Пример 4: Просмотр статистики")
    
    import sqlite3
    
    db_path = "ndtp_ids.db"
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Проверяем наличие данных
        cursor.execute("SELECT COUNT(*) FROM aggregated_metrics")
        metrics_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM alerts")
        alerts_count = cursor.fetchone()[0]
        
        print(f"📊 Статистика базы данных {db_path}:")
        print(f"   - Агрегированных метрик: {metrics_count}")
        print(f"   - Алертов: {alerts_count}")
        print()
        
        if metrics_count > 0:
            print("📈 Последние 5 агрегированных метрик:")
            cursor.execute('''
                SELECT src_ip, connections_count, unique_ports, 
                       unique_dst_ips, total_bytes
                FROM aggregated_metrics
                ORDER BY window_start DESC
                LIMIT 5
            ''')
            
            for row in cursor.fetchall():
                print(f"   IP: {row[0]}")
                print(f"      Соединения: {row[1]}, Порты: {row[2]}, "
                      f"Назначения: {row[3]}, Байты: {row[4]}")
            print()
        
        if alerts_count > 0:
            print("🚨 Последние 5 алертов:")
            cursor.execute('''
                SELECT src_ip, severity, anomaly_type, score
                FROM alerts
                ORDER BY timestamp DESC
                LIMIT 5
            ''')
            
            for row in cursor.fetchall():
                print(f"   [{row[1].upper()}] {row[0]} - {row[2]} (score: {row[3]:.2f})")
            print()
        
        conn.close()
        
    except sqlite3.Error as e:
        print(f"❌ Ошибка при работе с БД: {e}")
        print(f"   Возможно, база данных еще не создана.")
        print(f"   Запустите сначала пример 2 или 3.")

def show_menu():
    """Показать меню с примерами"""
    print("\n" + "=" * 60)
    print("  NDTP IDS - Примеры использования")
    print("=" * 60)
    print()
    print("Выберите пример для запуска:")
    print()
    print("  1. Коллектор пакетов (только захват)")
    print("  2. Коллектор + Агрегатор (с сохранением в БД)")
    print("  3. Полная система (Коллектор + Агрегатор + Детектор)")
    print("  4. Просмотр статистики из БД")
    print("  0. Выход")
    print()

def main():
    """Главная функция"""
    
    examples = {
        '1': example_1_collector_only,
        '2': example_2_collector_with_aggregator,
        '3': example_3_full_system,
        '4': example_4_view_statistics
    }
    
    while True:
        show_menu()
        
        try:
            choice = input("Ваш выбор: ").strip()
            
            if choice == '0':
                print("\n👋 До свидания!")
                break
            
            if choice in examples:
                examples[choice]()
            else:
                print("\n❌ Неверный выбор. Попробуйте снова.")
                
        except KeyboardInterrupt:
            print("\n\n👋 До свидания!")
            break
        except Exception as e:
            print(f"\n❌ Ошибка: {e}")

if __name__ == "__main__":
    main()
