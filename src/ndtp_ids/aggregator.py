"""
Агрегатор метрик для NDTP IDS
Группирует события из коллектора пакетов по временным окнам и вычисляет метрики
"""
import json
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List


class MetricsAggregator:
    """
    Агрегатор метрик сетевого трафика
    
    Собирает события из коллектора и вычисляет:
    - Количество соединений (connections_count)
    - Уникальные порты (unique_ports)
    - Уникальные IP назначения (unique_dst_ips)
    - Общий объем данных (total_bytes)
    - Средний размер пакета (avg_packet_size)
    """
    
    def __init__(self, db_path: str = "ndtp_ids.db", window_minutes: int = 10):
        """
        Инициализация агрегатора
        
        Args:
            db_path: Путь к базе данных SQLite
            window_minutes: Размер временного окна в минутах
        """
        self.db_path = db_path
        self.window_seconds = window_minutes * 60
        self.current_window: Dict = {}
        self.init_database()
        
    def init_database(self):
        """Инициализация базы данных"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Таблица для агрегированных метрик
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS aggregated_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                window_start REAL NOT NULL,
                window_end REAL NOT NULL,
                src_ip TEXT NOT NULL,
                connections_count INTEGER,
                unique_ports INTEGER,
                unique_dst_ips INTEGER,
                total_bytes INTEGER,
                avg_packet_size REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Таблица для хранения необработанных событий
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
        
        conn.commit()
        conn.close()
        
    def get_window_key(self, timestamp: float) -> float:
        """
        Определяет начало временного окна для заданного timestamp
        
        Args:
            timestamp: Unix timestamp
            
        Returns:
            Начало временного окна (Unix timestamp)
        """
        return (int(timestamp) // self.window_seconds) * self.window_seconds
    
    def process_event(self, event: Dict):
        """
        Обработка одного события
        
        Args:
            event: Словарь с данными события из коллектора
        """
        # Сохраняем сырое событие в БД
        self._store_raw_event(event)
        
        # Группировка по временным окнам и IP источника
        window_start = self.get_window_key(event['timestamp'])
        src_ip = event['src_ip']
        
        key = (window_start, src_ip)
        
        if key not in self.current_window:
            self.current_window[key] = {
                'window_start': window_start,
                'window_end': window_start + self.window_seconds,
                'src_ip': src_ip,
                'connections': 0,
                'ports': set(),
                'dst_ips': set(),
                'total_bytes': 0,
                'packet_count': 0
            }
        
        window_data = self.current_window[key]
        window_data['connections'] += 1
        
        if event.get('dst_port'):
            window_data['ports'].add(event['dst_port'])
        
        window_data['dst_ips'].add(event['dst_ip'])
        window_data['total_bytes'] += event['packet_size']
        window_data['packet_count'] += 1
        
        # Проверяем, не закончилось ли окно
        current_time = event['timestamp']
        self._flush_old_windows(current_time)
    
    def _store_raw_event(self, event: Dict):
        """Сохранение сырого события в БД"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO raw_events 
            (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size, direction)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event['timestamp'],
            event['src_ip'],
            event['dst_ip'],
            event.get('src_port'),
            event.get('dst_port'),
            event['protocol'],
            event['packet_size'],
            event['direction']
        ))
        
        conn.commit()
        conn.close()
    
    def _flush_old_windows(self, current_time: float):
        """
        Сохранение завершенных временных окон в БД
        
        Args:
            current_time: Текущий timestamp
        """
        windows_to_flush = []
        
        for key, window_data in self.current_window.items():
            window_start, src_ip = key
            
            # Если окно завершено (прошло больше времени, чем размер окна)
            if current_time - window_start >= self.window_seconds:
                windows_to_flush.append(key)
        
        # Сохраняем завершенные окна
        for key in windows_to_flush:
            self._save_window(self.current_window[key])
            del self.current_window[key]
    
    def _save_window(self, window_data: Dict):
        """Сохранение агрегированных метрик окна в БД"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        avg_packet_size = (
            window_data['total_bytes'] / window_data['packet_count']
            if window_data['packet_count'] > 0 else 0
        )
        
        cursor.execute('''
            INSERT INTO aggregated_metrics
            (window_start, window_end, src_ip, connections_count, unique_ports, 
             unique_dst_ips, total_bytes, avg_packet_size)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            window_data['window_start'],
            window_data['window_end'],
            window_data['src_ip'],
            window_data['connections'],
            len(window_data['ports']),
            len(window_data['dst_ips']),
            window_data['total_bytes'],
            avg_packet_size
        ))
        
        conn.commit()
        conn.close()
        
        print(f"[Aggregator] Saved metrics for {window_data['src_ip']}: "
              f"{window_data['connections']} connections, "
              f"{len(window_data['ports'])} unique ports, "
              f"{len(window_data['dst_ips'])} unique destinations")
    
    def flush_all(self):
        """Принудительное сохранение всех текущих окон"""
        for window_data in self.current_window.values():
            self._save_window(window_data)
        self.current_window.clear()
    
    def get_metrics(self, src_ip: str = None, limit: int = 100) -> List[Dict]:
        """
        Получение агрегированных метрик из БД
        
        Args:
            src_ip: Фильтр по IP источника (опционально)
            limit: Максимальное количество записей
            
        Returns:
            Список метрик
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if src_ip:
            cursor.execute('''
                SELECT window_start, window_end, src_ip, connections_count,
                       unique_ports, unique_dst_ips, total_bytes, avg_packet_size
                FROM aggregated_metrics
                WHERE src_ip = ?
                ORDER BY window_start DESC
                LIMIT ?
            ''', (src_ip, limit))
        else:
            cursor.execute('''
                SELECT window_start, window_end, src_ip, connections_count,
                       unique_ports, unique_dst_ips, total_bytes, avg_packet_size
                FROM aggregated_metrics
                ORDER BY window_start DESC
                LIMIT ?
            ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        metrics = []
        for row in rows:
            metrics.append({
                'window_start': row[0],
                'window_end': row[1],
                'src_ip': row[2],
                'connections_count': row[3],
                'unique_ports': row[4],
                'unique_dst_ips': row[5],
                'total_bytes': row[6],
                'avg_packet_size': row[7]
            })
        
        return metrics


def run_aggregator(input_stream=sys.stdin, db_path: str = "ndtp_ids.db", 
                   window_minutes: int = 10):
    """
    Запуск агрегатора с чтением событий из потока ввода
    
    Args:
        input_stream: Поток ввода (по умолчанию stdin)
        db_path: Путь к базе данных
        window_minutes: Размер временного окна в минутах
    """
    aggregator = MetricsAggregator(db_path=db_path, window_minutes=window_minutes)
    
    print(f"[Aggregator] Started with window size: {window_minutes} minutes")
    print(f"[Aggregator] Database: {db_path}")
    print("[Aggregator] Waiting for events from collector...")
    
    try:
        for line in input_stream:
            line = line.strip()
            if not line:
                continue
            
            # Пропускаем служебные сообщения коллектора
            if line.startswith('['):
                continue
                
            try:
                event = json.loads(line)
                aggregator.process_event(event)
            except json.JSONDecodeError as e:
                print(f"[Aggregator] Warning: Failed to parse JSON: {e}", file=sys.stderr)
                continue
                
    except KeyboardInterrupt:
        print("\n[Aggregator] Shutting down...")
        aggregator.flush_all()
        print("[Aggregator] All metrics saved.")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="NDTP IDS Aggregator - агрегация метрик сетевого трафика"
    )
    parser.add_argument(
        "--db", 
        default="ndtp_ids.db",
        help="Путь к базе данных SQLite (по умолчанию: ndtp_ids.db)"
    )
    parser.add_argument(
        "--window",
        type=int,
        default=10,
        help="Размер временного окна в минутах (по умолчанию: 10)"
    )
    
    args = parser.parse_args()
    
    run_aggregator(db_path=args.db, window_minutes=args.window)
