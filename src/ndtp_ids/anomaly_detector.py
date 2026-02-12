"""
Детектор аномалий для NDTP IDS
Использует статистические методы (z-score) для обнаружения аномального поведения в сети
"""
import sqlite3
import json
import sys
from typing import Dict, List, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import math


@dataclass
class Alert:
    """Класс для представления алерта"""
    timestamp: float
    src_ip: str
    anomaly_type: str
    score: float
    current_value: float
    mean_value: float
    std_value: float
    threshold: float
    severity: str  # low, medium, high, critical
    description: str


class AnomalyDetector:
    """
    Детектор аномалий на основе z-score метода
    
    Вычисляет статистические метрики (среднее, стандартное отклонение)
    для каждого хоста и детектирует аномалии при значительных отклонениях.
    """
    
    def __init__(self, db_path: str = "ndtp_ids.db", z_threshold: float = 3.0):
        """
        Инициализация детектора
        
        Args:
            db_path: Путь к базе данных SQLite
            z_threshold: Порог z-score для определения аномалии (обычно 2-3)
        """
        self.db_path = db_path
        self.z_threshold = z_threshold
        self.init_database()
        
    def init_database(self):
        """Инициализация таблицы для алертов"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                src_ip TEXT NOT NULL,
                anomaly_type TEXT NOT NULL,
                score REAL NOT NULL,
                current_value REAL,
                mean_value REAL,
                std_value REAL,
                threshold REAL,
                severity TEXT,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Таблица для базовых профилей хостов
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS host_profiles (
                src_ip TEXT PRIMARY KEY,
                connections_mean REAL,
                connections_std REAL,
                unique_ports_mean REAL,
                unique_ports_std REAL,
                unique_dst_ips_mean REAL,
                unique_dst_ips_std REAL,
                total_bytes_mean REAL,
                total_bytes_std REAL,
                sample_count INTEGER,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def calculate_statistics(self, src_ip: str, metric: str) -> Tuple[float, float, int]:
        """
        Вычисление среднего и стандартного отклонения для метрики
        
        Args:
            src_ip: IP адрес хоста
            metric: Название метрики (connections_count, unique_ports, и т.д.)
            
        Returns:
            Кортеж (mean, std, count)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(f'''
            SELECT {metric}
            FROM aggregated_metrics
            WHERE src_ip = ?
            ORDER BY window_start DESC
            LIMIT 50
        ''', (src_ip,))
        
        values = [row[0] for row in cursor.fetchall()]
        conn.close()
        
        if len(values) < 2:
            return 0.0, 0.0, len(values)
        
        # Вычисляем среднее
        mean = sum(values) / len(values)
        
        # Вычисляем стандартное отклонение
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        std = math.sqrt(variance)
        
        return mean, std, len(values)
    
    def calculate_z_score(self, current_value: float, mean: float, std: float) -> float:
        """
        Вычисление z-score для значения
        
        Args:
            current_value: Текущее значение
            mean: Среднее значение
            std: Стандартное отклонение
            
        Returns:
            Z-score (количество стандартных отклонений от среднего)
        """
        if std == 0:
            return 0.0
        return abs((current_value - mean) / std)
    
    def get_severity(self, z_score: float) -> str:
        """
        Определение уровня серьезности на основе z-score
        
        Args:
            z_score: Значение z-score
            
        Returns:
            Уровень серьезности: low, medium, high, critical
        """
        if z_score >= 5.0:
            return "critical"
        elif z_score >= 4.0:
            return "high"
        elif z_score >= 3.0:
            return "medium"
        else:
            return "low"
    
    def check_metric(self, src_ip: str, metric_name: str, 
                     current_value: float, metric_display_name: str) -> Alert | None:
        """
        Проверка метрики на аномалии
        
        Args:
            src_ip: IP адрес хоста
            metric_name: Название метрики в БД
            current_value: Текущее значение метрики
            metric_display_name: Отображаемое название метрики
            
        Returns:
            Alert если обнаружена аномалия, иначе None
        """
        mean, std, count = self.calculate_statistics(src_ip, metric_name)
        
        # Нужно минимум несколько наблюдений для статистики
        if count < 3:
            return None
        
        z_score = self.calculate_z_score(current_value, mean, std)
        
        # Если z-score превышает порог - это аномалия
        if z_score >= self.z_threshold:
            severity = self.get_severity(z_score)
            
            description = (
                f"Аномальное значение {metric_display_name} для {src_ip}: "
                f"текущее={current_value:.1f}, среднее={mean:.1f}, "
                f"отклонение={std:.1f}, z-score={z_score:.2f}"
            )
            
            alert = Alert(
                timestamp=datetime.now().timestamp(),
                src_ip=src_ip,
                anomaly_type=metric_name,
                score=z_score,
                current_value=current_value,
                mean_value=mean,
                std_value=std,
                threshold=self.z_threshold,
                severity=severity,
                description=description
            )
            
            return alert
        
        return None
    
    def analyze_window(self, window_data: Dict) -> List[Alert]:
        """
        Анализ временного окна на аномалии
        
        Args:
            window_data: Данные временного окна с метриками
            
        Returns:
            Список обнаруженных алертов
        """
        alerts = []
        src_ip = window_data['src_ip']
        
        # Проверяем различные метрики
        metrics_to_check = [
            ('connections_count', window_data['connections_count'], 'количество соединений'),
            ('unique_ports', window_data['unique_ports'], 'количество уникальных портов'),
            ('unique_dst_ips', window_data['unique_dst_ips'], 'количество уникальных IP назначения'),
            ('total_bytes', window_data['total_bytes'], 'объем данных (байты)')
        ]
        
        for metric_name, current_value, display_name in metrics_to_check:
            alert = self.check_metric(src_ip, metric_name, current_value, display_name)
            if alert:
                alerts.append(alert)
        
        return alerts
    
    def save_alert(self, alert: Alert):
        """Сохранение алерта в БД"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO alerts
            (timestamp, src_ip, anomaly_type, score, current_value, mean_value,
             std_value, threshold, severity, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert.timestamp,
            alert.src_ip,
            alert.anomaly_type,
            alert.score,
            alert.current_value,
            alert.mean_value,
            alert.std_value,
            alert.threshold,
            alert.severity,
            alert.description
        ))
        
        conn.commit()
        conn.close()
    
    def update_host_profile(self, src_ip: str):
        """
        Обновление профиля хоста (базовых статистик)
        
        Args:
            src_ip: IP адрес хоста
        """
        metrics = [
            'connections_count',
            'unique_ports',
            'unique_dst_ips',
            'total_bytes'
        ]
        
        profile = {'src_ip': src_ip, 'sample_count': 0}
        
        for metric in metrics:
            mean, std, count = self.calculate_statistics(src_ip, metric)
            profile[f'{metric}_mean'] = mean
            profile[f'{metric}_std'] = std
            profile['sample_count'] = count
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO host_profiles
            (src_ip, connections_mean, connections_std, unique_ports_mean, unique_ports_std,
             unique_dst_ips_mean, unique_dst_ips_std, total_bytes_mean, total_bytes_std,
             sample_count, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (
            profile['src_ip'],
            profile['connections_count_mean'],
            profile['connections_count_std'],
            profile['unique_ports_mean'],
            profile['unique_ports_std'],
            profile['unique_dst_ips_mean'],
            profile['unique_dst_ips_std'],
            profile['total_bytes_mean'],
            profile['total_bytes_std'],
            profile['sample_count']
        ))
        
        conn.commit()
        conn.close()
    
    def get_recent_alerts(self, limit: int = 50, severity: str = None) -> List[Dict]:
        """
        Получение последних алертов
        
        Args:
            limit: Максимальное количество алертов
            severity: Фильтр по уровню серьезности (опционально)
            
        Returns:
            Список алертов
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if severity:
            cursor.execute('''
                SELECT timestamp, src_ip, anomaly_type, score, severity, description
                FROM alerts
                WHERE severity = ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (severity, limit))
        else:
            cursor.execute('''
                SELECT timestamp, src_ip, anomaly_type, score, severity, description
                FROM alerts
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        alerts = []
        for row in rows:
            alerts.append({
                'timestamp': row[0],
                'src_ip': row[1],
                'anomaly_type': row[2],
                'score': row[3],
                'severity': row[4],
                'description': row[5]
            })
        
        return alerts
    
    def run_detection(self):
        """
        Запуск детектора для анализа последних метрик
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Получаем последние метрики для каждого хоста
        cursor.execute('''
            SELECT DISTINCT src_ip
            FROM aggregated_metrics
        ''')
        
        hosts = [row[0] for row in cursor.fetchall()]
        
        for src_ip in hosts:
            # Получаем последнюю метрику для хоста
            cursor.execute('''
                SELECT window_start, window_end, connections_count, unique_ports,
                       unique_dst_ips, total_bytes, avg_packet_size
                FROM aggregated_metrics
                WHERE src_ip = ?
                ORDER BY window_start DESC
                LIMIT 1
            ''', (src_ip,))
            
            row = cursor.fetchone()
            if not row:
                continue
            
            window_data = {
                'src_ip': src_ip,
                'window_start': row[0],
                'window_end': row[1],
                'connections_count': row[2],
                'unique_ports': row[3],
                'unique_dst_ips': row[4],
                'total_bytes': row[5],
                'avg_packet_size': row[6]
            }
            
            # Анализируем на аномалии
            alerts = self.analyze_window(window_data)
            
            for alert in alerts:
                self.save_alert(alert)
                print(f"[ALERT] {alert.severity.upper()}: {alert.description}")
            
            # Обновляем профиль хоста
            self.update_host_profile(src_ip)
        
        conn.close()


def run_detector(db_path: str = "ndtp_ids.db", z_threshold: float = 3.0, 
                 interval_seconds: int = 60):
    """
    Запуск детектора аномалий с периодическими проверками
    
    Args:
        db_path: Путь к базе данных
        z_threshold: Порог z-score
        interval_seconds: Интервал между проверками (секунды)
    """
    import time
    
    detector = AnomalyDetector(db_path=db_path, z_threshold=z_threshold)
    
    print(f"[Detector] Started with z-score threshold: {z_threshold}")
    print(f"[Detector] Database: {db_path}")
    print(f"[Detector] Check interval: {interval_seconds} seconds")
    print("[Detector] Running anomaly detection...")
    
    try:
        while True:
            detector.run_detection()
            time.sleep(interval_seconds)
    except KeyboardInterrupt:
        print("\n[Detector] Shutting down...")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="NDTP IDS Anomaly Detector - детектор аномалий сетевого трафика"
    )
    parser.add_argument(
        "--db", 
        default="ndtp_ids.db",
        help="Путь к базе данных SQLite (по умолчанию: ndtp_ids.db)"
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=3.0,
        help="Порог z-score для детекции аномалий (по умолчанию: 3.0)"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Интервал между проверками в секундах (по умолчанию: 60)"
    )
    
    args = parser.parse_args()
    
    run_detector(db_path=args.db, z_threshold=args.threshold, 
                interval_seconds=args.interval)
