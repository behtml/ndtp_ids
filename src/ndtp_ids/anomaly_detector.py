"""
Детектор аномалий
Использует статистические методы (z-score) для обнаружения аномального поведения в сети.
Поддерживает гибридный режим с ML-детектором (Isolation Forest).
"""
import sqlite3
import json
import sys
from typing import Dict, List, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import math

# Импорт ML-детектора (опциональный — работает и без scikit-learn)
try:
    from ndtp_ids.ml_detector import MLAnomalyDetector
    ML_AVAILABLE = True
except ImportError:
    try:
        from ml_detector import MLAnomalyDetector
        ML_AVAILABLE = True
    except ImportError:
        ML_AVAILABLE = False


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
    
    def __init__(self, db_path: str = "ids.db", z_threshold: float = 3.0,
                 use_ml: bool = True):
        """
        Инициализация детектора
        
        Args:
            db_path: Путь к базе данных SQLite
            z_threshold: Порог z-score для определения аномалии (обычно 2-3)
            use_ml: Использовать гибридный ML-детектор (если доступен)
        """
        self.db_path = db_path
        self.z_threshold = z_threshold
        self.ml_detector = None
        self.init_database()
        
        # Инициализация ML-детектора
        if use_ml and ML_AVAILABLE:
            try:
                self.ml_detector = MLAnomalyDetector(
                    db_path=db_path,
                    z_threshold=z_threshold
                )
                print(f"[AnomalyDetector] ML hybrid detector enabled "
                      f"(trained={self.ml_detector.is_trained})", file=sys.stderr)
            except Exception as e:
                print(f"[AnomalyDetector] ML detector failed to init: {e}", file=sys.stderr)
        elif use_ml and not ML_AVAILABLE:
            print("[AnomalyDetector] ML not available (install scikit-learn + numpy)", file=sys.stderr)
        
    def init_database(self):
        """Инициализация таблиц для профилей устройств и алертов"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Таблица для профилей устройств
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
            
            # Создаем индексы для alerts
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
            conn.close()
            print("[AnomalyDetector] Database initialized successfully", file=sys.stderr)
        except Exception as e:
            print(f"[AnomalyDetector] Error initializing database: {e}", file=sys.stderr)
    
    def calculate_statistics(self, src_ip: str, metric: str) -> Tuple[float, float, int]:
        """
        Вычисление среднего и стандартного отклонения для метрики
        
        Args:
            src_ip: IP адрес хоста
            metric: Название метрики (connections_count, unique_ports, и т.д.)
            
        Returns:
            Кортеж (mean, std, count)
        """
        # Whitelist разрешенных метрик для предотвращения SQL injection
        ALLOWED_METRICS = {
            'connections_count',
            'unique_ports',
            'unique_dst_ips',
            'total_bytes',
            'avg_packet_size'
        }
        
        if metric not in ALLOWED_METRICS:
            raise ValueError(f"Invalid metric: {metric}. Allowed: {ALLOWED_METRICS}")
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Используем новую схему с metric_name и metric_value
            cursor.execute('''
                SELECT metric_value
                FROM aggregated_metrics
                WHERE src_ip = ? AND metric_name = ?
                ORDER BY timestamp DESC
                LIMIT 50
            ''', (src_ip, metric))
            
            values = [row[0] for row in cursor.fetchall()]
        finally:
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
        
        try:
            cursor.execute('''
                INSERT INTO alerts
                (timestamp, src_ip, anomaly_type, score, severity, description,
                 metric_value, baseline_mean, baseline_std, resolved)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert.timestamp,
                alert.src_ip,
                alert.anomaly_type,
                alert.score,
                alert.severity,
                alert.description,
                alert.current_value,
                alert.mean_value,
                alert.std_value,
                0  # resolved = False по умолчанию
            ))
            
            conn.commit()
        finally:
            conn.close()
    
    def update_host_profile(self, src_ip: str):
        """
        Обновление профиля устройства (базовых статистик)
        
        Args:
            src_ip: IP адрес хоста
        """
        metrics = [
            'connections_count',
            'unique_ports',
            'unique_dst_ips',
            'total_bytes'
        ]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Обновляем профиль для каждой метрики в нормализованном формате
            for metric_name in metrics:
                mean, std, count = self.calculate_statistics(src_ip, metric_name)
            
            # Получаем min и max значения для этой метрики
            cursor.execute('''
                SELECT MIN(metric_value), MAX(metric_value)
                FROM aggregated_metrics
                WHERE src_ip = ? AND metric_name = ?
            ''', (src_ip, metric_name))
            
            row = cursor.fetchone()
            min_value = row[0] if row and row[0] is not None else 0.0
            max_value = row[1] if row and row[1] is not None else 0.0
            
            # Вставляем или обновляем профиль для этой метрики
            cursor.execute('''
                INSERT OR REPLACE INTO device_profiles
                (src_ip, metric_name, mean, std, min_value, max_value, sample_count, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                src_ip,
                metric_name,
                mean,
                std,
                min_value,
                max_value,
                count,
                datetime.now().timestamp()
            ))
        
            conn.commit()
        finally:
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
        
        try:
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
        finally:
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
        Запуск детектора для анализа последних метрик.
        Если ML-детектор доступен — также запускает гибридную детекцию.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Получаем последние окна для каждого хоста
            cursor.execute('''
                SELECT src_ip, window_start, window_end
                FROM aggregated_metrics
                GROUP BY src_ip
            ''')
            
            windows = cursor.fetchall()
            
            for src_ip, window_start, window_end in windows:
                # Получаем все метрики для этого окна
                cursor.execute('''
                SELECT metric_name, metric_value
                FROM aggregated_metrics
                WHERE src_ip = ? AND window_start = ?
            ''', (src_ip, window_start))
                
                window_data = {
                    'src_ip': src_ip,
                    'window_start': window_start,
                    'window_end': window_end
                }
                
                metrics_dict = {}
                # Заполняем данные метрик
                for metric_name, metric_value in cursor.fetchall():
                    window_data[metric_name] = metric_value
                    metrics_dict[metric_name] = metric_value
                
                # Проверяем что у нас есть необходимые метрики
                required_metrics = ['connections_count', 'unique_ports', 'unique_dst_ips', 'total_bytes']
                if not all(m in window_data for m in required_metrics):
                    continue
            
            # --- Слой 1: Z-Score (статистический анализ) ---
            alerts = self.analyze_window(window_data)
            
            for alert in alerts:
                self.save_alert(alert)
                print(f"[STAT-ALERT] {alert.severity.upper()}: {alert.description}", file=sys.stderr)
            
            # --- Слой 2: ML (Isolation Forest) гибридная детекция ---
            if self.ml_detector is not None:
                try:
                    # Пополняем обучающие данные
                    self.ml_detector.collect_training_data(src_ip, metrics_dict)
                    
                    # Запускаем ML-детекцию
                    ml_alert = self.ml_detector.detect(src_ip, metrics_dict)
                    if ml_alert:
                        self.ml_detector.save_ml_alert(ml_alert)
                        print(f"[ML-ALERT] {ml_alert.severity.upper()}: {ml_alert.description}",
                              file=sys.stderr)
                except Exception as e:
                    print(f"[AnomalyDetector] ML detection error: {e}", file=sys.stderr)
            
            # Обновляем профиль хоста
            self.update_host_profile(src_ip)
        finally:
            conn.close()
        
        # Попытка автообучения ML если ещё не обучен
        if self.ml_detector is not None and not self.ml_detector.is_trained:
            try:
                self.ml_detector.train()
            except Exception as e:
                print(f"[AnomalyDetector] ML auto-train error: {e}", file=sys.stderr)


def run_detector(db_path: str = "ids.db", z_threshold: float = 3.0, 
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
        description="Anomaly Detector — детектор аномалий сетевого трафика"
    )
    parser.add_argument(
        "--db", 
        default="ids.db",
        help="Путь к базе данных SQLite (по умолчанию: ids.db)"
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
