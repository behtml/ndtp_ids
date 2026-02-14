"""
Модуль для адаптивного обучения и профилирования хостов
Реализует режим обучения с EWMA и скользящими окнами
"""
import sqlite3
import time
import math
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
import json
import logging

logger = logging.getLogger(__name__)


@dataclass
class HostProfile:
    """Профиль хоста с адаптивными метриками"""
    src_ip: str
    connections_mean: float
    connections_std: float
    unique_ports_mean: float
    unique_ports_std: float
    unique_dst_ips_mean: float
    unique_dst_ips_std: float
    total_bytes_mean: float
    total_bytes_std: float
    avg_packet_size_mean: float
    avg_packet_size_std: float
    samples_count: int
    last_updated: float
    is_learning: bool  # Находится ли в режиме обучения
    

class AdaptiveTrainer:
    """
    Адаптивный тренер для системы обнаружения аномалий
    
    Реализует:
    - Режим обучения (learning mode) для создания baseline
    - Экспоненциальное сглаживание (EWMA) для адаптации
    - Скользящее окно для учета изменений во времени
    - Защиту от обучения на аномалиях
    """
    
    def __init__(
        self,
        db_path: str = "ids.db",
        learning_window: int = 100,  # Количество наблюдений для обучения
        ewma_alpha: float = 0.1,  # Коэффициент сглаживания (0.05-0.2)
        sliding_window_size: int = 50,  # Размер скользящего окна
        min_std_deviation: float = 0.01,  # Минимальное значение std для избежания деления на 0
    ):
        """
        Инициализация тренера
        
        Args:
            db_path: Путь к базе данных
            learning_window: Количество наблюдений для начального обучения
            ewma_alpha: Коэффициент для экспоненциального сглаживания
            sliding_window_size: Размер скользящего окна для пересчета baseline
            min_std_deviation: Минимальное стандартное отклонение
        """
        self.db_path = db_path
        self.learning_window = learning_window
        self.ewma_alpha = ewma_alpha
        self.sliding_window_size = sliding_window_size
        self.min_std_deviation = min_std_deviation
        self.init_database()
        
    def init_database(self):
        """Инициализация таблиц для профилей хостов"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Таблица для профилей хостов
        # Добавляем дополнительные поля для адаптивного обучения
        cursor.execute("""
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
                avg_packet_size_mean REAL,
                avg_packet_size_std REAL,
                samples_count INTEGER,
                last_updated REAL,
                is_learning INTEGER DEFAULT 1
            )
        """)
        
        # Таблица для истории метрик (скользящее окно)
        cursor.execute("""
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
        """)
        
        # Таблица для конфигурации режима обучения
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS training_config (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        
        conn.commit()
        conn.close()
        
    def set_learning_mode(self, src_ip: str, enabled: bool):
        """
        Установить режим обучения для хоста
        
        Args:
            src_ip: IP адрес хоста
            enabled: True - режим обучения, False - режим детекции
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "UPDATE host_profiles SET is_learning = ? WHERE src_ip = ?",
            (1 if enabled else 0, src_ip)
        )
        
        conn.commit()
        conn.close()
        
        logger.info(f"Хост {src_ip}: режим {'обучения' if enabled else 'детекции'}")
        
    def is_in_learning_mode(self, src_ip: str) -> bool:
        """Проверка режима обучения для хоста"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT is_learning FROM host_profiles WHERE src_ip = ?",
            (src_ip,)
        )
        
        result = cursor.fetchone()
        conn.close()
        
        if result is None:
            return True  # Новый хост - в режиме обучения по умолчанию
            
        return bool(result[0])
        
    def add_metrics_sample(
        self,
        src_ip: str,
        metrics: Dict,
        is_anomaly: bool = False
    ) -> bool:
        """
        Добавление нового наблюдения метрик
        
        Args:
            src_ip: IP адрес хоста
            metrics: Словарь с метриками
            is_anomaly: Является ли это наблюдение аномалией
            
        Returns:
            True если обновление профиля выполнено, False если аномалия пропущена
        """
        # Защита от обучения на аномалиях
        if is_anomaly and not self.is_in_learning_mode(src_ip):
            logger.warning(f"Пропуск аномального наблюдения для {src_ip}")
            return False
            
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Добавляем в историю
        cursor.execute("""
            INSERT INTO metrics_history 
            (src_ip, timestamp, connections_count, unique_ports, unique_dst_ips, 
             total_bytes, avg_packet_size, is_anomaly)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            src_ip,
            time.time(),
            metrics.get('connections_count', 0),
            metrics.get('unique_ports', 0),
            metrics.get('unique_dst_ips', 0),
            metrics.get('total_bytes', 0),
            metrics.get('avg_packet_size', 0),
            1 if is_anomaly else 0
        ))
        
        conn.commit()
        conn.close()
        
        # Обновляем профиль хоста
        self._update_host_profile(src_ip)
        
        return True
        
    def _update_host_profile(self, src_ip: str):
        """
        Обновление профиля хоста на основе скользящего окна
        
        Args:
            src_ip: IP адрес хоста
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Получаем последние N наблюдений (не аномальных)
        cursor.execute("""
            SELECT 
                connections_count, unique_ports, unique_dst_ips,
                total_bytes, avg_packet_size
            FROM metrics_history
            WHERE src_ip = ? AND is_anomaly = 0
            ORDER BY timestamp DESC
            LIMIT ?
        """, (src_ip, self.sliding_window_size))
        
        samples = cursor.fetchall()
        
        if not samples:
            conn.close()
            return
            
        # Получаем текущий профиль
        cursor.execute(
            "SELECT * FROM host_profiles WHERE src_ip = ?",
            (src_ip,)
        )
        current_profile = cursor.fetchone()
        
        # Вычисляем статистики
        samples_count = len(samples)
        
        # Транспонируем данные
        conn_vals = [s[0] for s in samples]
        port_vals = [s[1] for s in samples]
        dst_ip_vals = [s[2] for s in samples]
        bytes_vals = [s[3] for s in samples]
        pkt_size_vals = [s[4] for s in samples]
        
        # Вычисляем среднее и стандартное отклонение
        def calc_stats(values):
            if not values:
                return 0.0, self.min_std_deviation
            mean = sum(values) / len(values)
            variance = sum((x - mean) ** 2 for x in values) / len(values)
            std = math.sqrt(variance) if variance > 0 else self.min_std_deviation
            return mean, std
            
        conn_mean, conn_std = calc_stats(conn_vals)
        port_mean, port_std = calc_stats(port_vals)
        dst_mean, dst_std = calc_stats(dst_ip_vals)
        bytes_mean, bytes_std = calc_stats(bytes_vals)
        pkt_mean, pkt_std = calc_stats(pkt_size_vals)
        
        # Применяем EWMA если уже есть профиль
        if current_profile and not self.is_in_learning_mode(src_ip):
            alpha = self.ewma_alpha
            
            conn_mean = alpha * conn_mean + (1 - alpha) * current_profile[1]
            conn_std = alpha * conn_std + (1 - alpha) * current_profile[2]
            port_mean = alpha * port_mean + (1 - alpha) * current_profile[3]
            port_std = alpha * port_std + (1 - alpha) * current_profile[4]
            dst_mean = alpha * dst_mean + (1 - alpha) * current_profile[5]
            dst_std = alpha * dst_std + (1 - alpha) * current_profile[6]
            bytes_mean = alpha * bytes_mean + (1 - alpha) * current_profile[7]
            bytes_std = alpha * bytes_std + (1 - alpha) * current_profile[8]
            pkt_mean = alpha * pkt_mean + (1 - alpha) * current_profile[9]
            pkt_std = alpha * pkt_std + (1 - alpha) * current_profile[10]
            
        # Проверяем, достаточно ли наблюдений для выхода из режима обучения
        is_learning = samples_count < self.learning_window
        
        # Обновляем или создаем профиль
        cursor.execute("""
            INSERT OR REPLACE INTO host_profiles
            (src_ip, connections_mean, connections_std, unique_ports_mean, unique_ports_std,
             unique_dst_ips_mean, unique_dst_ips_std, total_bytes_mean, total_bytes_std,
             avg_packet_size_mean, avg_packet_size_std, samples_count, last_updated, is_learning)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            src_ip, conn_mean, conn_std, port_mean, port_std,
            dst_mean, dst_std, bytes_mean, bytes_std, pkt_mean, pkt_std,
            samples_count, time.time(), 1 if is_learning else 0
        ))
        
        conn.commit()
        conn.close()
        
        if not is_learning and current_profile and current_profile[13]:
            logger.info(f"Хост {src_ip} завершил обучение ({samples_count} наблюдений)")
            
    def get_host_profile(self, src_ip: str) -> Optional[HostProfile]:
        """Получение профиля хоста"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM host_profiles WHERE src_ip = ?",
            (src_ip,)
        )
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
            
        return HostProfile(
            src_ip=row[0],
            connections_mean=row[1],
            connections_std=row[2],
            unique_ports_mean=row[3],
            unique_ports_std=row[4],
            unique_dst_ips_mean=row[5],
            unique_dst_ips_std=row[6],
            total_bytes_mean=row[7],
            total_bytes_std=row[8],
            avg_packet_size_mean=row[9],
            avg_packet_size_std=row[10],
            samples_count=row[11],
            last_updated=row[12],
            is_learning=bool(row[13])
        )
        
    def get_all_profiles(self) -> List[HostProfile]:
        """Получение всех профилей хостов"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM host_profiles ORDER BY last_updated DESC")
        rows = cursor.fetchall()
        conn.close()
        
        profiles = []
        for row in rows:
            profiles.append(HostProfile(
                src_ip=row[0],
                connections_mean=row[1],
                connections_std=row[2],
                unique_ports_mean=row[3],
                unique_ports_std=row[4],
                unique_dst_ips_mean=row[5],
                unique_dst_ips_std=row[6],
                total_bytes_mean=row[7],
                total_bytes_std=row[8],
                avg_packet_size_mean=row[9],
                avg_packet_size_std=row[10],
                samples_count=row[11],
                last_updated=row[12],
                is_learning=bool(row[13])
            ))
            
        return profiles
        
    def reset_profile(self, src_ip: str):
        """Сброс профиля хоста и перевод в режим обучения"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Удаляем историю
        cursor.execute("DELETE FROM metrics_history WHERE src_ip = ?", (src_ip,))
        
        # Удаляем профиль
        cursor.execute("DELETE FROM host_profiles WHERE src_ip = ?", (src_ip,))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Профиль хоста {src_ip} сброшен")
        
    def get_learning_statistics(self) -> Dict:
        """Получение статистики по обучению"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                COUNT(*) as total_hosts,
                SUM(CASE WHEN is_learning = 1 THEN 1 ELSE 0 END) as learning_hosts,
                SUM(CASE WHEN is_learning = 0 THEN 1 ELSE 0 END) as detection_hosts,
                AVG(samples_count) as avg_samples
            FROM host_profiles
        """)
        
        row = cursor.fetchone()
        conn.close()
        
        return {
            'total_hosts': row[0] or 0,
            'learning_hosts': row[1] or 0,
            'detection_hosts': row[2] or 0,
            'avg_samples': row[3] or 0
        }


if __name__ == "__main__":
    # Пример использования
    logging.basicConfig(level=logging.INFO)
    
    trainer = AdaptiveTrainer(db_path="test_training.db")
    
    # Симуляция обучения
    test_ip = "192.168.1.100"
    
    # Добавляем нормальные наблюдения
    for i in range(10):
        metrics = {
            'connections_count': 10 + i,
            'unique_ports': 3,
            'unique_dst_ips': 2,
            'total_bytes': 5000 + i * 100,
            'avg_packet_size': 500
        }
        trainer.add_metrics_sample(test_ip, metrics)
        
    # Проверяем профиль
    profile = trainer.get_host_profile(test_ip)
    if profile:
        print(f"Профиль {test_ip}:")
        print(f"  Соединений (среднее): {profile.connections_mean:.2f} ± {profile.connections_std:.2f}")
        print(f"  Режим обучения: {profile.is_learning}")
        print(f"  Наблюдений: {profile.samples_count}")
        
    # Статистика
    stats = trainer.get_learning_statistics()
    print(f"\nСтатистика обучения: {stats}")
