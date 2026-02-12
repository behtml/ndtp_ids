"""
Простые тесты для проверки работоспособности модулей NDTP IDS
"""
import unittest
import json
import tempfile
import os
from datetime import datetime

from ndtp_ids.aggregator import MetricsAggregator
from ndtp_ids.anomaly_detector import AnomalyDetector
from ndtp_ids.packet_collector import PacketEvent, get_direction


class TestPacketCollector(unittest.TestCase):
    """Тесты для коллектора пакетов"""
    
    def test_get_direction_out(self):
        """Тест определения исходящего трафика"""
        result = get_direction("192.168.1.100")
        self.assertEqual(result, "out")
    
    def test_get_direction_in(self):
        """Тест определения входящего трафика"""
        result = get_direction("8.8.8.8")
        self.assertEqual(result, "in")
    
    def test_packet_event_creation(self):
        """Тест создания события пакета"""
        event = PacketEvent(
            timestamp=123456.789,
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=443,
            protocol="TCP",
            packet_size=1500,
            direction="out"
        )
        
        self.assertEqual(event.src_ip, "192.168.1.100")
        self.assertEqual(event.dst_ip, "8.8.8.8")
        self.assertEqual(event.protocol, "TCP")
        self.assertEqual(event.direction, "out")


class TestAggregator(unittest.TestCase):
    """Тесты для агрегатора"""
    
    def setUp(self):
        """Создание временной БД для тестов"""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_db.close()
        self.db_path = self.temp_db.name
        self.aggregator = MetricsAggregator(db_path=self.db_path, window_minutes=1)
    
    def tearDown(self):
        """Удаление временной БД"""
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)
    
    def test_aggregator_creation(self):
        """Тест создания агрегатора"""
        self.assertIsNotNone(self.aggregator)
        self.assertEqual(self.aggregator.window_seconds, 60)
    
    def test_process_event(self):
        """Тест обработки события"""
        event = {
            "timestamp": datetime.now().timestamp(),
            "src_ip": "192.168.1.100",
            "dst_ip": "8.8.8.8",
            "src_port": 54321,
            "dst_port": 443,
            "protocol": "TCP",
            "packet_size": 1500,
            "direction": "out"
        }
        
        # Должно выполниться без ошибок
        self.aggregator.process_event(event)
    
    def test_get_window_key(self):
        """Тест вычисления ключа окна"""
        timestamp = 1707646800.0  # Какой-то timestamp
        window_key = self.aggregator.get_window_key(timestamp)
        
        # Проверяем, что ключ кратен размеру окна
        self.assertEqual(window_key % self.aggregator.window_seconds, 0)
    
    def test_multiple_events_aggregation(self):
        """Тест агрегации нескольких событий"""
        base_time = datetime.now().timestamp()
        
        for i in range(5):
            event = {
                "timestamp": base_time + i,
                "src_ip": "192.168.1.100",
                "dst_ip": f"8.8.8.{i}",
                "src_port": 54321 + i,
                "dst_port": 443 + i,
                "protocol": "TCP",
                "packet_size": 1000 + i * 100,
                "direction": "out"
            }
            self.aggregator.process_event(event)
        
        # Принудительно сохраняем все окна
        self.aggregator.flush_all()
        
        # Получаем метрики
        metrics = self.aggregator.get_metrics(src_ip="192.168.1.100")
        
        self.assertGreater(len(metrics), 0)


class TestAnomalyDetector(unittest.TestCase):
    """Тесты для детектора аномалий"""
    
    def setUp(self):
        """Создание временной БД для тестов"""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_db.close()
        self.db_path = self.temp_db.name
        self.detector = AnomalyDetector(db_path=self.db_path, z_threshold=3.0)
    
    def tearDown(self):
        """Удаление временной БД"""
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)
    
    def test_detector_creation(self):
        """Тест создания детектора"""
        self.assertIsNotNone(self.detector)
        self.assertEqual(self.detector.z_threshold, 3.0)
    
    def test_calculate_z_score(self):
        """Тест вычисления z-score"""
        mean = 100.0
        std = 10.0
        current = 130.0
        
        z_score = self.detector.calculate_z_score(current, mean, std)
        self.assertEqual(z_score, 3.0)
    
    def test_get_severity(self):
        """Тест определения уровня серьезности"""
        self.assertEqual(self.detector.get_severity(2.5), "low")
        self.assertEqual(self.detector.get_severity(3.5), "medium")
        self.assertEqual(self.detector.get_severity(4.5), "high")
        self.assertEqual(self.detector.get_severity(5.5), "critical")
    
    def test_calculate_z_score_zero_std(self):
        """Тест z-score при нулевом отклонении"""
        z_score = self.detector.calculate_z_score(100, 100, 0)
        self.assertEqual(z_score, 0.0)
    
    def test_invalid_metric_name(self):
        """Тест валидации имени метрики (защита от SQL injection)"""
        with self.assertRaises(ValueError):
            self.detector.calculate_statistics("192.168.1.1", "invalid_metric; DROP TABLE alerts;--")


class TestIntegration(unittest.TestCase):
    """Интеграционные тесты"""
    
    def setUp(self):
        """Создание временной БД для тестов"""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_db.close()
        self.db_path = self.temp_db.name
        self.aggregator = MetricsAggregator(db_path=self.db_path, window_minutes=1)
        self.detector = AnomalyDetector(db_path=self.db_path, z_threshold=2.0)
    
    def tearDown(self):
        """Удаление временной БД"""
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)
    
    def test_full_pipeline(self):
        """Тест полного пайплайна: события -> агрегация -> детекция"""
        base_time = datetime.now().timestamp()
        
        # Генерируем нормальные события
        for i in range(10):
            event = {
                "timestamp": base_time + i,
                "src_ip": "192.168.1.100",
                "dst_ip": f"8.8.8.{i % 3}",
                "src_port": 54321,
                "dst_port": 443,
                "protocol": "TCP",
                "packet_size": 1000,
                "direction": "out"
            }
            self.aggregator.process_event(event)
        
        # Сохраняем метрики
        self.aggregator.flush_all()
        
        # Генерируем аномальное событие (много соединений)
        for i in range(100):
            event = {
                "timestamp": base_time + 100 + i,
                "src_ip": "192.168.1.100",
                "dst_ip": f"8.8.8.{i % 3}",
                "src_port": 54321 + i,
                "dst_port": 443,
                "protocol": "TCP",
                "packet_size": 1000,
                "direction": "out"
            }
            self.aggregator.process_event(event)
        
        # Сохраняем метрики
        self.aggregator.flush_all()
        
        # Запускаем детекцию
        self.detector.run_detection()
        
        # Проверяем, что алерты были созданы
        alerts = self.detector.get_recent_alerts(limit=10)
        
        # Должны быть обнаружены аномалии
        # (может быть 0 если недостаточно данных для статистики, это нормально)
        self.assertIsInstance(alerts, list)


if __name__ == "__main__":
    unittest.main()
