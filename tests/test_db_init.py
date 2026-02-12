"""
Тесты для инициализации базы данных
"""
import unittest
import tempfile
import os
import sqlite3

from ndtp_ids.init_db import init_database
from ndtp_ids.aggregator import MetricsAggregator
from ndtp_ids.anomaly_detector import AnomalyDetector


class TestDatabaseInitialization(unittest.TestCase):
    """Тесты для инициализации базы данных"""
    
    def setUp(self):
        """Создание временной БД для тестов"""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_db.close()
        self.db_path = self.temp_db.name
    
    def tearDown(self):
        """Удаление временной БД"""
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)
    
    def test_init_database_creates_tables(self):
        """Тест что init_database создает все таблицы"""
        success = init_database(self.db_path)
        self.assertTrue(success)
        
        # Проверяем что все таблицы созданы
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = [row[0] for row in cursor.fetchall()]
        
        self.assertIn('aggregated_metrics', tables)
        self.assertIn('alerts', tables)
        self.assertIn('device_profiles', tables)
        self.assertIn('raw_events', tables)
        
        conn.close()
    
    def test_aggregated_metrics_schema(self):
        """Тест схемы таблицы aggregated_metrics"""
        init_database(self.db_path)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("PRAGMA table_info(aggregated_metrics)")
        columns = {row[1]: row[2] for row in cursor.fetchall()}
        
        # Проверяем необходимые поля
        self.assertIn('id', columns)
        self.assertIn('timestamp', columns)
        self.assertIn('src_ip', columns)
        self.assertIn('metric_name', columns)
        self.assertIn('metric_value', columns)
        self.assertIn('window_start', columns)
        self.assertIn('window_end', columns)
        self.assertIn('created_at', columns)
        
        # Проверяем типы
        self.assertEqual(columns['timestamp'], 'REAL')
        self.assertEqual(columns['src_ip'], 'TEXT')
        self.assertEqual(columns['metric_name'], 'TEXT')
        self.assertEqual(columns['metric_value'], 'REAL')
        
        conn.close()
    
    def test_alerts_schema(self):
        """Тест схемы таблицы alerts"""
        init_database(self.db_path)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("PRAGMA table_info(alerts)")
        columns = {row[1]: row[2] for row in cursor.fetchall()}
        
        # Проверяем необходимые поля по требованиям
        self.assertIn('id', columns)
        self.assertIn('timestamp', columns)
        self.assertIn('src_ip', columns)
        self.assertIn('anomaly_type', columns)
        self.assertIn('score', columns)
        self.assertIn('severity', columns)
        self.assertIn('description', columns)
        self.assertIn('metric_value', columns)
        self.assertIn('baseline_mean', columns)
        self.assertIn('baseline_std', columns)
        self.assertIn('resolved', columns)
        self.assertIn('created_at', columns)
        
        conn.close()
    
    def test_device_profiles_schema(self):
        """Тест схемы таблицы device_profiles"""
        init_database(self.db_path)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("PRAGMA table_info(device_profiles)")
        columns = {row[1]: row[2] for row in cursor.fetchall()}
        
        # Проверяем необходимые поля
        self.assertIn('src_ip', columns)
        self.assertIn('metric_name', columns)
        self.assertIn('mean', columns)
        self.assertIn('std', columns)
        self.assertIn('min_value', columns)
        self.assertIn('max_value', columns)
        self.assertIn('sample_count', columns)
        self.assertIn('last_updated', columns)
        self.assertIn('created_at', columns)
        
        conn.close()
    
    def test_indexes_created(self):
        """Тест что индексы созданы"""
        init_database(self.db_path)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Проверяем индексы для aggregated_metrics
        cursor.execute("PRAGMA index_list(aggregated_metrics)")
        indexes = [row[1] for row in cursor.fetchall()]
        
        self.assertIn('idx_metrics_timestamp', indexes)
        self.assertIn('idx_metrics_src_ip', indexes)
        self.assertIn('idx_metrics_name', indexes)
        
        # Проверяем индексы для alerts
        cursor.execute("PRAGMA index_list(alerts)")
        indexes = [row[1] for row in cursor.fetchall()]
        
        self.assertIn('idx_alerts_timestamp', indexes)
        self.assertIn('idx_alerts_src_ip', indexes)
        self.assertIn('idx_alerts_severity', indexes)
        
        conn.close()
    
    def test_aggregator_auto_init(self):
        """Тест автоматической инициализации при создании агрегатора"""
        # Создаем уникальный путь для БД, которая не существует
        test_db_path = self.db_path + "_aggregator_test.db"
        
        # БД не существует
        self.assertFalse(os.path.exists(test_db_path))
        
        # Создаем агрегатор - должен создать БД
        aggregator = MetricsAggregator(db_path=test_db_path)
        
        # Проверяем что БД создана
        self.assertTrue(os.path.exists(test_db_path))
        
        # Проверяем что таблицы существуют
        conn = sqlite3.connect(test_db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='aggregated_metrics'")
        self.assertIsNotNone(cursor.fetchone())
        
        conn.close()
        
        # Очистка
        if os.path.exists(test_db_path):
            os.unlink(test_db_path)
    
    def test_detector_auto_init(self):
        """Тест автоматической инициализации при создании детектора"""
        # Создаем уникальный путь для БД, которая не существует
        test_db_path = self.db_path + "_detector_test.db"
        
        # БД не существует
        self.assertFalse(os.path.exists(test_db_path))
        
        # Создаем детектор - должен создать БД
        detector = AnomalyDetector(db_path=test_db_path)
        
        # Проверяем что БД создана
        self.assertTrue(os.path.exists(test_db_path))
        
        # Проверяем что таблицы существуют
        conn = sqlite3.connect(test_db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'")
        self.assertIsNotNone(cursor.fetchone())
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='device_profiles'")
        self.assertIsNotNone(cursor.fetchone())
        
        conn.close()
        
        # Очистка
        if os.path.exists(test_db_path):
            os.unlink(test_db_path)
    
    def test_idempotent_initialization(self):
        """Тест что повторная инициализация не вызывает ошибок"""
        # Инициализируем первый раз
        success1 = init_database(self.db_path)
        self.assertTrue(success1)
        
        # Инициализируем второй раз - должно работать без ошибок
        success2 = init_database(self.db_path)
        self.assertTrue(success2)
        
        # Проверяем что таблицы все еще существуют
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = [row[0] for row in cursor.fetchall()]
        
        self.assertIn('aggregated_metrics', tables)
        self.assertIn('alerts', tables)
        self.assertIn('device_profiles', tables)
        
        conn.close()


if __name__ == "__main__":
    unittest.main()
