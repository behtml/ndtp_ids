"""
ML-детектор аномалий на основе Isolation Forest
Гибридный подход: работает совместно с z-score детектором

Isolation Forest — unsupervised алгоритм, не требующий размеченных данных.
Обучается на нормальном трафике и определяет аномалии по отклонению от обученного паттерна.
"""
import sqlite3
import pickle
import os
import sys
import math
import json
import time
import numpy as np
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict


@dataclass
class MLAlert:
    """Алерт от ML-детектора"""
    timestamp: float
    src_ip: str
    anomaly_type: str
    ml_score: float          # Score от Isolation Forest (0..1, выше = аномальнее)
    stat_score: float        # Нормализованный z-score (0..1)
    combined_score: float    # Гибридный скор
    severity: str
    description: str
    top_features: List[Dict]  # Топ-3 признака, вызвавших тревогу


class MLAnomalyDetector:
    """
    Детектор аномалий на основе Isolation Forest + z-score (гибридный)

    Процесс:
    1. Период обучения: собирает нормальные данные и обучает модель
    2. Период детекции: использует обученную модель + z-score
    3. Гибридный скоринг: объединяет оба метода
    """

    # Признаки для ML-модели
    FEATURE_NAMES = [
        'connections_count',
        'unique_ports',
        'unique_dst_ips',
        'total_bytes',
        'avg_packet_size'
    ]

    def __init__(self, db_path: str = "ids.db",
                 model_path: str = "ml_model.pkl",
                 z_threshold: float = 3.0,
                 ml_contamination: float = 0.05,
                 alpha: float = 0.4,
                 min_training_samples: int = 50):
        """
        Args:
            db_path: Путь к базе данных
            model_path: Путь для сохранения обученной модели
            z_threshold: Порог z-score
            ml_contamination: Доля ожидаемых аномалий (для Isolation Forest)
            alpha: Вес статистического скора в гибриде (0..1)
                   final = alpha * stat_score + (1-alpha) * ml_score
            min_training_samples: Минимум наблюдений для обучения
        """
        self.db_path = db_path
        self.model_path = model_path
        self.z_threshold = z_threshold
        self.ml_contamination = ml_contamination
        self.alpha = alpha
        self.min_training_samples = min_training_samples

        self.model = None       # Isolation Forest модель
        self.scaler = None      # StandardScaler для нормализации
        self.is_trained = False

        self._init_db()
        self._load_model()

    def _init_db(self):
        """Инициализация таблиц для ML-детектора"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Таблица для хранения обучающих данных
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ml_training_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_ip TEXT NOT NULL,
                timestamp REAL NOT NULL,
                connections_count REAL DEFAULT 0,
                unique_ports REAL DEFAULT 0,
                unique_dst_ips REAL DEFAULT 0,
                total_bytes REAL DEFAULT 0,
                avg_packet_size REAL DEFAULT 0,
                is_normal BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Таблица для метрик модели
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ml_model_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                trained_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                n_samples INTEGER,
                n_features INTEGER,
                contamination REAL,
                alpha REAL,
                notes TEXT
            )
        ''')

        # Таблица для ML-алертов
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ml_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                src_ip TEXT NOT NULL,
                anomaly_type TEXT NOT NULL,
                ml_score REAL,
                stat_score REAL,
                combined_score REAL,
                severity TEXT NOT NULL,
                description TEXT,
                top_features TEXT,
                resolved BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_ml_alerts_timestamp
            ON ml_alerts(timestamp)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_ml_alerts_src_ip
            ON ml_alerts(src_ip)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_ml_training_src_ip
            ON ml_training_data(src_ip)
        ''')

        conn.commit()
        conn.close()
        print("[MLDetector] Database tables initialized", file=sys.stderr)

    def _load_model(self):
        """Загрузка ранее обученной модели с диска"""
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    data = pickle.load(f)
                self.model = data['model']
                self.scaler = data['scaler']
                self.is_trained = True
                print(f"[MLDetector] Model loaded from {self.model_path}", file=sys.stderr)
            except Exception as e:
                print(f"[MLDetector] Failed to load model: {e}", file=sys.stderr)
                self.is_trained = False

    def _save_model(self):
        """Сохранение обученной модели на диск"""
        try:
            with open(self.model_path, 'wb') as f:
                pickle.dump({
                    'model': self.model,
                    'scaler': self.scaler,
                    'feature_names': self.FEATURE_NAMES,
                    'trained_at': datetime.now().isoformat()
                }, f)
            print(f"[MLDetector] Model saved to {self.model_path}", file=sys.stderr)
        except Exception as e:
            print(f"[MLDetector] Failed to save model: {e}", file=sys.stderr)

    # =========================================================================
    #  СБОР ОБУЧАЮЩИХ ДАННЫХ
    # =========================================================================

    def collect_training_data(self, src_ip: str, metrics: Dict[str, float]):
        """
        Добавить наблюдение в обучающий набор

        Args:
            src_ip: IP хоста
            metrics: Словарь метрик {metric_name: value}
        """
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO ml_training_data
                (src_ip, timestamp, connections_count, unique_ports,
                 unique_dst_ips, total_bytes, avg_packet_size, is_normal)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1)
            ''', (
                src_ip,
                datetime.now().timestamp(),
                metrics.get('connections_count', 0),
                metrics.get('unique_ports', 0),
                metrics.get('unique_dst_ips', 0),
                metrics.get('total_bytes', 0),
                metrics.get('avg_packet_size', 0)
            ))

            conn.commit()
        finally:
            conn.close()

    def collect_from_aggregated(self) -> int:
        """
        Автоматический сбор обучающих данных из таблицы aggregated_metrics.
        Берёт все данные, которых ещё нет в ml_training_data.
        
        Returns:
            Количество добавленных записей
        """
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            # Получаем уникальные окна (src_ip + window_start)
            cursor.execute('''
                SELECT DISTINCT src_ip, window_start
                FROM aggregated_metrics
                ORDER BY window_start
            ''')

            windows = cursor.fetchall()
            added = 0

            for src_ip, window_start in windows:
                # Проверяем, есть ли уже эти данные
                cursor.execute('''
                    SELECT COUNT(*) FROM ml_training_data
                    WHERE src_ip = ? AND abs(timestamp - ?) < 1
                ''', (src_ip, window_start))

                if cursor.fetchone()[0] > 0:
                    continue

                # Собираем метрики для этого окна
                cursor.execute('''
                    SELECT metric_name, metric_value
                    FROM aggregated_metrics
                    WHERE src_ip = ? AND window_start = ?
                ''', (src_ip, window_start))

                metrics = {}
                for name, value in cursor.fetchall():
                    metrics[name] = value

                if len(metrics) >= 3:
                    cursor.execute('''
                        INSERT INTO ml_training_data
                        (src_ip, timestamp, connections_count, unique_ports,
                         unique_dst_ips, total_bytes, avg_packet_size, is_normal)
                        VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                    ''', (
                        src_ip,
                        window_start,
                        metrics.get('connections_count', 0),
                        metrics.get('unique_ports', 0),
                        metrics.get('unique_dst_ips', 0),
                        metrics.get('total_bytes', 0),
                        metrics.get('avg_packet_size', 0)
                    ))
                    added += 1

            conn.commit()
        finally:
            conn.close()

        if added > 0:
            print(f"[MLDetector] Collected {added} training samples from aggregated_metrics",
                  file=sys.stderr)

        return added

    def get_training_sample_count(self) -> int:
        """Количество обучающих наблюдений"""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM ml_training_data WHERE is_normal = 1')
            count = cursor.fetchone()[0]
        finally:
            conn.close()
        return count

    # =========================================================================
    #  ОБУЧЕНИЕ МОДЕЛИ
    # =========================================================================

    def train(self, force: bool = False) -> Dict:
        """
        Обучение Isolation Forest на собранных нормальных данных

        Args:
            force: Принудительное переобучение даже если модель уже есть

        Returns:
            Словарь с метриками обучения
        """
        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import StandardScaler
        except ImportError:
            print("[MLDetector] ERROR: scikit-learn не установлен!", file=sys.stderr)
            print("[MLDetector] Установите: pip install scikit-learn", file=sys.stderr)
            return {'status': 'error', 'message': 'scikit-learn not installed'}

        if self.is_trained and not force:
            return {
                'status': 'already_trained',
                'message': 'Model already trained. Use force=True to retrain.'
            }

        # Автоматически собираем данные из aggregated_metrics
        self.collect_from_aggregated()

        # Загружаем обучающие данные
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            cursor.execute('''
                SELECT connections_count, unique_ports, unique_dst_ips,
                       total_bytes, avg_packet_size
                FROM ml_training_data
                WHERE is_normal = 1
            ''')

            rows = cursor.fetchall()
        finally:
            conn.close()

        n_samples = len(rows)

        if n_samples < self.min_training_samples:
            msg = (f"Недостаточно данных: {n_samples}/{self.min_training_samples}. "
                   f"Продолжайте сбор трафика.")
            print(f"[MLDetector] {msg}", file=sys.stderr)
            return {
                'status': 'insufficient_data',
                'current_samples': n_samples,
                'required_samples': self.min_training_samples,
                'message': msg
            }

        # Формируем массив признаков
        X = np.array(rows, dtype=np.float64)

        # Заменяем NaN и Inf
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

        # Нормализация
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        # Обучение Isolation Forest
        self.model = IsolationForest(
            n_estimators=100,
            contamination=self.ml_contamination,
            random_state=42,
            n_jobs=-1
        )
        self.model.fit(X_scaled)

        # Вычисляем метрики на обучающей выборке
        scores = self.model.decision_function(X_scaled)
        predictions = self.model.predict(X_scaled)

        n_anomalies_in_train = int(np.sum(predictions == -1))
        mean_score = float(np.mean(scores))
        std_score = float(np.std(scores))

        self.is_trained = True
        self._save_model()

        # Сохраняем метрики в БД
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO ml_model_metrics (n_samples, n_features, contamination, alpha, notes)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                n_samples,
                len(self.FEATURE_NAMES),
                self.ml_contamination,
                self.alpha,
                f"anomalies_in_train={n_anomalies_in_train}, mean_score={mean_score:.4f}"
            ))
            conn.commit()
        finally:
            conn.close()

        result = {
            'status': 'trained',
            'n_samples': n_samples,
            'n_features': len(self.FEATURE_NAMES),
            'feature_names': self.FEATURE_NAMES,
            'contamination': self.ml_contamination,
            'anomalies_in_training': n_anomalies_in_train,
            'mean_decision_score': round(mean_score, 4),
            'std_decision_score': round(std_score, 4),
            'model_path': self.model_path
        }

        print(f"[MLDetector] Model trained: {n_samples} samples, "
              f"{n_anomalies_in_train} anomalies detected in training data", file=sys.stderr)

        return result

    # =========================================================================
    #  ДЕТЕКЦИЯ АНОМАЛИЙ
    # =========================================================================

    def _extract_features(self, metrics: Dict[str, float]) -> np.ndarray:
        """Извлечение вектора признаков из метрик"""
        features = []
        for name in self.FEATURE_NAMES:
            features.append(float(metrics.get(name, 0)))
        return np.array(features, dtype=np.float64).reshape(1, -1)

    def _get_ml_score(self, features: np.ndarray) -> float:
        """
        Получение ML-скора аномалии (0..1, выше = аномальнее)

        Isolation Forest возвращает decision_function:
        - Отрицательные значения = аномалии
        - Положительные = нормальные

        Мы нормализуем в [0, 1] где 1 = максимальная аномальность
        """
        if not self.is_trained or self.model is None:
            return 0.0

        features_scaled = self.scaler.transform(features)

        # decision_function: чем меньше (отрицательнее), тем аномальнее
        raw_score = self.model.decision_function(features_scaled)[0]

        # Нормализуем: sigmoid-like преобразование
        normalized = 1.0 / (1.0 + math.exp(raw_score * 5))

        return float(np.clip(normalized, 0.0, 1.0))

    def _get_stat_score(self, src_ip: str, metrics: Dict[str, float]) -> Tuple[float, List[Dict]]:
        """
        Получение статистического скора (нормализованный z-score) + объяснение

        Returns:
            (normalized_score, feature_contributions)
        """
        z_scores = []
        contributions = []

        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            for metric_name in self.FEATURE_NAMES:
                current_value = float(metrics.get(metric_name, 0))

                # Получаем исторические значения
                cursor.execute('''
                    SELECT metric_value
                    FROM aggregated_metrics
                    WHERE src_ip = ? AND metric_name = ?
                    ORDER BY timestamp DESC
                    LIMIT 50
                ''', (src_ip, metric_name))

                values = [row[0] for row in cursor.fetchall()]

                if len(values) < 3:
                    z_scores.append(0.0)
                    contributions.append({
                        'feature': metric_name,
                        'z_score': 0.0,
                        'current': current_value,
                        'mean': 0.0,
                        'std': 0.0
                    })
                    continue

                mean = sum(values) / len(values)
                variance = sum((x - mean) ** 2 for x in values) / len(values)
                std = math.sqrt(variance)

                z = abs((current_value - mean) / std) if std > 0 else 0.0
                z_scores.append(z)

                contributions.append({
                    'feature': metric_name,
                    'z_score': round(z, 2),
                    'current': round(current_value, 2),
                    'mean': round(mean, 2),
                    'std': round(std, 2)
                })
        finally:
            conn.close()

        if not z_scores:
            return 0.0, contributions

        # Нормализуем максимальный z-score в [0, 1]
        max_z = max(z_scores)
        normalized = 1.0 / (1.0 + math.exp(-(max_z - self.z_threshold)))

        # Сортируем по z-score (самые аномальные первые)
        contributions.sort(key=lambda x: x['z_score'], reverse=True)

        return float(np.clip(normalized, 0.0, 1.0)), contributions

    def detect(self, src_ip: str, metrics: Dict[str, float]) -> Optional[MLAlert]:
        """
        Гибридная детекция аномалий

        Args:
            src_ip: IP адрес хоста
            metrics: Словарь метрик текущего окна

        Returns:
            MLAlert если обнаружена аномалия, иначе None
        """
        features = self._extract_features(metrics)

        # ML-скор
        ml_score = self._get_ml_score(features)

        # Статистический скор + объяснение
        stat_score, contributions = self._get_stat_score(src_ip, metrics)

        # Гибридный скор
        if self.is_trained:
            combined = self.alpha * stat_score + (1 - self.alpha) * ml_score
        else:
            # Если модель не обучена — полагаемся только на статистику
            combined = stat_score
            ml_score = 0.0

        # Порог для комбинированного скора
        COMBINED_THRESHOLD = 0.5

        if combined < COMBINED_THRESHOLD:
            return None

        # Определяем severity
        if combined >= 0.9:
            severity = "critical"
        elif combined >= 0.75:
            severity = "high"
        elif combined >= 0.6:
            severity = "medium"
        else:
            severity = "low"

        # Определяем тип аномалии по самому аномальному признаку
        anomaly_type = "hybrid_anomaly"
        if contributions:
            top_feature = contributions[0]['feature']
            anomaly_type = f"anomaly_{top_feature}"

        # Формируем описание
        top3 = contributions[:3]
        feature_desc = "; ".join(
            f"{c['feature']}: текущее={c['current']}, среднее={c['mean']}, z={c['z_score']}"
            for c in top3
        )

        description = (
            f"Гибридная аномалия для {src_ip}: "
            f"combined={combined:.3f} (stat={stat_score:.3f}, ml={ml_score:.3f}). "
            f"Топ признаки: {feature_desc}"
        )

        alert = MLAlert(
            timestamp=datetime.now().timestamp(),
            src_ip=src_ip,
            anomaly_type=anomaly_type,
            ml_score=ml_score,
            stat_score=stat_score,
            combined_score=combined,
            severity=severity,
            description=description,
            top_features=top3
        )

        return alert

    def save_ml_alert(self, alert: MLAlert):
        """Сохранение ML-алерта в БД"""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO ml_alerts
                (timestamp, src_ip, anomaly_type, ml_score, stat_score,
                 combined_score, severity, description, top_features, resolved)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
            ''', (
                alert.timestamp,
                alert.src_ip,
                alert.anomaly_type,
                alert.ml_score,
                alert.stat_score,
                alert.combined_score,
                alert.severity,
                alert.description,
                json.dumps(alert.top_features, ensure_ascii=False)
            ))

            conn.commit()
        finally:
            conn.close()

    # =========================================================================
    #  ПОЛНЫЙ ЦИКЛ ДЕТЕКЦИИ
    # =========================================================================

    def run_detection(self):
        """
        Полный цикл: собрать данные → обучить (если нужно) → детектировать
        """
        # Попытка автообучения если модель ещё не обучена
        if not self.is_trained:
            result = self.train()
            if result['status'] not in ('trained', 'already_trained'):
                print(f"[MLDetector] Model not ready: {result.get('message', '')}",
                      file=sys.stderr)

        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            # Получаем последние окна для каждого хоста
            cursor.execute('''
                SELECT DISTINCT src_ip, window_start, window_end
                FROM aggregated_metrics
                WHERE (src_ip, timestamp) IN (
                    SELECT src_ip, MAX(timestamp)
                    FROM aggregated_metrics
                    GROUP BY src_ip
                )
            ''')

            windows = cursor.fetchall()
            total_alerts = 0

            for src_ip, window_start, window_end in windows:
                # Собираем метрики для этого окна
                cursor.execute('''
                    SELECT metric_name, metric_value
                    FROM aggregated_metrics
                    WHERE src_ip = ? AND window_start = ?
                ''', (src_ip, window_start))

                metrics = {}
                for name, value in cursor.fetchall():
                    metrics[name] = value

                if len(metrics) < 3:
                    continue

                # Также добавляем в обучающие данные (для будущего переобучения)
                self.collect_training_data(src_ip, metrics)

                # Детектируем
                alert = self.detect(src_ip, metrics)

                if alert:
                    self.save_ml_alert(alert)
                    total_alerts += 1
                    print(f"[ML-ALERT] {alert.severity.upper()}: {alert.description}",
                          file=sys.stderr)
        finally:
            conn.close()

        if total_alerts > 0:
            print(f"[MLDetector] Detection cycle complete: {total_alerts} alerts",
                  file=sys.stderr)

    # =========================================================================
    #  API-МЕТОДЫ ДЛЯ ВЕБ-ИНТЕРФЕЙСА
    # =========================================================================

    def get_model_status(self) -> Dict:
        """Статус модели для дашборда"""
        return {
            'is_trained': self.is_trained,
            'model_path': self.model_path,
            'training_samples': self.get_training_sample_count(),
            'min_required': self.min_training_samples,
            'alpha': self.alpha,
            'z_threshold': self.z_threshold,
            'contamination': self.ml_contamination,
            'feature_names': self.FEATURE_NAMES
        }

    def get_recent_ml_alerts(self, limit: int = 50,
                             severity: str = None,
                             src_ip: str = None) -> List[Dict]:
        """Получение последних ML-алертов"""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            query = '''
                SELECT timestamp, src_ip, anomaly_type, ml_score, stat_score,
                       combined_score, severity, description, top_features
                FROM ml_alerts
            '''
            conditions = []
            params = []

            if severity:
                conditions.append('severity = ?')
                params.append(severity)
            if src_ip:
                conditions.append('src_ip = ?')
                params.append(src_ip)

            if conditions:
                query += ' WHERE ' + ' AND '.join(conditions)

            query += ' ORDER BY timestamp DESC LIMIT ?'
            params.append(limit)

            cursor.execute(query, params)
            rows = cursor.fetchall()
        finally:
            conn.close()

        alerts = []
        for row in rows:
            top_features = []
            try:
                top_features = json.loads(row[8]) if row[8] else []
            except json.JSONDecodeError:
                pass

            alerts.append({
                'timestamp': row[0],
                'timestamp_fmt': datetime.fromtimestamp(row[0]).strftime('%Y-%m-%d %H:%M:%S'),
                'src_ip': row[1],
                'anomaly_type': row[2],
                'ml_score': row[3],
                'stat_score': row[4],
                'combined_score': row[5],
                'severity': row[6],
                'description': row[7],
                'top_features': top_features
            })

        return alerts

    def get_training_history(self) -> List[Dict]:
        """История обучений модели"""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            cursor.execute('''
                SELECT trained_at, n_samples, n_features, contamination, alpha, notes
                FROM ml_model_metrics
                ORDER BY trained_at DESC
                LIMIT 20
            ''')

            rows = cursor.fetchall()
        finally:
            conn.close()

        return [{
            'trained_at': row[0],
            'n_samples': row[1],
            'n_features': row[2],
            'contamination': row[3],
            'alpha': row[4],
            'notes': row[5]
        } for row in rows]

    def get_ml_alerts_stats(self) -> Dict:
        """Статистика ML-алертов"""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            cursor.execute('SELECT COUNT(*) FROM ml_alerts')
            total = cursor.fetchone()[0]

            one_hour_ago = datetime.now().timestamp() - 3600
            cursor.execute('SELECT COUNT(*) FROM ml_alerts WHERE timestamp > ?', (one_hour_ago,))
            last_hour = cursor.fetchone()[0]

            cursor.execute('''
                SELECT severity, COUNT(*) FROM ml_alerts GROUP BY severity
            ''')
            by_severity = {r[0]: r[1] for r in cursor.fetchall()}

            cursor.execute('''
                SELECT AVG(combined_score) FROM ml_alerts
                WHERE timestamp > ?
            ''', (one_hour_ago,))
            avg_score_row = cursor.fetchone()
            avg_combined = round(avg_score_row[0], 4) if avg_score_row[0] else 0.0
        finally:
            conn.close()

        return {
            'total': total,
            'last_hour': last_hour,
            'by_severity': by_severity,
            'avg_combined_score': avg_combined
        }


# =============================================================================
#  ТОЧКА ВХОДА
# =============================================================================

def run_ml_detector(db_path: str = "ids.db",
                    model_path: str = "ml_model.pkl",
                    z_threshold: float = 3.0,
                    interval_seconds: int = 60):
    """Запуск гибридного ML-детектора"""
    detector = MLAnomalyDetector(
        db_path=db_path,
        model_path=model_path,
        z_threshold=z_threshold
    )

    print(f"[MLDetector] Started (hybrid: z-score + Isolation Forest)")
    print(f"[MLDetector] Alpha (stat weight): {detector.alpha}")
    print(f"[MLDetector] Z-threshold: {z_threshold}")
    print(f"[MLDetector] ML contamination: {detector.ml_contamination}")
    print(f"[MLDetector] Model trained: {detector.is_trained}")
    print(f"[MLDetector] Training samples: {detector.get_training_sample_count()}")
    print(f"[MLDetector] Check interval: {interval_seconds}s")

    try:
        while True:
            detector.run_detection()
            time.sleep(interval_seconds)
    except KeyboardInterrupt:
        print("\n[MLDetector] Shutting down...")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="ML Anomaly Detector — гибридный детектор (z-score + Isolation Forest)"
    )
    parser.add_argument("--db", default="ids.db", help="Путь к БД")
    parser.add_argument("--model", default="ml_model.pkl", help="Путь к файлу модели")
    parser.add_argument("--threshold", type=float, default=3.0, help="Порог z-score")
    parser.add_argument("--interval", type=int, default=60, help="Интервал проверки (сек)")
    parser.add_argument("--train", action="store_true", help="Принудительно обучить модель")

    args = parser.parse_args()

    if args.train:
        detector = MLAnomalyDetector(db_path=args.db, model_path=args.model)
        result = detector.train(force=True)
        print(f"\nРезультат обучения: {json.dumps(result, indent=2, ensure_ascii=False)}")
    else:
        run_ml_detector(
            db_path=args.db,
            model_path=args.model,
            z_threshold=args.threshold,
            interval_seconds=args.interval
        )
