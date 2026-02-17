"""
Гибридный скоринг — объединение трёх слоёв детекции:
1. Suricata (сигнатурный анализ)
2. Z-Score (статистический анализ)
3. Isolation Forest (ML-анализ)

Каждому хосту за каждое временное окно выставляется единый threat_score.
"""
import sqlite3
import json
import sys
import time
import math
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict


@dataclass
class HybridVerdict:
    """Итоговый вердикт по хосту за окно"""
    timestamp: float
    src_ip: str

    # Скоры от каждого слоя (0..1)
    suricata_score: float    # Есть ли сигнатурные срабатывания
    stat_score: float        # Нормализованный z-score
    ml_score: float          # Score от Isolation Forest

    # Итог
    combined_score: float
    severity: str
    confidence: str          # low / medium / high (сколько слоёв сработали)

    # Объяснение
    suricata_alerts: List[Dict]
    stat_anomalies: List[Dict]
    ml_top_features: List[Dict]

    description: str


class HybridScorer:
    """
    Объединяет три слоя детекции в единый threat score.

    Формула:
        combined = w_sig * suricata_score + w_stat * stat_score + w_ml * ml_score

    Веса по умолчанию:
        w_sig  = 0.40  (сигнатуры — самые точные, наибольший вес)
        w_stat = 0.25  (статистика — быстро реагирует)
        w_ml   = 0.35  (ML — ловит сложные паттерны)

    Confidence:
        - 3 из 3 слоёв → high
        - 2 из 3 → medium
        - 1 из 3 → low
    """

    SEVERITY_THRESHOLDS = {
        'critical': 0.85,
        'high': 0.65,
        'medium': 0.45,
        'low': 0.25
    }

    def __init__(self, db_path: str = "ids.db",
                 w_sig: float = 0.40,
                 w_stat: float = 0.25,
                 w_ml: float = 0.35):
        self.db_path = db_path
        self.w_sig = w_sig
        self.w_stat = w_stat
        self.w_ml = w_ml

        # Компоненты (ленивая загрузка)
        self.suricata_engine = None
        self.anomaly_detector = None
        self.ml_detector = None

        self._init_components()
        self._init_db()

    def _init_components(self):
        """Ленивая загрузка компонентов"""
        try:
            from ndtp_ids.suricata_engine import SuricataEngine
            self.suricata_engine = SuricataEngine(db_path=self.db_path)
            self.suricata_engine.load_default_rules()
            print("[HybridScorer] Suricata engine: OK", file=sys.stderr)
        except Exception as e:
            print(f"[HybridScorer] Suricata engine: FAILED ({e})", file=sys.stderr)

        try:
            from ndtp_ids.anomaly_detector import AnomalyDetector
            self.anomaly_detector = AnomalyDetector(
                db_path=self.db_path, z_threshold=3.0
            )
            print("[HybridScorer] Z-Score detector: OK", file=sys.stderr)
        except Exception as e:
            print(f"[HybridScorer] Z-Score detector: FAILED ({e})", file=sys.stderr)

        try:
            from ndtp_ids.ml_detector import MLAnomalyDetector
            self.ml_detector = MLAnomalyDetector(db_path=self.db_path)
            print(f"[HybridScorer] ML detector: OK (trained={self.ml_detector.is_trained})",
                  file=sys.stderr)
        except Exception as e:
            print(f"[HybridScorer] ML detector: FAILED ({e})", file=sys.stderr)

    def _init_db(self):
        """Таблица для хранения гибридных вердиктов"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hybrid_verdicts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                src_ip TEXT NOT NULL,
                suricata_score REAL DEFAULT 0,
                stat_score REAL DEFAULT 0,
                ml_score REAL DEFAULT 0,
                combined_score REAL NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                description TEXT,
                details_json TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_hybrid_ts
            ON hybrid_verdicts(timestamp)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_hybrid_ip
            ON hybrid_verdicts(src_ip)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_hybrid_severity
            ON hybrid_verdicts(severity)
        ''')

        conn.commit()
        conn.close()

    # =========================================================================
    #  ПОЛУЧЕНИЕ СКОРОВ ОТ КАЖДОГО СЛОЯ
    # =========================================================================

    def _get_suricata_score(self, src_ip: str,
                            time_window_seconds: int = 120) -> tuple:
        """
        Скор от Suricata: были ли сигнатурные срабатывания за последнее окно?

        Returns:
            (score: 0..1, alerts: list)
        """
        if self.suricata_engine is None:
            return 0.0, []

        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            cutoff = datetime.now().timestamp() - time_window_seconds

            # Проверяем наличие таблицы
            cursor.execute("""
                SELECT name FROM sqlite_master
                WHERE type='table' AND name='suricata_alerts'
            """)
            if not cursor.fetchone():
                return 0.0, []

            cursor.execute('''
                SELECT timestamp, sid, msg, severity, src_ip, dst_ip,
                       dst_port, protocol
                FROM suricata_alerts
                WHERE src_ip = ? AND timestamp > ?
                ORDER BY timestamp DESC
                LIMIT 20
            ''', (src_ip, cutoff))

            rows = cursor.fetchall()
        finally:
            conn.close()

        if not rows:
            return 0.0, []

        alerts = []
        severity_weights = {
            'critical': 1.0,
            'high': 0.75,
            'medium': 0.5,
            'low': 0.25
        }

        max_weight = 0.0
        for row in rows:
            sev = row[3] if row[3] else 'medium'
            weight = severity_weights.get(sev, 0.5)
            max_weight = max(max_weight, weight)

            alerts.append({
                'timestamp': row[0],
                'sid': row[1],
                'msg': row[2],
                'severity': sev,
                'dst_port': row[6],
                'protocol': row[7]
            })

        # Скор = max(severity) * min(1, count/5)
        count_factor = min(1.0, len(rows) / 5.0)
        score = max_weight * (0.5 + 0.5 * count_factor)

        return min(score, 1.0), alerts

    def _get_stat_score(self, src_ip: str, metrics: Dict[str, float]) -> tuple:
        """
        Скор от Z-Score анализа

        Returns:
            (score: 0..1, anomalies: list)
        """
        if self.anomaly_detector is None:
            return 0.0, []

        FEATURE_NAMES = [
            'connections_count', 'unique_ports', 'unique_dst_ips',
            'total_bytes', 'avg_packet_size'
        ]

        z_scores = []
        anomalies = []

        for metric_name in FEATURE_NAMES:
            current_value = float(metrics.get(metric_name, 0))

            try:
                mean, std, count = self.anomaly_detector.calculate_statistics(
                    src_ip, metric_name
                )
            except (ValueError, Exception):
                continue

            if count < 3 or std == 0:
                continue

            z = abs((current_value - mean) / std)
            z_scores.append(z)

            if z > self.anomaly_detector.z_threshold:
                anomalies.append({
                    'metric': metric_name,
                    'z_score': round(z, 2),
                    'current': round(current_value, 2),
                    'mean': round(mean, 2),
                    'std': round(std, 2)
                })

        if not z_scores:
            return 0.0, anomalies

        max_z = max(z_scores)
        threshold = self.anomaly_detector.z_threshold
        score = 1.0 / (1.0 + math.exp(-(max_z - threshold)))

        return float(min(score, 1.0)), anomalies

    def _get_ml_score(self, src_ip: str, metrics: Dict[str, float]) -> tuple:
        """
        Скор от Isolation Forest

        Returns:
            (score: 0..1, top_features: list)
        """
        if self.ml_detector is None or not self.ml_detector.is_trained:
            return 0.0, []

        try:
            import numpy as np
            features = self.ml_detector._extract_features(metrics)
            ml_score = self.ml_detector._get_ml_score(features)

            _, contributions = self.ml_detector._get_stat_score(src_ip, metrics)
            top_features = contributions[:3]

            return ml_score, top_features
        except Exception as e:
            print(f"[HybridScorer] ML score error: {e}", file=sys.stderr)
            return 0.0, []

    # =========================================================================
    #  ГИБРИДНЫЙ СКОРИНГ
    # =========================================================================

    def score_host(self, src_ip: str, metrics: Dict[str, float]) -> HybridVerdict:
        """
        Вычисление гибридного threat score для одного хоста

        Args:
            src_ip: IP хоста
            metrics: Агрегированные метрики за текущее окно

        Returns:
            HybridVerdict с полной информацией
        """
        now = datetime.now().timestamp()

        # Получаем скоры от каждого слоя
        sig_score, sig_alerts = self._get_suricata_score(src_ip)
        stat_score, stat_anomalies = self._get_stat_score(src_ip, metrics)
        ml_score, ml_features = self._get_ml_score(src_ip, metrics)

        # Подсчёт сколько слоёв активны и сработали
        active_layers = 0
        triggered_layers = 0

        weights = {}

        if self.suricata_engine is not None:
            active_layers += 1
            if sig_score > 0.25:
                triggered_layers += 1
            weights['sig'] = self.w_sig
        else:
            weights['sig'] = 0.0

        if self.anomaly_detector is not None:
            active_layers += 1
            if stat_score > 0.5:
                triggered_layers += 1
            weights['stat'] = self.w_stat
        else:
            weights['stat'] = 0.0

        if self.ml_detector is not None and self.ml_detector.is_trained:
            active_layers += 1
            if ml_score > 0.5:
                triggered_layers += 1
            weights['ml'] = self.w_ml
        else:
            weights['ml'] = 0.0

        # Нормализация весов (чтобы сумма = 1)
        total_weight = sum(weights.values())
        if total_weight > 0:
            w_sig_norm = weights['sig'] / total_weight
            w_stat_norm = weights['stat'] / total_weight
            w_ml_norm = weights['ml'] / total_weight
        else:
            w_sig_norm = w_stat_norm = w_ml_norm = 0.0

        # Гибридный скор
        combined = (
            w_sig_norm * sig_score +
            w_stat_norm * stat_score +
            w_ml_norm * ml_score
        )

        # Бонус за согласие нескольких слоёв (consensus boost)
        if triggered_layers >= 3:
            combined = min(1.0, combined * 1.3)
        elif triggered_layers >= 2:
            combined = min(1.0, combined * 1.15)

        combined = min(1.0, max(0.0, combined))

        # Severity
        severity = 'info'
        for sev, threshold in self.SEVERITY_THRESHOLDS.items():
            if combined >= threshold:
                severity = sev
                break

        # Confidence
        if triggered_layers >= 3:
            confidence = 'high'
        elif triggered_layers >= 2:
            confidence = 'medium'
        elif triggered_layers >= 1:
            confidence = 'low'
        else:
            confidence = 'none'

        # Описание
        parts = []
        parts.append(f"Host {src_ip}: combined={combined:.3f}")
        parts.append(f"[SIG={sig_score:.2f}({len(sig_alerts)} alerts)]")
        parts.append(f"[STAT={stat_score:.2f}({len(stat_anomalies)} anomalies)]")
        parts.append(f"[ML={ml_score:.2f}]")
        parts.append(f"confidence={confidence}")
        description = " ".join(parts)

        verdict = HybridVerdict(
            timestamp=now,
            src_ip=src_ip,
            suricata_score=round(sig_score, 4),
            stat_score=round(stat_score, 4),
            ml_score=round(ml_score, 4),
            combined_score=round(combined, 4),
            severity=severity,
            confidence=confidence,
            suricata_alerts=sig_alerts,
            stat_anomalies=stat_anomalies,
            ml_top_features=ml_features,
            description=description
        )

        return verdict

    def save_verdict(self, verdict: HybridVerdict):
        """Сохранение вердикта в БД"""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            details = {
                'suricata_alerts': verdict.suricata_alerts,
                'stat_anomalies': verdict.stat_anomalies,
                'ml_top_features': verdict.ml_top_features
            }

            cursor.execute('''
                INSERT INTO hybrid_verdicts
                (timestamp, src_ip, suricata_score, stat_score, ml_score,
                 combined_score, severity, confidence, description, details_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                verdict.timestamp,
                verdict.src_ip,
                verdict.suricata_score,
                verdict.stat_score,
                verdict.ml_score,
                verdict.combined_score,
                verdict.severity,
                verdict.confidence,
                verdict.description,
                json.dumps(details, ensure_ascii=False)
            ))

            conn.commit()
        finally:
            conn.close()

    # =========================================================================
    #  ПОЛНЫЙ ЦИКЛ
    # =========================================================================

    def run_scoring_cycle(self):
        """
        Один цикл скоринга: для каждого активного хоста вычислить
        гибридный скор, сохранить.
        """
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            cursor.execute('''
                SELECT DISTINCT src_ip
                FROM aggregated_metrics
                WHERE timestamp > ?
            ''', (datetime.now().timestamp() - 300,))

            active_hosts = [row[0] for row in cursor.fetchall()]

            verdicts_generated = 0
            alerts_generated = 0

            for src_ip in active_hosts:
                cursor.execute('''
                    SELECT metric_name, metric_value
                    FROM aggregated_metrics
                    WHERE src_ip = ?
                    AND timestamp = (
                        SELECT MAX(timestamp) FROM aggregated_metrics WHERE src_ip = ?
                    )
                ''', (src_ip, src_ip))

                metrics = {}
                for name, value in cursor.fetchall():
                    metrics[name] = value

                if len(metrics) < 3:
                    continue

                verdict = self.score_host(src_ip, metrics)
                verdicts_generated += 1

                if verdict.combined_score >= self.SEVERITY_THRESHOLDS['low']:
                    self.save_verdict(verdict)
                    alerts_generated += 1

                    print(
                        f"[HYBRID] {verdict.severity.upper()} "
                        f"({verdict.confidence}) {verdict.description}",
                        file=sys.stderr
                    )

                # Пополняем обучающие данные для ML
                if self.ml_detector is not None:
                    self.ml_detector.collect_training_data(src_ip, metrics)
        finally:
            conn.close()

        if verdicts_generated > 0:
            print(
                f"[HybridScorer] Cycle: {verdicts_generated} hosts scored, "
                f"{alerts_generated} alerts",
                file=sys.stderr
            )

    def auto_train_ml(self):
        """Попытка автоматически обучить ML-модель если достаточно данных"""
        if self.ml_detector is None:
            return None

        if self.ml_detector.is_trained:
            return {'status': 'already_trained'}

        result = self.ml_detector.train()
        if result.get('status') == 'trained':
            print(
                f"[HybridScorer] ML model auto-trained on "
                f"{result['n_samples']} samples",
                file=sys.stderr
            )
        return result

    # =========================================================================
    #  API ДЛЯ ВЕБ-ИНТЕРФЕЙСА
    # =========================================================================

    def get_recent_verdicts(self, limit: int = 50,
                            severity: str = None,
                            src_ip: str = None) -> List[Dict]:
        """Последние гибридные вердикты для дашборда"""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            query = '''
                SELECT timestamp, src_ip, suricata_score, stat_score, ml_score,
                       combined_score, severity, confidence, description, details_json
                FROM hybrid_verdicts
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

        verdicts = []
        for row in rows:
            details = {}
            try:
                details = json.loads(row[9]) if row[9] else {}
            except json.JSONDecodeError:
                pass

            verdicts.append({
                'timestamp': row[0],
                'time_str': datetime.fromtimestamp(row[0]).strftime('%Y-%m-%d %H:%M:%S'),
                'src_ip': row[1],
                'suricata_score': row[2],
                'stat_score': row[3],
                'ml_score': row[4],
                'combined_score': row[5],
                'severity': row[6],
                'confidence': row[7],
                'description': row[8],
                'suricata_alerts': details.get('suricata_alerts', []),
                'stat_anomalies': details.get('stat_anomalies', []),
                'ml_top_features': details.get('ml_top_features', [])
            })

        return verdicts

    def get_layer_status(self) -> Dict:
        """Статус каждого слоя для дашборда"""
        layers = {
            'suricata': {
                'active': self.suricata_engine is not None,
                'weight': self.w_sig,
                'info': {}
            },
            'stat': {
                'active': self.anomaly_detector is not None,
                'weight': self.w_stat,
                'info': {
                    'z_threshold': self.anomaly_detector.z_threshold
                    if self.anomaly_detector else None
                }
            },
            'ml': {
                'active': (self.ml_detector is not None
                           and self.ml_detector.is_trained),
                'weight': self.w_ml,
                'info': {}
            }
        }

        if self.suricata_engine:
            try:
                layers['suricata']['info'] = self.suricata_engine.get_rules_count()
            except Exception:
                pass

        if self.ml_detector:
            try:
                layers['ml']['info'] = self.ml_detector.get_model_status()
            except Exception:
                pass

        return layers

    def get_hybrid_stats(self) -> Dict:
        """Агрегированная статистика гибридного скоринга"""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            cursor.execute('SELECT COUNT(*) FROM hybrid_verdicts')
            total = cursor.fetchone()[0]

            one_hour_ago = datetime.now().timestamp() - 3600
            cursor.execute(
                'SELECT COUNT(*) FROM hybrid_verdicts WHERE timestamp > ?',
                (one_hour_ago,)
            )
            last_hour = cursor.fetchone()[0]

            cursor.execute('''
                SELECT severity, COUNT(*) FROM hybrid_verdicts GROUP BY severity
            ''')
            by_severity = {r[0]: r[1] for r in cursor.fetchall()}

            cursor.execute('''
                SELECT confidence, COUNT(*) FROM hybrid_verdicts GROUP BY confidence
            ''')
            by_confidence = {r[0]: r[1] for r in cursor.fetchall()}

            cursor.execute('''
                SELECT AVG(combined_score), AVG(suricata_score),
                       AVG(stat_score), AVG(ml_score)
                FROM hybrid_verdicts WHERE timestamp > ?
            ''', (one_hour_ago,))
            avg_row = cursor.fetchone()
        finally:
            conn.close()

        return {
            'total_verdicts': total,
            'last_hour': last_hour,
            'by_severity': by_severity,
            'by_confidence': by_confidence,
            'avg_scores': {
                'combined': round(avg_row[0] or 0, 4),
                'suricata': round(avg_row[1] or 0, 4),
                'stat': round(avg_row[2] or 0, 4),
                'ml': round(avg_row[3] or 0, 4)
            }
        }


# =============================================================================
#  ТОЧКА ВХОДА
# =============================================================================

def run_hybrid_scorer(db_path: str = "ids.db", interval_seconds: int = 60):
    """Запуск гибридного скорера в цикле"""
    scorer = HybridScorer(db_path=db_path)

    print("[HybridScorer] ====================================")
    print("[HybridScorer] Гибридная IDS — три слоя детекции")
    print(f"[HybridScorer] Weights: SIG={scorer.w_sig}, STAT={scorer.w_stat}, ML={scorer.w_ml}")

    status = scorer.get_layer_status()
    for layer, info in status.items():
        state = "OK" if info['active'] else "OFF"
        print(f"[HybridScorer]   [{state}] {layer}: weight={info['weight']}")

    print(f"[HybridScorer] Interval: {interval_seconds}s")
    print("[HybridScorer] ====================================")

    try:
        cycle = 0
        while True:
            cycle += 1

            # Каждые 10 циклов пробуем автообучить ML
            if cycle % 10 == 1:
                scorer.auto_train_ml()

            scorer.run_scoring_cycle()
            time.sleep(interval_seconds)

    except KeyboardInterrupt:
        print("\n[HybridScorer] Shutting down...")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Hybrid Scorer — гибридная IDS (Suricata + Z-Score + ML)"
    )
    parser.add_argument("--db", default="ids.db", help="Путь к БД")
    parser.add_argument(
        "--interval", type=int, default=60,
        help="Интервал между циклами (сек)"
    )
    parser.add_argument(
        "--w-sig", type=float, default=0.40,
        help="Вес сигнатурного слоя (0..1)"
    )
    parser.add_argument(
        "--w-stat", type=float, default=0.25,
        help="Вес статистического слоя (0..1)"
    )
    parser.add_argument(
        "--w-ml", type=float, default=0.35,
        help="Вес ML слоя (0..1)"
    )

    args = parser.parse_args()

    run_hybrid_scorer(
        db_path=args.db,
        interval_seconds=args.interval
    )
