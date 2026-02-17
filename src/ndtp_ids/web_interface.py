"""
Веб-интерфейс
Flask-based dashboard для мониторинга и управления системой обнаружения вторжений
"""
from flask import Flask, render_template, jsonify, request, send_from_directory
import sqlite3
import json
from datetime import datetime, timedelta
import os
from typing import Dict, List
import logging

# Импорты модулей системы
# Импорты модулей системы
try:
    from .adaptive_trainer import AdaptiveTrainer
    from .suricata_rules import SuricataRuleParser, DEFAULT_RULES
    from .suricata_engine import SuricataEngine
    from .anomaly_detector import AnomalyDetector
except ImportError:
    # Для запуска как standalone скрипт
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from adaptive_trainer import AdaptiveTrainer  # type: ignore
    from suricata_rules import SuricataRuleParser, DEFAULT_RULES  # type: ignore
    from suricata_engine import SuricataEngine  # type: ignore
    from anomaly_detector import AnomalyDetector  # type: ignore

# Опциональные м��дули ML (работают и без scikit-learn)
try:
    from .ml_detector import MLAnomalyDetector
    ML_AVAILABLE = True
except ImportError:
    try:
        from ml_detector import MLAnomalyDetector  # type: ignore
        ML_AVAILABLE = True
    except ImportError:
        ML_AVAILABLE = False

try:
    from .hybrid_scorer import HybridScorer
    HYBRID_AVAILABLE = True
except ImportError:
    try:
        from hybrid_scorer import HybridScorer  # type: ignore
        HYBRID_AVAILABLE = True
    except ImportError:
        HYBRID_AVAILABLE = False

logger = logging.getLogger(__name__)

# Инициализация Flask приложения
app = Flask(__name__)
# Security: Use environment variable for SECRET_KEY in production
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'ids-secret-key-change-in-production')

# Глобальные переменные для компонентов системы
DB_PATH = "ids.db"
RULES_DIR = os.path.join(os.path.dirname(__file__), 'rules')
trainer = None
rule_parser = None
suricata_engine = None
anomaly_detector = None
ml_detector = None
hybrid_scorer = None


def _ensure_core_tables():
    """Создание базовых таблиц если они ещё не существуют"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
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
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS aggregated_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_ip TEXT NOT NULL,
                timestamp REAL NOT NULL,
                window_start REAL,
                window_end REAL,
                metric_name TEXT NOT NULL,
                metric_value REAL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Core tables ensured")
    except Exception as e:
        logger.warning(f"Error ensuring core tables: {e}")


def init_components():
    """Инициализация компонентов системы"""
    global trainer, rule_parser, suricata_engine, anomaly_detector, ml_detector, hybrid_scorer
    
    trainer = AdaptiveTrainer(db_path=DB_PATH)
    rule_parser = SuricataRuleParser()
    
    # Загружаем базовые правила Suricata (в старый парсер для совместимости)
    rule_parser.load_rules_from_text(DEFAULT_RULES)
    
    # Создаём недостающие таблицы (raw_events, aggregated_metrics) если их нет
    _ensure_core_tables()
    
    # Инициализируем Suricata Engine с БД-хранилищем правил
    suricata_engine = SuricataEngine(db_path=DB_PATH)
    suricata_engine.load_default_rules()
    
    # Инициализируем детектор аномалий (z-score + ML)
    anomaly_detector = AnomalyDetector(db_path=DB_PATH, z_threshold=3.0, use_ml=True)
    logger.info("Anomaly detector initialized")
    
    # Инициализируем ML-детектор отдельно для API
    if ML_AVAILABLE:
        try:
            ml_detector = MLAnomalyDetector(db_path=DB_PATH)
            logger.info(f"ML detector initialized (trained={ml_detector.is_trained})")
        except Exception as e:
            logger.warning(f"ML detector failed: {e}")
    
    # Инициализируем гибридный скорер
    if HYBRID_AVAILABLE:
        try:
            hybrid_scorer = HybridScorer(db_path=DB_PATH)
            logger.info("Hybrid scorer initialized")
        except Exception as e:
            logger.warning(f"Hybrid scorer failed: {e}")
    
    # Автозагрузка правил из директории rules/
    if os.path.isdir(RULES_DIR):
        # Загружаем только те файлы, которые ещё не были загружены
        available = suricata_engine.get_available_rule_files(RULES_DIR)
        for rf in available:
            if not rf['is_loaded']:
                suricata_engine.add_rules_from_file(rf['path'], category=rf['category'])
        logger.info(f"Rules directory: {RULES_DIR}")
    
    logger.info("Компоненты системы инициализированы")


@app.route('/')
def index():
    """Главная страница - дашборд"""
    return render_template('dashboard.html')


@app.route('/api/chart/alerts_timeline')
def chart_alerts_timeline():
    """API: Данные для графика алертов по времени (последние 24 часа, по часам)"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        now = datetime.now().timestamp()
        day_ago = now - 86400

        # Собираем алерты из всех таблиц через UNION ALL
        # (таблицы могут не существовать, обрабатываем gracefully)
        union_parts = []
        for table in ['alerts', 'suricata_alerts', 'ml_alerts']:
            try:
                cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'")
                if cursor.fetchone():
                    union_parts.append(f"SELECT timestamp, severity FROM {table} WHERE timestamp > ?")
            except Exception:
                pass

        if not union_parts:
            conn.close()
            return jsonify({'labels': [], 'datasets': {}})

        union_query = " UNION ALL ".join(union_parts)
        params = [day_ago] * len(union_parts)

        cursor.execute(f'''
            SELECT CAST((timestamp - ?) / 3600 AS INTEGER) AS hour_bucket,
                   COUNT(*) AS cnt,
                   SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical,
                   SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) AS high,
                   SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) AS medium,
                   SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) AS low
            FROM ({union_query})
            GROUP BY hour_bucket
            ORDER BY hour_bucket
        ''', [day_ago] + params)

        rows = cursor.fetchall()
        conn.close()

        labels = []
        total = []
        critical = []
        high = []
        medium = []
        low = []

        for row in rows:
            hour_offset = row[0]
            t = datetime.fromtimestamp(day_ago + hour_offset * 3600)
            labels.append(t.strftime('%H:%M'))
            total.append(row[1])
            critical.append(row[2])
            high.append(row[3])
            medium.append(row[4])
            low.append(row[5])

        return jsonify({
            'labels': labels,
            'datasets': {
                'total': total,
                'critical': critical,
                'high': high,
                'medium': medium,
                'low': low
            }
        })
    except Exception as e:
        logger.error(f"Ошибка chart_alerts_timeline: {e}")
        return jsonify({'labels': [], 'datasets': {}}), 500


@app.route('/api/chart/severity_distribution')
def chart_severity_distribution():
    """API: Распределение алертов по severity (для pie/doughnut chart)"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Собираем severity из всех таблиц алертов
        severity_counts = {}
        for table in ['alerts', 'suricata_alerts', 'ml_alerts']:
            try:
                cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'")
                if cursor.fetchone():
                    cursor.execute(f'SELECT severity, COUNT(*) FROM {table} GROUP BY severity')
                    for sev, cnt in cursor.fetchall():
                        severity_counts[sev] = severity_counts.get(sev, 0) + cnt
            except Exception:
                pass

        conn.close()

        labels = list(severity_counts.keys())
        values = list(severity_counts.values())

        return jsonify({'labels': labels, 'values': values})
    except Exception as e:
        logger.error(f"Ошибка chart_severity_distribution: {e}")
        return jsonify({'labels': [], 'values': []}), 500


@app.route('/api/chart/traffic_metrics')
def chart_traffic_metrics():
    """API: Метрики трафика по временным окнам (для line chart на мониторинге)"""
    try:
        src_ip = request.args.get('src_ip', None)
        limit = request.args.get('limit', 30, type=int)

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        if src_ip:
            cursor.execute('''
                SELECT DISTINCT window_start, window_end
                FROM aggregated_metrics
                WHERE src_ip = ?
                ORDER BY window_start DESC
                LIMIT ?
            ''', (src_ip, limit))
        else:
            cursor.execute('''
                SELECT DISTINCT window_start, window_end
                FROM aggregated_metrics
                ORDER BY window_start DESC
                LIMIT ?
            ''', (limit,))

        windows = cursor.fetchall()
        windows.reverse()  # хронологический порядок

        labels = []
        connections = []
        unique_ports = []
        unique_dst_ips = []
        total_bytes = []

        for ws, we in windows:
            t = datetime.fromtimestamp(we)
            labels.append(t.strftime('%H:%M'))

            if src_ip:
                cursor.execute('''
                    SELECT metric_name, SUM(metric_value)
                    FROM aggregated_metrics
                    WHERE window_start = ? AND src_ip = ?
                    GROUP BY metric_name
                ''', (ws, src_ip))
            else:
                cursor.execute('''
                    SELECT metric_name, SUM(metric_value)
                    FROM aggregated_metrics
                    WHERE window_start = ?
                    GROUP BY metric_name
                ''', (ws,))

            metrics_map = {}
            for name, val in cursor.fetchall():
                metrics_map[name] = val

            connections.append(metrics_map.get('connections_count', 0))
            unique_ports.append(metrics_map.get('unique_ports', 0))
            unique_dst_ips.append(metrics_map.get('unique_dst_ips', 0))
            total_bytes.append(metrics_map.get('total_bytes', 0))

        conn.close()

        return jsonify({
            'labels': labels,
            'datasets': {
                'connections_count': connections,
                'unique_ports': unique_ports,
                'unique_dst_ips': unique_dst_ips,
                'total_bytes': total_bytes
            }
        })
    except Exception as e:
        logger.error(f"Ошибка chart_traffic_metrics: {e}")
        return jsonify({'labels': [], 'datasets': {}}), 500


@app.route('/api/chart/top_hosts')
def chart_top_hosts():
    """API: Топ хостов по количеству алертов (для bar chart)"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT src_ip, COUNT(*) AS cnt
            FROM alerts
            GROUP BY src_ip
            ORDER BY cnt DESC
            LIMIT 10
        ''')
        rows = cursor.fetchall()
        conn.close()

        labels = [r[0] for r in rows]
        values = [r[1] for r in rows]

        return jsonify({'labels': labels, 'values': values})
    except Exception as e:
        logger.error(f"Ошибка chart_top_hosts: {e}")
        return jsonify({'labels': [], 'values': []}), 500


@app.route('/api/stats')
def get_stats():
    """API: Получение общей статистики системы"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Общее количество событий (raw_events может не существовать)
        total_events = 0
        try:
            cursor.execute("SELECT COUNT(*) FROM raw_events")
            total_events = cursor.fetchone()[0]
        except sqlite3.OperationalError:
            pass
        
        # Количество алертов (из обеих таблиц: alerts + suricata_alerts)
        total_alerts = 0
        recent_alerts = 0
        one_hour_ago = datetime.now().timestamp() - 3600
        
        try:
            cursor.execute("SELECT COUNT(*) FROM alerts")
            total_alerts += cursor.fetchone()[0]
            cursor.execute(
                "SELECT COUNT(*) FROM alerts WHERE timestamp > ?",
                (one_hour_ago,)
            )
            recent_alerts += cursor.fetchone()[0]
        except sqlite3.OperationalError:
            pass
        
        try:
            cursor.execute("SELECT COUNT(*) FROM suricata_alerts")
            total_alerts += cursor.fetchone()[0]
            cursor.execute(
                "SELECT COUNT(*) FROM suricata_alerts WHERE timestamp > ?",
                (one_hour_ago,)
            )
            recent_alerts += cursor.fetchone()[0]
        except sqlite3.OperationalError:
            pass
        
        # Количество отслеживаемых хостов
        total_hosts = 0
        try:
            cursor.execute("SELECT COUNT(DISTINCT src_ip) FROM aggregated_metrics")
            total_hosts = cursor.fetchone()[0]
        except sqlite3.OperationalError:
            pass
        
        conn.close()
        
        # Статистика обучения
        learning_stats = {'learning_hosts': 0, 'detection_hosts': 0}
        try:
            learning_stats = trainer.get_learning_statistics()
        except Exception:
            pass
        
        # Количество правил Suricata (из движка с БД, а не старого парсера)
        suricata_rules_count = 0
        try:
            rules_info = suricata_engine.get_rules_count()
            suricata_rules_count = rules_info.get('active', rules_info.get('total', 0))
        except Exception:
            suricata_rules_count = rule_parser.get_rules_count()
        
        return jsonify({
            'total_events': total_events,
            'total_alerts': total_alerts,
            'recent_alerts': recent_alerts,
            'total_hosts': total_hosts,
            'learning_hosts': learning_stats.get('learning_hosts', 0),
            'detection_hosts': learning_stats.get('detection_hosts', 0),
            'suricata_rules': suricata_rules_count,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Ошибка при получении статистики: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts')
def get_alerts():
    """API: Получение объединённого списка алертов (suricata + z-score + ML)"""
    try:
        limit = request.args.get('limit', 50, type=int)
        severity = request.args.get('severity', None, type=str)
        
        all_alerts = []
        
        # Алерты от Suricata
        try:
            suricata_alerts = suricata_engine.get_recent_alerts(limit=limit, severity=severity)
            for a in suricata_alerts:
                all_alerts.append({
                    'timestamp': a['timestamp'],
                    'src_ip': a.get('src_ip', 'N/A'),
                    'description': a.get('msg', a.get('description', 'Suricata alert')),
                    'score': 0,
                    'severity': a.get('severity', 'medium'),
                    'anomaly_type': 'suricata',
                    'source': 'suricata'
                })
        except Exception as e:
            logger.debug(f"Suricata alerts error: {e}")
        
        # Алерты от z-score детектора
        try:
            if anomaly_detector:
                stat_alerts = anomaly_detector.get_recent_alerts(limit=limit, severity=severity)
                for a in stat_alerts:
                    all_alerts.append({
                        'timestamp': a['timestamp'],
                        'src_ip': a.get('src_ip', 'N/A'),
                        'description': a.get('description', 'Anomaly alert'),
                        'score': a.get('score', 0),
                        'severity': a.get('severity', 'medium'),
                        'anomaly_type': a.get('anomaly_type', 'stat'),
                        'source': 'z-score'
                    })
        except Exception as e:
            logger.debug(f"Anomaly alerts error: {e}")
        
        # Алерты от ML-детектора
        try:
            if ml_detector:
                ml_alerts = ml_detector.get_recent_ml_alerts(limit=limit, severity=severity)
                for a in ml_alerts:
                    all_alerts.append({
                        'timestamp': a['timestamp'],
                        'src_ip': a.get('src_ip', 'N/A'),
                        'description': a.get('description', 'ML anomaly'),
                        'score': a.get('combined_score', a.get('ml_score', 0)),
                        'severity': a.get('severity', 'medium'),
                        'anomaly_type': a.get('anomaly_type', 'ml'),
                        'source': 'ml'
                    })
        except Exception as e:
            logger.debug(f"ML alerts error: {e}")
        
        # Сортируем по timestamp (новые первые) и обрезаем
        all_alerts.sort(key=lambda x: x['timestamp'], reverse=True)
        all_alerts = all_alerts[:limit]
        
        return jsonify({'alerts': all_alerts})
    except Exception as e:
        logger.error(f"Ошибка при получении алертов: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/hosts')
def get_hosts():
    """API: Получение списка отслеживаемых хостов"""
    try:
        profiles = trainer.get_all_profiles()
        
        hosts_data = []
        for profile in profiles:
            hosts_data.append({
                'src_ip': profile.src_ip,
                'is_learning': profile.is_learning,
                'samples_count': profile.samples_count,
                'connections_mean': round(profile.connections_mean, 2),
                'connections_std': round(profile.connections_std, 2),
                'unique_ports_mean': round(profile.unique_ports_mean, 2),
                'total_bytes_mean': round(profile.total_bytes_mean, 2),
                'last_updated': datetime.fromtimestamp(profile.last_updated).isoformat()
            })
            
        return jsonify({'hosts': hosts_data})
    except Exception as e:
        logger.error(f"Ошибка при получении хостов: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/host/<ip>')
def get_host_details(ip):
    """API: Получение детальной информации о хосте"""
    try:
        profile = trainer.get_host_profile(ip)
        
        if not profile:
            return jsonify({'error': 'Host not found'}), 404
            
        # Получаем последние метрики хоста (новая схема: metric_name / metric_value)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Получаем последние временные окна
        cursor.execute("""
            SELECT DISTINCT window_start, window_end
            FROM aggregated_metrics 
            WHERE src_ip = ? 
            ORDER BY window_end DESC 
            LIMIT 10
        """, (ip,))
        
        windows = cursor.fetchall()
        metrics = []
        for ws, we in windows:
            cursor.execute("""
                SELECT metric_name, metric_value
                FROM aggregated_metrics
                WHERE src_ip = ? AND window_start = ?
            """, (ip, ws))
            
            m = {}
            for name, val in cursor.fetchall():
                m[name] = val
            
            metrics.append({
                'window_end': datetime.fromtimestamp(we).isoformat() if we else '',
                'connections_count': m.get('connections_count', 0),
                'unique_ports': m.get('unique_ports', 0),
                'unique_dst_ips': m.get('unique_dst_ips', 0),
                'total_bytes': m.get('total_bytes', 0),
                'avg_packet_size': round(m.get('avg_packet_size', 0), 2)
            })
            
        # Получаем последние алерты для хоста
        cursor.execute("""
            SELECT timestamp, anomaly_type, score, severity, description
            FROM alerts 
            WHERE src_ip = ? 
            ORDER BY timestamp DESC 
            LIMIT 10
        """, (ip,))
        
        alerts = []
        for row in cursor.fetchall():
            alerts.append({
                'timestamp': datetime.fromtimestamp(row[0]).isoformat() if row[0] else '',
                'anomaly_type': row[1],
                'score': row[2],
                'severity': row[3],
                'description': row[4]
            })
            
        conn.close()
        
        return jsonify({
            'profile': {
                'src_ip': profile.src_ip,
                'is_learning': profile.is_learning,
                'samples_count': profile.samples_count,
                'connections_mean': round(profile.connections_mean, 2),
                'connections_std': round(profile.connections_std, 2),
                'unique_ports_mean': round(profile.unique_ports_mean, 2),
                'unique_ports_std': round(profile.unique_ports_std, 2),
                'unique_dst_ips_mean': round(profile.unique_dst_ips_mean, 2),
                'unique_dst_ips_std': round(profile.unique_dst_ips_std, 2),
                'total_bytes_mean': round(profile.total_bytes_mean, 2),
                'total_bytes_std': round(profile.total_bytes_std, 2),
                'last_updated': datetime.fromtimestamp(profile.last_updated).isoformat()
            },
            'recent_metrics': metrics,
            'recent_alerts': alerts
        })
    except Exception as e:
        logger.error(f"Ошибка при получении информации о хосте: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/host/<ip>/learning', methods=['POST'])
def set_host_learning_mode(ip):
    """API: Установка режима обучения для хоста"""
    try:
        data = request.get_json()
        enabled = data.get('enabled', True)
        
        trainer.set_learning_mode(ip, enabled)
        
        return jsonify({
            'success': True,
            'src_ip': ip,
            'learning_mode': enabled
        })
    except Exception as e:
        logger.error(f"Ошибка при установке режима обучения: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/host/<ip>/reset', methods=['POST'])
def reset_host_profile(ip):
    """API: Сброс профиля хоста"""
    try:
        trainer.reset_profile(ip)
        
        return jsonify({
            'success': True,
            'src_ip': ip,
            'message': 'Profile reset successfully'
        })
    except Exception as e:
        logger.error(f"Ошибка при сбросе профиля: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/suricata/rules')
def get_suricata_rules():
    """API: Получение всех правил Suricata из БД"""
    try:
        rules = suricata_engine.get_all_rules()
        counts = suricata_engine.get_rules_count()
        return jsonify({
            'rules': rules,
            'count': counts['total'],
            'active': counts['active']
        })
    except Exception as e:
        logger.error(f"Ошибка при получении правил Suricata: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/suricata/rules', methods=['POST'])
def add_suricata_rule():
    """API: Добавление нового правила Suricata (сохраняется в БД)"""
    try:
        data = request.get_json()
        rule_text = data.get('rule', '')
        category = data.get('category', 'custom')
        
        result = suricata_engine.add_rule(rule_text, category=category)
        
        if result:
            return jsonify({'success': True, 'rule': result})
        else:
            return jsonify({'error': 'Неверный формат правила. Пример: alert tcp any any -> any 80 (msg:"HTTP"; sid:2000001;)'}), 400
    except Exception as e:
        logger.error(f"Ошибка при добавлении правила: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/suricata/rules/bulk', methods=['POST'])
def add_suricata_rules_bulk():
    """API: Массовое добавление правил (текст с несколькими правилами)"""
    try:
        data = request.get_json()
        rules_text = data.get('rules', '')
        category = data.get('category', 'custom')
        
        count = suricata_engine.add_rules_from_text(rules_text, category=category)
        
        return jsonify({'success': True, 'added': count})
    except Exception as e:
        logger.error(f"Ошибка при массовом добавлении правил: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/suricata/rules/<int:sid>', methods=['DELETE'])
def delete_suricata_rule(sid):
    """API: Удаление правила по SID"""
    try:
        success = suricata_engine.delete_rule(sid)
        if success:
            return jsonify({'success': True, 'sid': sid})
        else:
            return jsonify({'error': f'Правило SID {sid} не найдено'}), 404
    except Exception as e:
        logger.error(f"Ошибка при удалении правила: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/suricata/rules/<int:sid>/toggle', methods=['POST'])
def toggle_suricata_rule(sid):
    """API: Включение/выключение правила"""
    try:
        data = request.get_json()
        enabled = data.get('enabled', True)
        
        success = suricata_engine.toggle_rule(sid, enabled)
        if success:
            return jsonify({'success': True, 'sid': sid, 'enabled': enabled})
        else:
            return jsonify({'error': f'Правило SID {sid} не найдено'}), 404
    except Exception as e:
        logger.error(f"Ошибка при переключении правила: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/suricata/alerts')
def get_suricata_alerts():
    """API: Получение алертов Suricata"""
    try:
        limit = request.args.get('limit', 50, type=int)
        severity = request.args.get('severity', None)
        src_ip = request.args.get('src_ip', None)
        
        alerts = suricata_engine.get_recent_alerts(
            limit=limit, severity=severity, src_ip=src_ip
        )
        
        # Форматируем timestamp для UI
        for alert in alerts:
            alert['timestamp_fmt'] = datetime.fromtimestamp(
                alert['timestamp']
            ).strftime('%Y-%m-%d %H:%M:%S')
        
        return jsonify({'alerts': alerts, 'count': len(alerts)})
    except Exception as e:
        logger.error(f"Ошибка при получении алертов Suricata: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/suricata/alerts/stats')
def get_suricata_alerts_stats():
    """API: Статистика алертов Suricata"""
    try:
        stats = suricata_engine.get_alerts_stats()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Ошибка при получении статистики: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/suricata/test', methods=['POST'])
def test_suricata_packet():
    """API: Тестовая проверка пакета по правилам (для отладки)"""
    try:
        packet = request.get_json()
        
        # Минимальная валидация
        required = ['src_ip', 'dst_ip', 'protocol']
        for field in required:
            if field not in packet:
                return jsonify({'error': f'Поле {field} обязательно'}), 400
        
        if 'timestamp' not in packet:
            packet['timestamp'] = datetime.now().timestamp()
        
        alerts = suricata_engine.check_packet(packet)
        
        return jsonify({
            'packet': packet,
            'alerts': alerts,
            'matched_rules': len(alerts)
        })
    except Exception as e:
        logger.error(f"Ошибка при тестировании пакета: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== API: Управление файлами правил ====================

@app.route('/api/suricata/rule-files')
def get_rule_files():
    """API: Список доступных файлов правил"""
    try:
        files = suricata_engine.get_available_rule_files(RULES_DIR)
        return jsonify({'files': files, 'rules_dir': RULES_DIR})
    except Exception as e:
        logger.error(f"Ошибка при получении списка файлов: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/suricata/rule-files/load', methods=['POST'])
def load_rule_file():
    """API: Загрузка правил из конкретного файла"""
    try:
        data = request.get_json()
        filename = data.get('filename', '')
        
        # Защита от path traversal
        if '..' in filename or '/' in filename or '\\' in filename:
            return jsonify({'error': 'Недопустимое имя файла'}), 400
        
        filepath = os.path.join(RULES_DIR, filename)
        if not os.path.exists(filepath):
            return jsonify({'error': f'Файл {filename} не найден'}), 404
        
        category = os.path.splitext(filename)[0]
        count = suricata_engine.add_rules_from_file(filepath, category=category)
        
        return jsonify({
            'success': True,
            'filename': filename,
            'category': category,
            'loaded': count
        })
    except Exception as e:
        logger.error(f"Ошибка при загрузке файла правил: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/suricata/rule-files/load-all', methods=['POST'])
def load_all_rule_files():
    """API: Загрузка всех файлов правил"""
    try:
        results = suricata_engine.load_rules_directory(RULES_DIR)
        total = sum(results.values())
        return jsonify({
            'success': True,
            'results': results,
            'total_loaded': total,
            'files_processed': len(results)
        })
    except Exception as e:
        logger.error(f"Ошибка при загрузке всех правил: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/suricata/rule-files/unload', methods=['POST'])
def unload_rule_file():
    """API: Удаление правил определённой категории"""
    try:
        data = request.get_json()
        category = data.get('category', '')
        
        if not category:
            return jsonify({'error': 'Категория не указана'}), 400
        
        deleted = suricata_engine.delete_rules_by_category(category)
        return jsonify({
            'success': True,
            'category': category,
            'deleted': deleted
        })
    except Exception as e:
        logger.error(f"Ошибка при выгрузке правил: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/suricata/rule-files/toggle', methods=['POST'])
def toggle_rule_file():
    """API: Включение/выключение всех правил категории"""
    try:
        data = request.get_json()
        category = data.get('category', '')
        enabled = data.get('enabled', True)
        
        affected = suricata_engine.toggle_category(category, enabled)
        return jsonify({
            'success': True,
            'category': category,
            'enabled': enabled,
            'affected': affected
        })
    except Exception as e:
        logger.error(f"Ошибка при переключении категории: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/suricata/categories')
def get_categories():
    """API: Статистика по категориям правил"""
    try:
        categories = suricata_engine.get_categories_stats()
        return jsonify({'categories': categories})
    except Exception as e:
        logger.error(f"Ошибка при получении категорий: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== API: Детектор аномалий (z-score) ====================

@app.route('/api/anomaly/alerts')
def get_anomaly_alerts():
    """API: Получение алертов детектора аномалий (z-score)"""
    try:
        if anomaly_detector is None:
            return jsonify({'error': 'Anomaly detector not initialized'}), 503
        
        limit = request.args.get('limit', 50, type=int)
        severity = request.args.get('severity', None)
        
        alerts = anomaly_detector.get_recent_alerts(limit=limit, severity=severity)
        return jsonify({'alerts': alerts, 'count': len(alerts)})
    except Exception as e:
        logger.error(f"Ошибка при получении алертов аномалий: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/anomaly/detect', methods=['POST'])
def run_anomaly_detection():
    """API: Запустить цикл детекции аномалий"""
    try:
        if anomaly_detector is None:
            return jsonify({'error': 'Anomaly detector not initialized'}), 503
        
        anomaly_detector.run_detection()
        return jsonify({'success': True, 'message': 'Detection cycle completed'})
    except Exception as e:
        logger.error(f"Ошибка при запуске детекции: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== API: ML-детектор (Isolation Forest) ====================

@app.route('/api/ml/status')
def get_ml_status():
    """API: Статус ML-модели"""
    try:
        if ml_detector is None:
            return jsonify({
                'available': False,
                'message': 'ML detector not available (install scikit-learn numpy)'
            })
        
        status = ml_detector.get_model_status()
        status['available'] = True
        return jsonify(status)
    except Exception as e:
        logger.error(f"Ошибка ML status: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ml/train', methods=['POST'])
def train_ml_model():
    """API: Обучить/переобучить ML-модель"""
    try:
        if ml_detector is None:
            return jsonify({'error': 'ML detector not available'}), 503
        
        data = request.get_json() or {}
        force = data.get('force', False)
        
        result = ml_detector.train(force=force)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Ошибка обучения ML: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ml/alerts')
def get_ml_alerts():
    """API: Получение ML-алертов"""
    try:
        if ml_detector is None:
            return jsonify({'alerts': [], 'count': 0, 'available': False})
        
        limit = request.args.get('limit', 50, type=int)
        severity = request.args.get('severity', None)
        src_ip = request.args.get('src_ip', None)
        
        alerts = ml_detector.get_recent_ml_alerts(
            limit=limit, severity=severity, src_ip=src_ip
        )
        return jsonify({'alerts': alerts, 'count': len(alerts), 'available': True})
    except Exception as e:
        logger.error(f"Ошибка ML alerts: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ml/alerts/stats')
def get_ml_alerts_stats():
    """API: Статистика ML-алертов"""
    try:
        if ml_detector is None:
            return jsonify({'available': False})
        
        stats = ml_detector.get_ml_alerts_stats()
        stats['available'] = True
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Ошибка ML alerts stats: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ml/training-history')
def get_ml_training_history():
    """API: История обучений ML-модели"""
    try:
        if ml_detector is None:
            return jsonify({'history': [], 'available': False})
        
        history = ml_detector.get_training_history()
        return jsonify({'history': history, 'available': True})
    except Exception as e:
        logger.error(f"Ошибка ML training history: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ml/collect', methods=['POST'])
def collect_ml_training_data():
    """API: Собрать обучающие данные из aggregated_metrics"""
    try:
        if ml_detector is None:
            return jsonify({'error': 'ML detector not available'}), 503
        
        added = ml_detector.collect_from_aggregated()
        total = ml_detector.get_training_sample_count()
        return jsonify({
            'success': True,
            'added': added,
            'total_samples': total,
            'min_required': ml_detector.min_training_samples
        })
    except Exception as e:
        logger.error(f"Ошибка сбора данных ML: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== API: Гибридный скоринг ====================

@app.route('/api/hybrid/status')
def get_hybrid_status():
    """API: Статус гибридного скорера (все три слоя)"""
    try:
        if hybrid_scorer is None:
            return jsonify({
                'available': False,
                'message': 'Hybrid scorer not available'
            })
        
        layers = hybrid_scorer.get_layer_status()
        stats = hybrid_scorer.get_hybrid_stats()
        return jsonify({
            'available': True,
            'layers': layers,
            'stats': stats,
            'weights': {
                'suricata': hybrid_scorer.w_sig,
                'stat': hybrid_scorer.w_stat,
                'ml': hybrid_scorer.w_ml
            }
        })
    except Exception as e:
        logger.error(f"Ошибка hybrid status: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/hybrid/verdicts')
def get_hybrid_verdicts():
    """API: Получение гибридных вердиктов"""
    try:
        if hybrid_scorer is None:
            return jsonify({'verdicts': [], 'count': 0, 'available': False})
        
        limit = request.args.get('limit', 50, type=int)
        severity = request.args.get('severity', None)
        src_ip = request.args.get('src_ip', None)
        
        verdicts = hybrid_scorer.get_recent_verdicts(
            limit=limit, severity=severity, src_ip=src_ip
        )
        return jsonify({'verdicts': verdicts, 'count': len(verdicts), 'available': True})
    except Exception as e:
        logger.error(f"Ошибка hybrid verdicts: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/hybrid/score', methods=['POST'])
def run_hybrid_scoring():
    """API: Запустить один цикл гибридного скоринга"""
    try:
        if hybrid_scorer is None:
            return jsonify({'error': 'Hybrid scorer not available'}), 503
        
        hybrid_scorer.run_scoring_cycle()
        return jsonify({'success': True, 'message': 'Scoring cycle completed'})
    except Exception as e:
        logger.error(f"Ошибка hybrid scoring: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/hybrid/train-ml', methods=['POST'])
def hybrid_train_ml():
    """API: Обучить ML-модель через гибридный скорер"""
    try:
        if hybrid_scorer is None:
            return jsonify({'error': 'Hybrid scorer not available'}), 503
        
        result = hybrid_scorer.auto_train_ml()
        if result is None:
            return jsonify({'status': 'error', 'message': 'ML detector not available in scorer'})
        return jsonify(result)
    except Exception as e:
        logger.error(f"Ошибка обучения через hybrid: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/monitoring')
def monitoring():
    """Страница мониторинга в реальном времени"""
    return render_template('monitoring.html')


@app.route('/hosts')
def hosts():
    """Страница со списком хостов"""
    return render_template('hosts.html')


@app.route('/alerts')
def alerts():
    """Страница с алертами"""
    return render_template('alerts.html')


@app.route('/rules')
def rules():
    """Страница с правилами Suricata"""
    return render_template('rules.html')


@app.route('/training')
def training():
    """Страница управления обучением и ML"""
    return render_template('training.html')


@app.route('/hybrid')
def hybrid():
    """Страница гибридного анализа (три слоя)"""
    return render_template('hybrid.html')


def start_web_interface(host='127.0.0.1', port=5000, debug=False, db_path="ids.db"):
    """
    Запуск веб-интерфейса
    
    Args:
        host: Хост для прослушивания
              '127.0.0.1' - только локальный доступ (рекомендуется)
              '0.0.0.0' - доступ со всех интерфейсов (ВНИМАНИЕ: небезопасно в публичных сетях)
        port: Порт для прослушивания
        debug: Режим отладки Flask
        db_path: Путь к базе данных
    """
    global DB_PATH
    DB_PATH = db_path
    
    # Инициализация компонентов
    init_components()
    
    logger.info(f"Запуск веб-интерфейса на http://{host}:{port}")
    
    # Запуск Flask приложения
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    import argparse
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    parser = argparse.ArgumentParser(description='IDS Web Interface')
    parser.add_argument('--host', default='127.0.0.1', 
                       help='Host to listen on (default: 127.0.0.1 for local only, use 0.0.0.0 for all interfaces)')
    parser.add_argument('--port', type=int, default=5000, help='Port to listen on')
    parser.add_argument('--db', default='ids.db', help='Database path')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    start_web_interface(
        host=args.host,
        port=args.port,
        debug=args.debug,
        db_path=args.db
    )
