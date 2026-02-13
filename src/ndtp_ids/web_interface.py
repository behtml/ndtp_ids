"""
Веб-интерфейс для NDTP IDS
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
try:
    from .anomaly_detector import AnomalyDetector
    from .adaptive_trainer import AdaptiveTrainer
    from .suricata_rules import SuricataRuleParser, DEFAULT_RULES
    from .suricata_engine import SuricataEngine
except ImportError:
    # Для запуска как standalone скрипт
    import sys
    sys.path.insert(0, os.path.dirname(__file__))
    from anomaly_detector import AnomalyDetector
    from adaptive_trainer import AdaptiveTrainer
    from suricata_rules import SuricataRuleParser, DEFAULT_RULES
    from suricata_engine import SuricataEngine

logger = logging.getLogger(__name__)

# Инициализация Flask приложения
app = Flask(__name__)
# Security: Use environment variable for SECRET_KEY in production
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'ndtp-ids-secret-key-change-in-production')

# Глобальные переменные для компонентов системы
DB_PATH = "ndtp_ids.db"
detector = None
trainer = None
rule_parser = None
suricata_engine = None


def init_components():
    """Инициализация компонентов системы"""
    global detector, trainer, rule_parser, suricata_engine
    
    detector = AnomalyDetector(db_path=DB_PATH)
    trainer = AdaptiveTrainer(db_path=DB_PATH)
    rule_parser = SuricataRuleParser()
    
    # Загружаем базовые правила Suricata (в старый парсер для совместимости)
    rule_parser.load_rules_from_text(DEFAULT_RULES)
    
    # Инициализируем Suricata Engine с БД-хранилищем правил
    suricata_engine = SuricataEngine(db_path=DB_PATH)
    suricata_engine.load_default_rules()
    
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

        # Считаем алерты по часам за последние 24 часа
        cursor.execute('''
            SELECT CAST((timestamp - ?) / 3600 AS INTEGER) AS hour_bucket,
                   COUNT(*) AS cnt,
                   SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical,
                   SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) AS high,
                   SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) AS medium,
                   SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) AS low
            FROM alerts
            WHERE timestamp > ?
            GROUP BY hour_bucket
            ORDER BY hour_bucket
        ''', (day_ago, day_ago))

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
        cursor.execute('''
            SELECT severity, COUNT(*) FROM alerts GROUP BY severity
        ''')
        rows = cursor.fetchall()
        conn.close()

        labels = []
        values = []
        for row in rows:
            labels.append(row[0])
            values.append(row[1])

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
        
        # Общее количество событий
        cursor.execute("SELECT COUNT(*) FROM raw_events")
        total_events = cursor.fetchone()[0]
        
        # Количество алертов
        cursor.execute("SELECT COUNT(*) FROM alerts")
        total_alerts = cursor.fetchone()[0]
        
        # Алерты за последний час
        one_hour_ago = datetime.now().timestamp() - 3600
        cursor.execute(
            "SELECT COUNT(*) FROM alerts WHERE timestamp > ?",
            (one_hour_ago,)
        )
        recent_alerts = cursor.fetchone()[0]
        
        # Количество отслеживаемых хостов
        cursor.execute("SELECT COUNT(DISTINCT src_ip) FROM aggregated_metrics")
        total_hosts = cursor.fetchone()[0]
        
        conn.close()
        
        # Статистика обучения
        learning_stats = trainer.get_learning_statistics()
        
        # Количество правил Suricata
        suricata_rules_count = rule_parser.get_rules_count()
        
        return jsonify({
            'total_events': total_events,
            'total_alerts': total_alerts,
            'recent_alerts': recent_alerts,
            'total_hosts': total_hosts,
            'learning_hosts': learning_stats['learning_hosts'],
            'detection_hosts': learning_stats['detection_hosts'],
            'suricata_rules': suricata_rules_count,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Ошибка при получении статистики: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts')
def get_alerts():
    """API: Получение списка алертов"""
    try:
        limit = request.args.get('limit', 50, type=int)
        severity = request.args.get('severity', None, type=str)
        
        alerts = detector.get_recent_alerts(limit=limit, severity=severity)
        
        alerts_data = []
        for alert in alerts:
            alerts_data.append({
                'timestamp': datetime.fromtimestamp(alert.timestamp).isoformat(),
                'src_ip': alert.src_ip,
                'anomaly_type': alert.anomaly_type,
                'score': round(alert.score, 2),
                'current_value': round(alert.current_value, 2),
                'mean_value': round(alert.mean_value, 2),
                'severity': alert.severity,
                'description': alert.description
            })
            
        return jsonify({'alerts': alerts_data})
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
            
        # Получаем последние метрики хоста
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM aggregated_metrics 
            WHERE src_ip = ? 
            ORDER BY window_end DESC 
            LIMIT 10
        """, (ip,))
        
        metrics = []
        for row in cursor.fetchall():
            metrics.append({
                'window_end': datetime.fromtimestamp(row[2]).isoformat(),
                'connections_count': row[3],
                'unique_ports': row[4],
                'unique_dst_ips': row[5],
                'total_bytes': row[6],
                'avg_packet_size': round(row[7], 2)
            })
            
        # Получаем последние алерты для хоста
        cursor.execute("""
            SELECT * FROM alerts 
            WHERE src_ip = ? 
            ORDER BY timestamp DESC 
            LIMIT 10
        """, (ip,))
        
        alerts = []
        for row in cursor.fetchall():
            alerts.append({
                'timestamp': datetime.fromtimestamp(row[1]).isoformat(),
                'anomaly_type': row[3],
                'severity': row[9],
                'description': row[10]
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
    """Страница управления обучением"""
    return render_template('training.html')


def start_web_interface(host='127.0.0.1', port=5000, debug=False, db_path="ndtp_ids.db"):
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
    
    parser = argparse.ArgumentParser(description='NDTP IDS Web Interface')
    parser.add_argument('--host', default='127.0.0.1', 
                       help='Host to listen on (default: 127.0.0.1 for local only, use 0.0.0.0 for all interfaces)')
    parser.add_argument('--port', type=int, default=5000, help='Port to listen on')
    parser.add_argument('--db', default='ndtp_ids.db', help='Database path')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    start_web_interface(
        host=args.host,
        port=args.port,
        debug=args.debug,
        db_path=args.db
    )
