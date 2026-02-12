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
except ImportError:
    # Для запуска как standalone скрипт
    import sys
    sys.path.insert(0, os.path.dirname(__file__))
    from anomaly_detector import AnomalyDetector
    from adaptive_trainer import AdaptiveTrainer
    from suricata_rules import SuricataRuleParser, DEFAULT_RULES

logger = logging.getLogger(__name__)

# Инициализация Flask приложения
app = Flask(__name__)
app.config['SECRET_KEY'] = 'ndtp-ids-secret-key-change-in-production'

# Глобальные переменные для компонентов системы
DB_PATH = "ndtp_ids.db"
detector = None
trainer = None
rule_parser = None


def init_components():
    """Инициализация компонентов системы"""
    global detector, trainer, rule_parser
    
    detector = AnomalyDetector(db_path=DB_PATH)
    trainer = AdaptiveTrainer(db_path=DB_PATH)
    rule_parser = SuricataRuleParser()
    
    # Загружаем базовые правила Suricata
    rule_parser.load_rules_from_text(DEFAULT_RULES)
    
    logger.info("Компоненты системы инициализированы")


@app.route('/')
def index():
    """Главная страница - дашборд"""
    return render_template('dashboard.html')


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
    """API: Получение списка правил Suricata"""
    try:
        rules_data = []
        for rule in rule_parser.rules:
            rules_data.append({
                'sid': rule.sid,
                'action': rule.action,
                'protocol': rule.protocol,
                'msg': rule.msg,
                'src_ip': rule.src_ip,
                'src_port': rule.src_port,
                'dst_ip': rule.dst_ip,
                'dst_port': rule.dst_port
            })
            
        return jsonify({'rules': rules_data, 'count': len(rules_data)})
    except Exception as e:
        logger.error(f"Ошибка при получении правил Suricata: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/suricata/rules', methods=['POST'])
def add_suricata_rule():
    """API: Добавление нового правила Suricata"""
    try:
        data = request.get_json()
        rule_text = data.get('rule', '')
        
        rule = rule_parser.parse_rule(rule_text)
        
        if rule:
            rule_parser.rules.append(rule)
            return jsonify({
                'success': True,
                'rule': {
                    'sid': rule.sid,
                    'msg': rule.msg
                }
            })
        else:
            return jsonify({'error': 'Invalid rule format'}), 400
            
    except Exception as e:
        logger.error(f"Ошибка при добавлении правила: {e}")
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


def start_web_interface(host='0.0.0.0', port=5000, debug=False, db_path="ndtp_ids.db"):
    """
    Запуск веб-интерфейса
    
    Args:
        host: Хост для прослушивания (по умолчанию 0.0.0.0 - все интерфейсы)
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
    parser.add_argument('--host', default='0.0.0.0', help='Host to listen on')
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
