"""
Suricata Rule Engine — модуль обнаружения угроз на основе правил Suricata

Проверяет каждый пакет по загруженным правилам, генерирует алерты
и сохраняет их в базу данных. Поддерживает:
- Загрузку правил из файлов и текста
- Хранение правил в SQLite для персистентности
- Проверку пакетов в реальном времени
- Генерацию алертов с привязкой к SID правила
"""
import sqlite3
import sys
import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

try:
    from .suricata_rules import SuricataRuleParser, SuricataRule, DEFAULT_RULES
except ImportError:
    from suricata_rules import SuricataRuleParser, SuricataRule, DEFAULT_RULES


class SuricataEngine:
    """
    Движок IDS на основе правил Suricata.
    
    Хранит правила в БД, проверяет пакеты, генерирует алерты.
    """
    
    def __init__(self, db_path: str = "ids.db"):
        self.db_path = db_path
        self.parser = SuricataRuleParser()
        self.init_database()
        self._load_rules_from_db()
    
    def init_database(self):
        """Создание таблиц для правил и алертов Suricata"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Таблица для хранения правил Suricata
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS suricata_rules (
                    sid INTEGER PRIMARY KEY,
                    action TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    src_port TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    dst_port TEXT NOT NULL,
                    msg TEXT NOT NULL,
                    options TEXT,
                    raw_rule TEXT NOT NULL,
                    enabled BOOLEAN DEFAULT 1,
                    category TEXT DEFAULT 'custom',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Таблица для алертов Suricata
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS suricata_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    sid INTEGER NOT NULL,
                    src_ip TEXT NOT NULL,
                    src_port INTEGER,
                    dst_ip TEXT NOT NULL,
                    dst_port INTEGER,
                    protocol TEXT NOT NULL,
                    action TEXT NOT NULL,
                    msg TEXT NOT NULL,
                    severity TEXT DEFAULT 'medium',
                    raw_packet TEXT,
                    resolved BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Индексы
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_suricata_alerts_timestamp
                ON suricata_alerts(timestamp)
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_suricata_alerts_sid
                ON suricata_alerts(sid)
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_suricata_alerts_src_ip
                ON suricata_alerts(src_ip)
            ''')
            
            conn.commit()
            conn.close()
            print("[SuricataEngine] Database initialized", file=sys.stderr)
        except Exception as e:
            print(f"[SuricataEngine] DB init error: {e}", file=sys.stderr)
    
    # ==================== Управление правилами ====================
    
    def _load_rules_from_db(self):
        """Загрузка правил из БД в память парсера"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT raw_rule, enabled FROM suricata_rules')
        rows = cursor.fetchall()
        conn.close()
        
        self.parser.rules.clear()
        for raw_rule, enabled in rows:
            if enabled:
                rule = self.parser.parse_rule(raw_rule)
                if rule:
                    self.parser.rules.append(rule)
        
        print(f"[SuricataEngine] Loaded {len(self.parser.rules)} rules from DB", file=sys.stderr)
    
    def load_default_rules(self):
        """Загрузка правил по умолчанию (если БД пуста)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM suricata_rules')
        count = cursor.fetchone()[0]
        conn.close()
        
        if count == 0:
            self.add_rules_from_text(DEFAULT_RULES, category='default')
            print(f"[SuricataEngine] Default rules loaded", file=sys.stderr)
    
    def add_rule(self, rule_text: str, category: str = 'custom') -> Optional[Dict]:
        """
        Добавление одного правила
        
        Args:
            rule_text: Текст правила Suricata
            category: Категория правила (default, custom, imported)
            
        Returns:
            Словарь с данными правила или None если ошибка
        """
        rule = self.parser.parse_rule(rule_text.strip())
        if not rule:
            return None
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO suricata_rules
                (sid, action, protocol, src_ip, src_port, direction, dst_ip, dst_port,
                 msg, options, raw_rule, enabled, category)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
            ''', (
                rule.sid, rule.action, rule.protocol,
                rule.src_ip, rule.src_port, rule.direction,
                rule.dst_ip, rule.dst_port, rule.msg,
                json.dumps(rule.options), rule.raw_rule, category
            ))
            conn.commit()
            conn.close()
            
            # Перезагружаем правила в память
            self._load_rules_from_db()
            
            return {
                'sid': rule.sid,
                'action': rule.action,
                'protocol': rule.protocol,
                'msg': rule.msg,
                'src_ip': rule.src_ip,
                'src_port': rule.src_port,
                'dst_ip': rule.dst_ip,
                'dst_port': rule.dst_port,
                'raw_rule': rule.raw_rule,
                'category': category
            }
        except Exception as e:
            conn.close()
            print(f"[SuricataEngine] Error adding rule: {e}", file=sys.stderr)
            return None
    
    def add_rules_from_text(self, text: str, category: str = 'custom') -> int:
        """Добавление нескольких правил из текста"""
        count = 0
        for line in text.strip().split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                result = self.add_rule(line, category=category)
                if result:
                    count += 1
        return count
    
    def add_rules_from_file(self, filepath: str, category: str = 'imported') -> int:
        """Загрузка правил из файла"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                text = f.read()
            return self.add_rules_from_text(text, category=category)
        except Exception as e:
            print(f"[SuricataEngine] Error loading file {filepath}: {e}", file=sys.stderr)
            return 0
    
    def delete_rule(self, sid: int) -> bool:
        """Удаление правила по SID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM suricata_rules WHERE sid = ?', (sid,))
        affected = cursor.rowcount
        conn.commit()
        conn.close()
        
        if affected > 0:
            self._load_rules_from_db()
        return affected > 0
    
    def toggle_rule(self, sid: int, enabled: bool) -> bool:
        """Включение/выключение правила"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE suricata_rules SET enabled = ? WHERE sid = ?',
            (1 if enabled else 0, sid)
        )
        affected = cursor.rowcount
        conn.commit()
        conn.close()
        
        if affected > 0:
            self._load_rules_from_db()
        return affected > 0
    
    def get_all_rules(self) -> List[Dict]:
        """Получение всех правил из БД"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT sid, action, protocol, src_ip, src_port, direction,
                   dst_ip, dst_port, msg, raw_rule, enabled, category, created_at
            FROM suricata_rules
            ORDER BY sid
        ''')
        rows = cursor.fetchall()
        conn.close()
        
        rules = []
        for row in rows:
            rules.append({
                'sid': row[0],
                'action': row[1],
                'protocol': row[2],
                'src_ip': row[3],
                'src_port': row[4],
                'direction': row[5],
                'dst_ip': row[6],
                'dst_port': row[7],
                'msg': row[8],
                'raw_rule': row[9],
                'enabled': bool(row[10]),
                'category': row[11],
                'created_at': row[12]
            })
        return rules
    
    def get_rules_count(self) -> Dict:
        """Количество правил (всего / активных)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM suricata_rules')
        total = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM suricata_rules WHERE enabled = 1')
        active = cursor.fetchone()[0]
        conn.close()
        return {'total': total, 'active': active}
    
    # ==================== Проверка пакетов ====================
    
    def check_packet(self, packet_event: Dict) -> List[Dict]:
        """
        Проверка пакета по всем активным правилам
        
        Args:
            packet_event: Словарь с данными пакета из коллектора
            
        Returns:
            Список сработавших алертов
        """
        matches = self.parser.match_packet(packet_event)
        
        alerts = []
        for rule, reason in matches:
            alert = {
                'timestamp': packet_event.get('timestamp', time.time()),
                'sid': rule.sid,
                'src_ip': packet_event.get('src_ip', ''),
                'src_port': packet_event.get('src_port'),
                'dst_ip': packet_event.get('dst_ip', ''),
                'dst_port': packet_event.get('dst_port'),
                'protocol': packet_event.get('protocol', ''),
                'action': rule.action,
                'msg': rule.msg,
                'severity': self._get_severity_from_rule(rule),
                'reason': reason
            }
            
            # Сохраняем алерт в БД
            self._save_alert(alert)
            alerts.append(alert)
        
        return alerts
    
    def _get_severity_from_rule(self, rule: SuricataRule) -> str:
        """Определение серьёзности по правилу"""
        # Критические порты
        critical_ports = {'23', '445', '135', '3389'}  # telnet, smb, rpc, rdp
        high_ports = {'22', '5900', '5901'}  # ssh, vnc
        
        if rule.dst_port in critical_ports:
            return 'critical'
        if rule.dst_port in high_ports:
            return 'high'
        if rule.action in ('drop', 'reject'):
            return 'high'
        return 'medium'
    
    def _save_alert(self, alert: Dict):
        """Сохранение алерта Suricata в БД"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO suricata_alerts
                (timestamp, sid, src_ip, src_port, dst_ip, dst_port,
                 protocol, action, msg, severity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert['timestamp'],
                alert['sid'],
                alert['src_ip'],
                alert['src_port'],
                alert['dst_ip'],
                alert['dst_port'],
                alert['protocol'],
                alert['action'],
                alert['msg'],
                alert['severity']
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[SuricataEngine] Error saving alert: {e}", file=sys.stderr)
    
    # ==================== Получение алертов ====================
    
    def get_recent_alerts(self, limit: int = 50, severity: str = None,
                         src_ip: str = None) -> List[Dict]:
        """Получение последних алертов Suricata"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = 'SELECT id, timestamp, sid, src_ip, src_port, dst_ip, dst_port, protocol, action, msg, severity, resolved FROM suricata_alerts'
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
        conn.close()
        
        return [{
            'id': r[0],
            'timestamp': r[1],
            'sid': r[2],
            'src_ip': r[3],
            'src_port': r[4],
            'dst_ip': r[5],
            'dst_port': r[6],
            'protocol': r[7],
            'action': r[8],
            'msg': r[9],
            'severity': r[10],
            'resolved': bool(r[11])
        } for r in rows]
    
    def get_alerts_stats(self) -> Dict:
        """Статистика алертов для дашборда"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM suricata_alerts')
        total = cursor.fetchone()[0]
        
        one_hour_ago = datetime.now().timestamp() - 3600
        cursor.execute('SELECT COUNT(*) FROM suricata_alerts WHERE timestamp > ?', (one_hour_ago,))
        last_hour = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT severity, COUNT(*) FROM suricata_alerts
            GROUP BY severity
        ''')
        by_severity = {r[0]: r[1] for r in cursor.fetchall()}
        
        cursor.execute('''
            SELECT sid, msg, COUNT(*) as cnt FROM suricata_alerts
            GROUP BY sid ORDER BY cnt DESC LIMIT 5
        ''')
        top_rules = [{'sid': r[0], 'msg': r[1], 'count': r[2]} for r in cursor.fetchall()]
        
        conn.close()
        
        return {
            'total': total,
            'last_hour': last_hour,
            'by_severity': by_severity,
            'top_rules': top_rules
        }


def run_suricata_ids(db_path: str = "ids.db", input_stream=None):
    """
    Запуск IDS: читает JSON-события из stdin (от коллектора) и проверяет по правилам
    
    Использование:
        python packet_collector.py | python -m suricata_engine
    """
    import sys
    
    if input_stream is None:
        input_stream = sys.stdin
    
    engine = SuricataEngine(db_path=db_path)
    engine.load_default_rules()
    
    rules_count = engine.get_rules_count()
    print(f"[SuricataIDS] Started with {rules_count['active']} active rules")
    print(f"[SuricataIDS] Database: {db_path}")
    print("[SuricataIDS] Waiting for packets from collector...")
    
    alert_count = 0
    packet_count = 0
    
    try:
        for line in input_stream:
            line = line.strip()
            if not line or line.startswith('['):
                continue
            
            try:
                packet = json.loads(line)
                packet_count += 1
                
                alerts = engine.check_packet(packet)
                
                for alert in alerts:
                    alert_count += 1
                    severity = alert['severity'].upper()
                    print(
                        f"[ALERT #{alert_count}] [{severity}] SID:{alert['sid']} "
                        f"{alert['src_ip']}:{alert['src_port']} -> "
                        f"{alert['dst_ip']}:{alert['dst_port']} "
                        f"| {alert['msg']}",
                        file=sys.stderr
                    )
                
                if packet_count % 100 == 0:
                    print(
                        f"[SuricataIDS] Processed: {packet_count} packets, "
                        f"{alert_count} alerts",
                        file=sys.stderr
                    )
                    
            except json.JSONDecodeError:
                continue
                
    except KeyboardInterrupt:
        print(f"\n[SuricataIDS] Stopped. Total: {packet_count} packets, {alert_count} alerts")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Suricata Rule Engine — сигнатурный анализ пакетов"
    )
    parser.add_argument(
        "--db", default="ids.db",
        help="Путь к базе данных SQLite (по умолчанию: ids.db)"
    )
    
    args = parser.parse_args()
    run_suricata_ids(db_path=args.db)
