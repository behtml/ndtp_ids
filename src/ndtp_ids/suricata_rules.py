"""
Модуль для парсинга и применения правил Suricata
Интеграция с поведенческим анализом для гибридной IDS
"""
import re
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class SuricataRule:
    """Представление правила Suricata"""
    action: str  # alert, drop, reject, pass
    protocol: str  # tcp, udp, icmp, ip
    src_ip: str
    src_port: str
    direction: str  # -> или <>
    dst_ip: str
    dst_port: str
    options: Dict[str, str]
    sid: int
    msg: str
    raw_rule: str
    
    
class SuricataRuleParser:
    """
    Парсер правил Suricata
    
    Пример правила:
    alert tcp any any -> any 80 (msg:"HTTP Request"; sid:1000001;)
    """
    
    def __init__(self):
        self.rules: List[SuricataRule] = []
        
    def parse_rule(self, rule_text: str) -> Optional[SuricataRule]:
        """
        Парсинг одного правила Suricata
        
        Args:
            rule_text: Текст правила
            
        Returns:
            SuricataRule или None если парсинг не удался
        """
        rule_text = rule_text.strip()
        
        # Игнорируем комментарии и пустые строки
        if not rule_text or rule_text.startswith('#'):
            return None
            
        # Основной regex для парсинга правила
        pattern = r'^(\w+)\s+(\w+)\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)\s+\((.*)\)$'
        match = re.match(pattern, rule_text)
        
        if not match:
            logger.warning(f"Не удалось распарсить правило: {rule_text}")
            return None
            
        action, protocol, src_ip, src_port, direction, dst_ip, dst_port, options_str = match.groups()
        
        # Парсинг опций
        options = {}
        msg = ""
        sid = 0
        
        # Парсим все опции: key:"value" и key:value
        # Сначала извлекаем опции с кавычками
        quoted_pattern = r'([\w-]+):\s*"([^"]*)"'
        for opt_match in re.finditer(quoted_pattern, options_str):
            key, value = opt_match.groups()
            options[key] = value
            if key == "msg":
                msg = value
        
        # Затем извлекаем опции без кавычек (classtype, rev, flow, app-layer-event и т.д.)
        # Разбиваем по ; и парсим каждую опцию
        for opt_part in options_str.split(';'):
            opt_part = opt_part.strip()
            if not opt_part or '"' in opt_part:
                continue  # пропускаем пустые и уже обработанные с кавычками
            if ':' in opt_part:
                key, _, value = opt_part.partition(':')
                key = key.strip()
                value = value.strip()
                if key and value and key not in options:
                    options[key] = value
        
        # Извлечение sid
        sid_match = re.search(r'sid:\s*(\d+)', options_str)
        if sid_match:
            sid = int(sid_match.group(1))
            
        return SuricataRule(
            action=action,
            protocol=protocol,
            src_ip=src_ip,
            src_port=src_port,
            direction=direction,
            dst_ip=dst_ip,
            dst_port=dst_port,
            options=options,
            sid=sid,
            msg=msg,
            raw_rule=rule_text
        )
        
    def load_rules_from_file(self, filepath: str) -> int:
        """
        Загрузка правил из файла
        
        Args:
            filepath: Путь к файлу с правилами
            
        Returns:
            Количество загруженных правил
        """
        count = 0
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                accumulated = ""
                for line in f:
                    stripped = line.rstrip('\n\r')
                    if stripped.endswith('\\'):
                        # Строка продолжается на следующей строке
                        accumulated += stripped[:-1].rstrip() + " "
                        continue
                    accumulated += stripped
                    rule = self.parse_rule(accumulated)
                    accumulated = ""
                    if rule:
                        self.rules.append(rule)
                        count += 1
                # На случай если файл заканчивается строкой с \
                if accumulated.strip():
                    rule = self.parse_rule(accumulated)
                    if rule:
                        self.rules.append(rule)
                        count += 1
            logger.info(f"Загружено {count} правил из {filepath}")
        except FileNotFoundError:
            logger.error(f"Файл не найден: {filepath}")
        except Exception as e:
            logger.error(f"Ошибка при загрузке правил: {e}")
            
        return count
        
    def load_rules_from_text(self, rules_text: str) -> int:
        """
        Загрузка правил из текста
        
        Args:
            rules_text: Текст с правилами (построчно)
            
        Returns:
            Количество загруженных правил
        """
        count = 0
        for line in rules_text.split('\n'):
            rule = self.parse_rule(line)
            if rule:
                self.rules.append(rule)
                count += 1
        return count
        
    def match_packet(self, packet_event: Dict) -> List[Tuple[SuricataRule, str]]:
        """
        Проверка пакета на соответствие правилам
        
        Args:
            packet_event: Словарь с данными пакета (из packet_collector)
            
        Returns:
            Список кортежей (правило, причина срабатывания)
        """
        matches = []
        
        for rule in self.rules:
            # Проверка протокола
            if rule.protocol.lower() != 'ip' and rule.protocol.lower() != packet_event.get('protocol', '').lower():
                continue
                
            # Проверка src_ip
            if not self._match_ip(rule.src_ip, packet_event.get('src_ip', '')):
                continue
                
            # Проверка dst_ip
            if not self._match_ip(rule.dst_ip, packet_event.get('dst_ip', '')):
                continue
                
            # Проверка портов
            if not self._match_port(rule.src_port, packet_event.get('src_port')):
                continue
                
            if not self._match_port(rule.dst_port, packet_event.get('dst_port')):
                continue
                
            # Правило сработало
            reason = f"Suricata Rule {rule.sid}: {rule.msg}"
            matches.append((rule, reason))
            
        return matches
        
    def _match_ip(self, rule_ip: str, packet_ip: str) -> bool:
        """Проверka соответствия IP адреса правилу"""
        if rule_ip == 'any':
            return True
            
        # Простое сравнение
        if rule_ip == packet_ip:
            return True
            
        # Проверка на CIDR с использованием ipaddress
        if '/' in rule_ip:
            try:
                import ipaddress
                network = ipaddress.ip_network(rule_ip, strict=False)
                if ipaddress.ip_address(packet_ip) in network:
                    return True
            except (ValueError, TypeError):
                # Фолбэк: упрощённая проверка по префиксу
                network_prefix = rule_ip.split('/')[0].rsplit('.', 1)[0]
                if packet_ip.startswith(network_prefix):
                    return True
                
        return False
        
    def _match_port(self, rule_port: str, packet_port: Optional[int]) -> bool:
        """Проверка соответствия порта правилу"""
        if rule_port == 'any':
            return True
            
        if packet_port is None:
            return rule_port == 'any'
            
        # Проверка на конкретный порт
        if rule_port.isdigit() and int(rule_port) == packet_port:
            return True
            
        # Проверка диапазона портов (например, 1024:65535)
        if ':' in rule_port and not rule_port.startswith('['):
            try:
                start, end = map(int, rule_port.split(':'))
                if start <= packet_port <= end:
                    return True
            except ValueError:
                pass
        
        # Проверка Suricata bracket-синтаксиса: [1-1024], [5900:5999]
        if rule_port.startswith('[') and rule_port.endswith(']'):
            inner = rule_port[1:-1]  # убираем скобки
            # Диапазон через дефис: [1-1024]
            if '-' in inner:
                try:
                    start, end = map(int, inner.split('-', 1))
                    if start <= packet_port <= end:
                        return True
                except ValueError:
                    pass
            # Диапазон через двоеточие: [5900:5999]
            if ':' in inner:
                try:
                    start, end = map(int, inner.split(':', 1))
                    if start <= packet_port <= end:
                        return True
                except ValueError:
                    pass
            # Список портов: [80,443,8080]
            if ',' in inner:
                try:
                    ports = [int(p.strip()) for p in inner.split(',')]
                    if packet_port in ports:
                        return True
                except ValueError:
                    pass
                
        return False
        
    def get_rules_by_protocol(self, protocol: str) -> List[SuricataRule]:
        """Получение правил для конкретного протокола"""
        return [rule for rule in self.rules if rule.protocol.lower() == protocol.lower() or rule.protocol.lower() == 'ip']
        
    def get_rules_count(self) -> int:
        """Получение общего количества правил"""
        return len(self.rules)


# Примеры правил Suricata для сетевых атак
DEFAULT_RULES = """
alert tcp any any -> any 22 (msg:"SSH Connection Attempt"; sid:1000001;)
alert tcp any any -> any 23 (msg:"Telnet Connection Attempt"; sid:1000002;)
alert tcp any any -> any [1-1024] (msg:"Connection to Privileged Port"; sid:1000003;)
alert tcp any any -> any any (msg:"High Connection Rate"; threshold:type both,track by_src,count 50,seconds 10; sid:1000004;)
alert udp any any -> any 53 (msg:"DNS Request"; sid:1000005;)
alert icmp any any -> any any (msg:"ICMP Ping"; sid:1000006;)
alert tcp any any -> any 3389 (msg:"RDP Connection Attempt"; sid:1000007;)
alert tcp any any -> any 445 (msg:"SMB Connection"; sid:1000008;)
alert tcp any any -> any 135 (msg:"RPC Connection"; sid:1000009;)
alert tcp any any -> any [5900:5999] (msg:"VNC Connection Attempt"; sid:1000010;)
"""


if __name__ == "__main__":
    # Пример использования
    logging.basicConfig(level=logging.INFO)
    
    parser = SuricataRuleParser()
    count = parser.load_rules_from_text(DEFAULT_RULES)
    print(f"Загружено {count} правил")
    
    # Тестовый пакет
    test_packet = {
        'src_ip': '192.168.1.100',
        'dst_ip': '8.8.8.8',
        'src_port': 54321,
        'dst_port': 22,
        'protocol': 'TCP'
    }
    
    matches = parser.match_packet(test_packet)
    for rule, reason in matches:
        print(f"Сработало: {reason}")
