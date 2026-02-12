#!/usr/bin/env python3
"""
Пример интеграции всех компонентов NDTP IDS:
- Suricata правила
- Поведенческий анализ
- Адаптивное обучение
- Веб-интерфейс
"""
import sys
import os

# Добавляем путь к модулям
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from ndtp_ids.suricata_rules import SuricataRuleParser, DEFAULT_RULES
from ndtp_ids.adaptive_trainer import AdaptiveTrainer
from ndtp_ids.anomaly_detector import AnomalyDetector
from ndtp_ids.aggregator import MetricsAggregator
import time


def demo_suricata_rules():
    """Демонстрация работы с правилами Suricata"""
    print("=" * 60)
    print("ДЕМО: Suricata Rules Integration")
    print("=" * 60)
    
    parser = SuricataRuleParser()
    count = parser.load_rules_from_text(DEFAULT_RULES)
    print(f"✓ Загружено {count} базовых правил Suricata\n")
    
    # Тестовые пакеты
    test_packets = [
        {
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
            'src_port': 54321,
            'dst_port': 22,
            'protocol': 'TCP'
        },
        {
            'src_ip': '192.168.1.101',
            'dst_ip': '10.0.0.1',
            'src_port': 12345,
            'dst_port': 3389,
            'protocol': 'TCP'
        },
        {
            'src_ip': '192.168.1.102',
            'dst_ip': '1.1.1.1',
            'src_port': 50000,
            'dst_port': 80,
            'protocol': 'TCP'
        }
    ]
    
    print("Проверка пакетов на соответствие правилам:\n")
    for i, packet in enumerate(test_packets, 1):
        print(f"Пакет {i}: {packet['src_ip']}:{packet['src_port']} → "
              f"{packet['dst_ip']}:{packet['dst_port']} ({packet['protocol']})")
        
        matches = parser.match_packet(packet)
        if matches:
            for rule, reason in matches:
                print(f"  🚨 ALERT: {reason}")
        else:
            print(f"  ✓ OK: Правила не сработали")
        print()


def demo_adaptive_learning():
    """Демонстрация адаптивного обучения"""
    print("=" * 60)
    print("ДЕМО: Adaptive Learning & Training")
    print("=" * 60)
    
    trainer = AdaptiveTrainer(
        db_path='/tmp/demo_training.db',
        learning_window=10,  # Упрощаем для демо
        ewma_alpha=0.15
    )
    
    test_ip = "192.168.1.100"
    
    print(f"Симуляция обучения для хоста {test_ip}\n")
    
    # Фаза 1: Нормальное обучение
    print("Фаза 1: Обучение на нормальном поведении")
    for i in range(12):
        metrics = {
            'connections_count': 10 + i % 3,
            'unique_ports': 3,
            'unique_dst_ips': 2,
            'total_bytes': 5000 + i * 100,
            'avg_packet_size': 500
        }
        trainer.add_metrics_sample(test_ip, metrics, is_anomaly=False)
        
        if i % 3 == 0:
            profile = trainer.get_host_profile(test_ip)
            if profile:
                status = "Обучение" if profile.is_learning else "Детекция"
                print(f"  [{i+1:2d}] Наблюдений: {profile.samples_count:2d} | "
                      f"Режим: {status} | "
                      f"Соединений (μ): {profile.connections_mean:.1f}")
    
    print()
    profile = trainer.get_host_profile(test_ip)
    print(f"✓ Обучение завершено!")
    print(f"  Профиль хоста {test_ip}:")
    print(f"    - Соединений: {profile.connections_mean:.2f} ± {profile.connections_std:.2f}")
    print(f"    - Портов: {profile.unique_ports_mean:.2f} ± {profile.unique_ports_std:.2f}")
    print(f"    - Режим: {'Обучение' if profile.is_learning else 'Детекция'}")
    print()
    
    # Фаза 2: Детекция аномалии
    print("Фаза 2: Попытка добавить аномальное наблюдение")
    anomaly_metrics = {
        'connections_count': 50,  # Резкий всплеск!
        'unique_ports': 20,
        'unique_dst_ips': 15,
        'total_bytes': 50000,
        'avg_packet_size': 500
    }
    
    result = trainer.add_metrics_sample(test_ip, anomaly_metrics, is_anomaly=True)
    if not result:
        print("  ⚠️  Аномальное наблюдение отклонено (защита от обучения на атаках)")
    print()
    
    # Статистика
    stats = trainer.get_learning_statistics()
    print(f"Общая статистика обучения:")
    print(f"  Всего хостов: {stats['total_hosts']}")
    print(f"  В режиме обучения: {stats['learning_hosts']}")
    print(f"  В режиме детекции: {stats['detection_hosts']}")
    print()


def demo_hybrid_detection():
    """Демонстрация гибридной детекции (Suricata + Behavioral)"""
    print("=" * 60)
    print("ДЕМО: Hybrid Detection (Suricata + Behavioral)")
    print("=" * 60)
    
    # Инициализация компонентов
    parser = SuricataRuleParser()
    parser.load_rules_from_text(DEFAULT_RULES)
    
    detector = AnomalyDetector(db_path='/tmp/demo_detection.db', z_threshold=2.0)
    aggregator = MetricsAggregator(db_path='/tmp/demo_detection.db', window_minutes=1)
    
    print("✓ Система инициализирована")
    print(f"  - Правил Suricata: {len(parser.rules)}")
    print(f"  - Z-score порог: 2.0")
    print()
    
    # Симуляция событий
    test_events = [
        # Нормальный трафик
        {
            'timestamp': time.time(),
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
            'src_port': 54321,
            'dst_port': 443,
            'protocol': 'TCP',
            'packet_size': 1500,
            'direction': 'out'
        },
        # SSH подключение (Suricata alert)
        {
            'timestamp': time.time(),
            'src_ip': '192.168.1.100',
            'dst_ip': '10.0.0.50',
            'src_port': 54322,
            'dst_port': 22,
            'protocol': 'TCP',
            'packet_size': 1200,
            'direction': 'out'
        },
        # RDP подключение (Suricata alert)
        {
            'timestamp': time.time(),
            'src_ip': '192.168.1.100',
            'dst_ip': '10.0.0.51',
            'src_port': 54323,
            'dst_port': 3389,
            'protocol': 'TCP',
            'packet_size': 1300,
            'direction': 'out'
        }
    ]
    
    print("Обработка событий:\n")
    for i, event in enumerate(test_events, 1):
        print(f"Событие {i}: {event['src_ip']} → {event['dst_ip']}:{event['dst_port']}")
        
        # Проверка правилами Suricata
        matches = parser.match_packet(event)
        if matches:
            for rule, reason in matches:
                print(f"  🔴 Suricata: {reason}")
        
        # Агрегация для поведенческого анализа
        aggregator.process_event(event)
        print()
    
    print("✓ События обработаны")
    print("\nГибридная система сочетает:")
    print("  1. Сигнатурный анализ (Suricata) - известные атаки")
    print("  2. Поведенческий анализ - аномалии и zero-day")
    print()


def demo_web_interface_info():
    """Информация о веб-интерфейсе"""
    print("=" * 60)
    print("ДЕМО: Web Interface")
    print("=" * 60)
    
    print("Для запуска веб-интерфейса используйте:")
    print()
    print("  python -m ndtp_ids.web_interface --port 5000")
    print()
    print("Или с помощью скрипта:")
    print()
    print("  cd /home/runner/work/ndtp_ids/ndtp_ids")
    print("  python src/ndtp_ids/web_interface.py")
    print()
    print("После запуска откройте в браузере:")
    print("  http://localhost:5000")
    print()
    print("Доступные страницы:")
    print("  /          - Dashboard с общей статистикой")
    print("  /hosts     - Список отслеживаемых хостов")
    print("  /alerts    - История алертов")
    print("  /rules     - Правила Suricata")
    print("  /training  - Управление режимом обучения")
    print()


def main():
    """Запуск всех демонстраций"""
    print("\n" + "=" * 60)
    print("NDTP IDS - Интегрированная демонстрация")
    print("Suricata Rules + Behavioral Analysis + Adaptive Learning")
    print("=" * 60 + "\n")
    
    try:
        # 1. Suricata правила
        demo_suricata_rules()
        time.sleep(1)
        
        # 2. Адаптивное обучение
        demo_adaptive_learning()
        time.sleep(1)
        
        # 3. Гибридная детекция
        demo_hybrid_detection()
        time.sleep(1)
        
        # 4. Веб-интерфейс
        demo_web_interface_info()
        
        print("=" * 60)
        print("Демонстрация завершена успешно!")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n❌ Ошибка: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
