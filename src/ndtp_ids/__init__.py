"""
Система обнаружения вторжений

Модульная система обнаружения вторжений, включающая:
- packet_collector: Коллектор пакетов для захвата сетевого трафика
- aggregator: Агрегатор метрик по временным окнам
- suricata_engine: Движок IDS на основе правил Suricata
"""

__version__ = "0.1.0"

from ndtp_ids.packet_collector import start_collector, process_packet, PacketEvent
from ndtp_ids.aggregator import MetricsAggregator, run_aggregator
from ndtp_ids.suricata_engine import SuricataEngine
from ndtp_ids.suricata_rules import SuricataRuleParser, SuricataRule

__all__ = [
    # Packet Collector
    "start_collector",
    "process_packet",
    "PacketEvent",
    
    # Aggregator
    "MetricsAggregator",
    "run_aggregator",
    
    # Suricata Engine
    "SuricataEngine",
    "SuricataRuleParser",
    "SuricataRule",
]
