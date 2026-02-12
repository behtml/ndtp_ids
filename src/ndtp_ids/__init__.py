"""
NDTP IDS - Network Data Traffic Processing Intrusion Detection System

Модульная система обнаружения вторжений, включающая:
- packet_collector: Коллектор пакетов для захвата сетевого трафика
- aggregator: Агрегатор метрик по временным окнам
- anomaly_detector: Детектор аномалий на основе z-score метода
"""

__version__ = "0.1.0"

from ndtp_ids.packet_collector import start_collector, process_packet, PacketEvent
from ndtp_ids.aggregator import MetricsAggregator, run_aggregator
from ndtp_ids.anomaly_detector import AnomalyDetector, run_detector, Alert

__all__ = [
    # Packet Collector
    "start_collector",
    "process_packet",
    "PacketEvent",
    
    # Aggregator
    "MetricsAggregator",
    "run_aggregator",
    
    # Anomaly Detector
    "AnomalyDetector",
    "run_detector",
    "Alert",
]
