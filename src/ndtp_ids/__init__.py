"""
Система обнаружения вторжений

Модульная система обнаружения вторжений, включающая:
- packet_collector: Коллектор пакетов для захвата сетевого трафика
- aggregator: Агрегатор метрик по временным окнам
- suricata_engine: Движок IDS на основе правил Suricata
- anomaly_detector: Детектор аномалий (z-score)
- ml_detector: ML-детектор аномалий (Isolation Forest)
- hybrid_scorer: Гибридный скорер (3 слоя детекции)
"""

__version__ = "0.1.0"

from ndtp_ids.packet_collector import start_collector, process_packet, PacketEvent
from ndtp_ids.aggregator import MetricsAggregator, run_aggregator
from ndtp_ids.suricata_engine import SuricataEngine
from ndtp_ids.suricata_rules import SuricataRuleParser, SuricataRule
from ndtp_ids.anomaly_detector import AnomalyDetector

try:
    from ndtp_ids.ml_detector import MLAnomalyDetector, MLAlert
    from ndtp_ids.hybrid_scorer import HybridScorer, HybridVerdict
    _ml_available = True
except ImportError:
    _ml_available = False

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
    
    # Anomaly Detector
    "AnomalyDetector",
    
    # ML (optional, requires scikit-learn)
    "MLAnomalyDetector",
    "MLAlert",
    "HybridScorer",
    "HybridVerdict",
]
