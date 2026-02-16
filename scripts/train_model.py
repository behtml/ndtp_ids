#!/usr/bin/env python3
"""
Обучение / переобучение ML-модели

Запуск:
    python scripts/train_model.py               # обучить (если ещё не обучена)
    python scripts/train_model.py --force        # переобучить принудительно
    python scripts/train_model.py --collect      # сначала собрать данные, потом обучить
"""
import os
import sys
import argparse

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, 'src'))


def train_model(db_path: str = "ids.db",
                model_path: str = "ml_model.pkl",
                force: bool = False,
                collect: bool = False):
    """Обучение ML-модели"""

    try:
        from ndtp_ids.ml_detector import MLAnomalyDetector
    except ImportError:
        print("[!] Не удалось импортировать MLAnomalyDetector")
        print("    Установите: pip install scikit-learn numpy")
        return

    detector = MLAnomalyDetector(db_path=db_path, model_path=model_path)

    print("=" * 55)
    print("ОБУЧЕНИЕ ML-МОДЕЛИ")
    print("=" * 55)

    # Статус до обучения
    status = detector.get_model_status()
    print(f"\n  Модель: {'обучена' if status['is_trained'] else 'не обучена'}")
    print(f"  Training samples: {status['training_samples']} / {status['min_required']}")

    # Сбор данных
    if collect:
        print(f"\n  Сбор данных из aggregated_metrics...")
        n = detector.collect_from_aggregated()
        print(f"  Собрано: {n} новых samples")

        status = detector.get_model_status()
        print(f"  Всего samples: {status['training_samples']}")

    # Проверка готовности
    if status['training_samples'] < status['min_required']:
        print(f"\n  [!] Недостаточно данных для обучения!")
        print(f"      Нужно: {status['min_required']}, есть: {status['training_samples']}")
        print(f"      Продолжайте сбор трафика.")
        return

    # Обучение
    print(f"\n  Обучение{'(принудительное)' if force else ''}...")
    result = detector.train(force=force)

    if result.get('status') == 'trained':
        print(f"\n  ✅ Модель обучена!")
        print(f"     Samples:     {result.get('n_samples', '?')}")
        print(f"     Features:    {result.get('n_features', '?')}")
        print(f"     Аномалий:    {result.get('anomalies_in_training', '?')}")
        print(f"     Файл модели: {model_path}")
        print(f"\n  Проверка: python scripts/verify_model.py")
    elif result.get('status') == 'already_trained':
        print(f"\n  Модель уже обучена. Для переобучения: --force")
    else:
        print(f"\n  [!] Ошибка: {result}")

    print("=" * 55)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Обучение ML-модели NDTP IDS")
    parser.add_argument("--db", default="ids.db", help="Путь к БД")
    parser.add_argument("--model", default="ml_model.pkl", help="Путь к файлу модели")
    parser.add_argument("--force", action="store_true", help="Переобучить принудительно")
    parser.add_argument("--collect", action="store_true",
                        help="Сначала собрать данные из aggregated_metrics")
    args = parser.parse_args()

    os.chdir(PROJECT_ROOT)
    train_model(db_path=args.db, model_path=args.model,
                force=args.force, collect=args.collect)
