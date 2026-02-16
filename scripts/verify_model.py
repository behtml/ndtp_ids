#!/usr/bin/env python3
"""
Проверка обученной ML-модели

Показывает:
- Параметры Isolation Forest
- Scaler и его статистики
- Feature names
- Время обучения
- Тестовый прогон на примерных данных

Запуск:
    python scripts/verify_model.py
    python scripts/verify_model.py --model ml_model.pkl
"""
import os
import sys
import pickle
import argparse

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def verify_model(model_path: str = "ml_model.pkl"):
    """Проверка сохранённой ML-модели"""

    if not os.path.exists(model_path):
        print(f"[!] Модель не найдена: {model_path}")
        print("    Сначала обучите модель:")
        print("      python -m ndtp_ids.ml_detector --db ids.db --train")
        print("      или: http://127.0.0.1:5000/training → «Обучить»")
        return

    print("=" * 55)
    print("ПРОВЕРКА ML-МОДЕЛИ")
    print("=" * 55)

    with open(model_path, 'rb') as f:
        data = pickle.load(f)

    print(f"\n  Файл: {model_path} ({os.path.getsize(model_path)} bytes)")
    print(f"  Время обучения: {data.get('trained_at', '?')}")

    # Модель
    model = data.get('model')
    if model:
        print(f"\n  --- Isolation Forest ---")
        print(f"  Класс:         {type(model).__name__}")
        print(f"  N estimators:  {model.n_estimators}")
        print(f"  Contamination: {model.contamination}")
        print(f"  Max samples:   {model.max_samples}")
        print(f"  Max features:  {model.max_features}")
        print(f"  Random state:  {model.random_state}")
    else:
        print(f"\n  [!] Модель отсутствует в файле")

    # Scaler
    scaler = data.get('scaler')
    if scaler:
        print(f"\n  --- StandardScaler ---")
        print(f"  Класс:  {type(scaler).__name__}")
        feature_names = data.get('feature_names', [])
        if hasattr(scaler, 'mean_') and scaler.mean_ is not None:
            print(f"  Признаки и их статистики:")
            for i, name in enumerate(feature_names):
                mean_val = scaler.mean_[i] if i < len(scaler.mean_) else '?'
                scale_val = scaler.scale_[i] if i < len(scaler.scale_) else '?'
                print(f"    {name:25s}  mean={mean_val:10.2f}  std={scale_val:10.2f}")
    else:
        print(f"\n  [!] Scaler отсутствует в файле")

    # Feature names
    feature_names = data.get('feature_names', [])
    print(f"\n  Признаки: {feature_names}")

    # Прочие данные
    for key in data:
        if key not in ('model', 'scaler', 'feature_names', 'trained_at'):
            val = data[key]
            if not hasattr(val, '__len__') or len(str(val)) < 100:
                print(f"  {key}: {val}")

    # Тестовый прогон
    if model and scaler:
        print(f"\n  --- Тестовый прогон ---")
        try:
            import numpy as np

            # Нормальный трафик
            normal = np.array([[10, 3, 2, 5000, 500]])   # мало всего
            normal_scaled = scaler.transform(normal)
            normal_pred = model.predict(normal_scaled)
            normal_score = model.decision_function(normal_scaled)

            # Аномальный трафик
            anomaly = np.array([[500, 100, 50, 500000, 100]])  # много всего
            anomaly_scaled = scaler.transform(anomaly)
            anomaly_pred = model.predict(anomaly_scaled)
            anomaly_score = model.decision_function(anomaly_scaled)

            print(f"  Нормальный вектор:  {normal[0].tolist()}")
            print(f"    Prediction: {'NORMAL' if normal_pred[0] == 1 else 'ANOMALY'}")
            print(f"    Decision score: {normal_score[0]:.4f}")
            print()
            print(f"  Аномальный вектор:  {anomaly[0].tolist()}")
            print(f"    Prediction: {'NORMAL' if anomaly_pred[0] == 1 else 'ANOMALY'}")
            print(f"    Decision score: {anomaly_score[0]:.4f}")

            if anomaly_pred[0] == -1:
                print(f"\n  ✅ Модель корректно распознаёт аномалию!")
            else:
                print(f"\n  ⚠️  Модель не распознала аномалию — возможно мало обучающих данных")

        except ImportError:
            print(f"  [!] numpy не установлен, тестовый прогон невозможен")
        except Exception as e:
            print(f"  [!] Ошибка тестового прогона: {e}")

    print("\n" + "=" * 55)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Проверка ML-модели NDTP IDS")
    parser.add_argument("--model", default="ml_model.pkl", help="Путь к файлу модели")
    args = parser.parse_args()

    os.chdir(PROJECT_ROOT)
    verify_model(model_path=args.model)
