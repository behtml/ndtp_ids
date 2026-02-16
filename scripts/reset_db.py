#!/usr/bin/env python3
"""
Сброс базы данных и модели — чистый старт
Удаляет ids.db и ml_model.pkl, создаёт пустую БД.

Запуск:
    python scripts/reset_db.py
    python scripts/reset_db.py --db my_ids.db
    python scripts/reset_db.py --keep-model   # не удалять ML-модель
"""
import os
import sys
import sqlite3
import argparse

# Путь к корню проекта
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def reset_database(db_path: str = "ids.db",
                   model_path: str = "ml_model.pkl",
                   keep_model: bool = False):
    """Сброс БД и ML-модели"""

    print("=" * 50)
    print("СБРОС NDTP IDS")
    print("=" * 50)

    # Удаляем старую БД
    if os.path.exists(db_path):
        os.remove(db_path)
        print(f"[OK] Удалена БД: {db_path}")
    else:
        print(f"[--] БД не найдена: {db_path}")

    # Удаляем ML-модель
    if not keep_model:
        if os.path.exists(model_path):
            os.remove(model_path)
            print(f"[OK] Удалена модель: {model_path}")
        else:
            print(f"[--] Модель не найдена: {model_path}")
    else:
        print(f"[--] Модель сохранена: {model_path}")

    # Создаём пустую БД (таблицы создадутся при запуске компонентов)
    conn = sqlite3.connect(db_path)
    conn.close()
    print(f"[OK] Создана чистая БД: {db_path}")

    print()
    print("Готово! Теперь запускайте компоненты:")
    print("  python scripts/run_all.py")
    print("  или по отдельности — см. README.md")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Сброс базы данных NDTP IDS"
    )
    parser.add_argument("--db", default="ids.db", help="Путь к БД (по умолчанию: ids.db)")
    parser.add_argument("--model", default="ml_model.pkl", help="Путь к ML-модели")
    parser.add_argument("--keep-model", action="store_true", help="Не удалять ML-модель")

    args = parser.parse_args()

    os.chdir(PROJECT_ROOT)
    reset_database(db_path=args.db, model_path=args.model, keep_model=args.keep_model)
