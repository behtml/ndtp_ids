# scripts/

Утилиты и вспомогательные скрипты для NDTP IDS.

## Структура

| Скрипт | Назначение |
|---|---|
| `run_all.py` | Запуск всех компонентов IDS одной командой |
| `reset_db.py` | Сброс БД и ML-модели (чистый старт) |
| `generate_normal_traffic.py` | Генерация нормального трафика для обучения |
| `train_model.py` | Обучение / переобучение ML-модели |
| `verify_model.py` | Проверка обученной ML-модели |
| `check_progress.py` | Мониторинг прогресса сбора данных |
| `check_results.py` | Просмотр результатов детекции |
| `attack_simulator.py` | Симулятор атак для тестирования |

## Быстрый старт

```bash
# 1. Чистый старт
python scripts/reset_db.py

# 2. Запуск всех компонентов (окно 1 минута для быстрого обучения)
python scripts/run_all.py --window 1

# 3. (Опционально) Генерация трафика для обучения
python scripts/generate_normal_traffic.py --fast --duration 30

# 4. Проверка прогресса
python scripts/check_progress.py

# 5. Обучение ML-модели (когда samples >= 50)
python scripts/train_model.py --collect --force

# 6. Проверка модели
python scripts/verify_model.py

# 7. Тестирование — запуск атак
python scripts/attack_simulator.py --attack all

# 8. Проверка результатов
python scripts/check_results.py
```
