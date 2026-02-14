#!/bin/bash
# Проверка статуса компонентов NDTP IDS

# Цвета для вывода
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

PID_DIR="pids"
DB_PATH="ndtp_ids.db"
WEB_PORT=5000

echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  📊 NDTP IDS Status${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

# Функция проверки процесса
check_process() {
    local name=$1
    local pidfile="$PID_DIR/$name.pid"
    
    if [ -f "$pidfile" ]; then
        pid=$(cat "$pidfile" 2>/dev/null)
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            # Получаем информацию о процессе
            if command -v ps &> /dev/null; then
                cpu_mem=$(ps -p "$pid" -o %cpu,%mem --no-headers 2>/dev/null | awk '{print "CPU: " $1 "%, MEM: " $2 "%"}')
                echo -e "${GREEN}✓${NC} $name (PID: $pid) - ${GREEN}Running${NC}"
                echo -e "  ${cpu_mem}"
            else
                echo -e "${GREEN}✓${NC} $name (PID: $pid) - ${GREEN}Running${NC}"
            fi
            return 0
        else
            echo -e "${RED}✗${NC} $name - ${RED}Stopped${NC} (stale PID)"
            return 1
        fi
    else
        echo -e "${RED}✗${NC} $name - ${RED}Not running${NC}"
        return 1
    fi
}

echo "Components:"
echo "───────────"
check_process "collector_aggregator"
check_process "detector"
check_process "web"

echo ""
echo "Services:"
echo "─────────"

# Проверка веб-интерфейса
if command -v curl &> /dev/null; then
    if curl -s -o /dev/null -w "%{http_code}" http://localhost:$WEB_PORT/api/stats 2>/dev/null | grep -q "200"; then
        echo -e "${GREEN}✓${NC} Web Interface - ${GREEN}Accessible${NC} (http://localhost:$WEB_PORT)"
    else
        echo -e "${RED}✗${NC} Web Interface - ${RED}Not accessible${NC}"
    fi
else
    echo -e "${YELLOW}⚠${NC} curl not found, skipping web interface check"
fi

echo ""
echo "Database:"
echo "─────────"

# Проверка БД
if [ -f "$DB_PATH" ]; then
    size=$(du -h "$DB_PATH" 2>/dev/null | cut -f1)
    echo -e "${GREEN}✓${NC} Database exists - ${size}"
    
    # Проверяем количество записей если sqlite3 доступен
    if command -v sqlite3 &> /dev/null; then
        events=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM raw_events" 2>/dev/null || echo "N/A")
        metrics=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM aggregated_metrics" 2>/dev/null || echo "N/A")
        alerts=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM alerts" 2>/dev/null || echo "N/A")
        
        echo -e "  Raw events: ${events}"
        echo -e "  Metrics: ${metrics}"
        echo -e "  Alerts: ${alerts}"
    fi
else
    echo -e "${RED}✗${NC} Database not found"
fi

echo ""
echo "Logs:"
echo "─────"

# Проверка логов
if [ -d "logs" ]; then
    echo -e "${GREEN}✓${NC} Logs directory exists"
    for log in logs/*.log; do
        if [ -f "$log" ]; then
            size=$(du -h "$log" 2>/dev/null | cut -f1)
            lines=$(wc -l < "$log" 2>/dev/null || echo "0")
            echo -e "  $(basename "$log"): ${size} (${lines} lines)"
        fi
    done
else
    echo -e "${YELLOW}⚠${NC} Logs directory not found"
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

# Подсказки
if [ ! -f "$PID_DIR/collector_aggregator.pid" ] && [ ! -f "$PID_DIR/detector.pid" ] && [ ! -f "$PID_DIR/web.pid" ]; then
    echo -e "${YELLOW}ℹ${NC}  System is not running. Start with: ${CYAN}./start_ids.sh${NC}"
    echo ""
fi
