#!/bin/bash
# Остановка всех компонентов NDTP IDS

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PID_DIR="pids"

echo -e "\n${RED}🛑 Stopping NDTP IDS...${NC}\n"

if [ ! -d "$PID_DIR" ]; then
    echo -e "${YELLOW}⚠${NC} No PID directory found. System may not be running."
    exit 0
fi

STOPPED_COUNT=0
FAILED_COUNT=0

for pidfile in "$PID_DIR"/*.pid; do
    if [ -f "$pidfile" ]; then
        component=$(basename "$pidfile" .pid)
        pid=$(cat "$pidfile" 2>/dev/null)
        
        if [ -n "$pid" ]; then
            if kill -0 "$pid" 2>/dev/null; then
                echo -e "  ${YELLOW}→${NC} Stopping $component (PID: $pid)..."
                if kill "$pid" 2>/dev/null; then
                    # Ждем завершения процесса
                    for i in {1..5}; do
                        if ! kill -0 "$pid" 2>/dev/null; then
                            break
                        fi
                        sleep 1
                    done
                    
                    # Проверяем, завершился ли процесс
                    if kill -0 "$pid" 2>/dev/null; then
                        # Принудительное завершение
                        echo -e "  ${YELLOW}→${NC} Force stopping $component..."
                        kill -9 "$pid" 2>/dev/null || true
                    fi
                    
                    echo -e "  ${GREEN}✓${NC} Stopped $component"
                    STOPPED_COUNT=$((STOPPED_COUNT + 1))
                else
                    echo -e "  ${RED}✗${NC} Failed to stop $component"
                    FAILED_COUNT=$((FAILED_COUNT + 1))
                fi
            else
                echo -e "  ${YELLOW}⚠${NC} $component was not running (stale PID)"
            fi
        fi
        rm -f "$pidfile"
    fi
done

echo ""
if [ $STOPPED_COUNT -gt 0 ]; then
    echo -e "${GREEN}✓${NC} Stopped $STOPPED_COUNT component(s)"
fi

if [ $FAILED_COUNT -gt 0 ]; then
    echo -e "${RED}✗${NC} Failed to stop $FAILED_COUNT component(s)"
    exit 1
fi

if [ $STOPPED_COUNT -eq 0 ] && [ $FAILED_COUNT -eq 0 ]; then
    echo -e "${YELLOW}⚠${NC} No running components found"
else
    echo -e "${GREEN}✓${NC} All components stopped successfully"
fi

echo ""
