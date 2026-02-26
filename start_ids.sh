#!/bin/bash
# NDTP IDS System Launcher
# Запуск всех компонентов системы обнаружения вторжений

set -e

# Цвета для вывода
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Конфигурация по умолчанию
INTERFACE="auto"
WEB_PORT=5000
THRESHOLD=3.0
WINDOW=10
DB_PATH="ndtp_ids.db"
LOG_DIR="logs"
PID_DIR="pids"
RUN_COLLECTOR=true
RUN_WEB=true
DEBUG_MODE=false

# Функции для вывода
print_header() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1" >&2
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

show_help() {
    cat << EOF
NDTP IDS System Launcher

Usage: ./start_ids.sh [OPTIONS]

OPTIONS:
  --interface <name>     Network interface for packet capture (default: auto-detect)
  --port <port>          Web interface port (default: 5000)
  --threshold <value>    Anomaly detection threshold (default: 3.0)
  --window <minutes>     Aggregation window in minutes (default: 10)
  --no-collector         Start without packet collector
  --no-web               Start without web interface
  --debug                Enable debug mode
  --help                 Show this help message

EXAMPLES:
  # Basic start
  ./start_ids.sh

  # With custom settings
  ./start_ids.sh --interface eth0 --port 8080 --threshold 2.5

  # Without collector (no sudo required)
  ./start_ids.sh --no-collector

  # Debug mode
  ./start_ids.sh --debug

EOF
}

# Проверка окружения
check_environment() {
    print_info "Checking environment..."
    
    # Проверка Python
    if ! command -v python &> /dev/null && ! command -v python3 &> /dev/null; then
        print_error "Python is not installed"
        exit 1
    fi
    
    # Определение команды Python
    if command -v python3 &> /dev/null; then
        PYTHON_CMD="python3"
    else
        PYTHON_CMD="python"
    fi
    
    # Проверка версии Python
    PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
    print_success "Python $PYTHON_VERSION found"
    
    # Проверка установки пакета ndtp_ids
    if ! $PYTHON_CMD -c "import ndtp_ids" 2>/dev/null; then
        print_warning "ndtp_ids package not installed, attempting to install..."
        if [ -f "pyproject.toml" ]; then
            pip install -e . || {
                print_error "Failed to install ndtp_ids package"
                exit 1
            }
        else
            print_error "ndtp_ids package not found. Please install it first."
            exit 1
        fi
    fi
    print_success "ndtp_ids package is available"
    
    # Проверка зависимостей
    if ! $PYTHON_CMD -c "import scapy" 2>/dev/null; then
        print_error "scapy is not installed. Run: pip install scapy"
        exit 1
    fi
    
    if ! $PYTHON_CMD -c "import flask" 2>/dev/null; then
        print_error "flask is not installed. Run: pip install flask"
        exit 1
    fi
    
    print_success "All dependencies are available"
    
    # Проверка прав sudo для коллектора
    if [ "$RUN_COLLECTOR" = true ]; then
        if [ "$EUID" -ne 0 ] && ! sudo -n true 2>/dev/null; then
            print_warning "Packet collector requires sudo privileges"
            print_info "You may need to enter your password..."
            if ! sudo -v; then
                print_error "Cannot obtain sudo privileges"
                print_info "Run with --no-collector to skip packet capture"
                exit 1
            fi
        fi
        print_success "Sudo privileges available"
    fi
    
    # Определение сетевого интерфейса
    if [ "$INTERFACE" = "auto" ]; then
        # Попытка автоопределения интерфейса
        if command -v ip &> /dev/null; then
            INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
        elif command -v route &> /dev/null; then
            INTERFACE=$(route -n | grep '^0.0.0.0' | awk '{print $8}' | head -n1)
        fi
        
        if [ -z "$INTERFACE" ] || [ "$INTERFACE" = "auto" ]; then
            INTERFACE="eth0"
            print_warning "Could not auto-detect interface, using $INTERFACE"
        else
            print_success "Auto-detected interface: $INTERFACE"
        fi
    fi
}

# Создание директорий
setup_directories() {
    print_info "Setting up directories..."
    mkdir -p "$LOG_DIR" "$PID_DIR"
    print_success "Directories created: $LOG_DIR, $PID_DIR"
}

# Инициализация БД
init_database() {
    print_info "Initializing database..."
    if [ ! -f "$DB_PATH" ]; then
        $PYTHON_CMD -c "from ndtp_ids.init_db import init_database; init_database('$DB_PATH')" 2>/dev/null || {
            print_error "Failed to initialize database"
            exit 1
        }
        print_success "Database initialized: $DB_PATH"
    else
        print_success "Database already exists: $DB_PATH"
    fi
}

# Запуск коллектора + агрегатора
start_collector_aggregator() {
    if [ "$RUN_COLLECTOR" = true ]; then
        print_info "Starting Packet Collector + Aggregator..."
        
        sudo $PYTHON_CMD -m ndtp_ids.packet_collector --interface "$INTERFACE" 2>> "$LOG_DIR/collector.log" | \
        $PYTHON_CMD -m ndtp_ids.aggregator --db "$DB_PATH" --window "$WINDOW" >> "$LOG_DIR/aggregator.log" 2>&1 &
        
        COLLECTOR_PID=$!
        echo $COLLECTOR_PID > "$PID_DIR/collector_aggregator.pid"
        print_success "Collector+Aggregator started (PID: $COLLECTOR_PID)"
        sleep 2
    fi
}

# Запуск детектора аномалий
start_detector() {
    print_info "Starting Anomaly Detector..."
    
    $PYTHON_CMD -m ndtp_ids.anomaly_detector --db "$DB_PATH" --threshold "$THRESHOLD" --interval 60 \
        >> "$LOG_DIR/detector.log" 2>&1 &
    
    DETECTOR_PID=$!
    echo $DETECTOR_PID > "$PID_DIR/detector.pid"
    print_success "Anomaly Detector started (PID: $DETECTOR_PID)"
    sleep 1
}

# Запуск веб-интерфейса
start_web() {
    if [ "$RUN_WEB" = true ]; then
        print_info "Starting Web Interface..."
        
        if [ "$DEBUG_MODE" = true ]; then
            $PYTHON_CMD -m ndtp_ids.web_interface --port "$WEB_PORT" --db "$DB_PATH" --debug \
                >> "$LOG_DIR/web.log" 2>&1 &
        else
            $PYTHON_CMD -m ndtp_ids.web_interface --port "$WEB_PORT" --db "$DB_PATH" \
                >> "$LOG_DIR/web.log" 2>&1 &
        fi
        
        WEB_PID=$!
        echo $WEB_PID > "$PID_DIR/web.pid"
        print_success "Web Interface started (PID: $WEB_PID)"
        sleep 2
    fi
}

# Обработка сигналов
cleanup() {
    echo ""
    print_info "Stopping NDTP IDS..."
    
    # Остановка всех процессов
    if [ -d "$PID_DIR" ]; then
        for pidfile in "$PID_DIR"/*.pid; do
            if [ -f "$pidfile" ]; then
                pid=$(cat "$pidfile" 2>/dev/null)
                if [ -n "$pid" ]; then
                    if kill -0 "$pid" 2>/dev/null; then
                        print_info "Stopping $(basename "$pidfile" .pid) (PID: $pid)"
                        kill "$pid" 2>/dev/null || true
                        # Ждем завершения процесса
                        for i in {1..5}; do
                            if ! kill -0 "$pid" 2>/dev/null; then
                                break
                            fi
                            sleep 1
                        done
                        # Принудительное завершение если процесс все еще работает
                        if kill -0 "$pid" 2>/dev/null; then
                            kill -9 "$pid" 2>/dev/null || true
                        fi
                    fi
                fi
                rm -f "$pidfile"
            fi
        done
    fi
    
    print_success "All components stopped"
    exit 0
}

trap cleanup EXIT INT TERM

# Главная функция
main() {
    print_header "🚀 NDTP IDS System Launcher"
    
    check_environment
    setup_directories
    init_database
    
    print_header "🔧 Starting Components"
    
    start_collector_aggregator
    start_detector
    start_web
    
    print_header "✅ System is Running"
    
    if [ "$RUN_WEB" = true ]; then
        print_success "Web Interface: ${CYAN}http://localhost:$WEB_PORT${NC}"
    fi
    print_info "Logs directory: $LOG_DIR/"
    print_info "Interface: $INTERFACE"
    print_info "Database: $DB_PATH"
    print_info "Threshold: $THRESHOLD"
    print_info "Window: ${WINDOW} minutes"
    
    echo ""
    print_warning "Press Ctrl+C to stop all components..."
    echo ""
    
    # Ждем сигнала остановки
    wait
}

# Парсинг аргументов
while [[ $# -gt 0 ]]; do
    case $1 in
        --interface)
            INTERFACE="$2"
            shift 2
            ;;
        --port)
            WEB_PORT="$2"
            shift 2
            ;;
        --threshold)
            THRESHOLD="$2"
            shift 2
            ;;
        --window)
            WINDOW="$2"
            shift 2
            ;;
        --no-collector)
            RUN_COLLECTOR=false
            shift
            ;;
        --no-web)
            RUN_WEB=false
            shift
            ;;
        --debug)
            DEBUG_MODE=true
            shift
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

main
