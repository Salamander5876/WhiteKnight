#!/bin/bash

#####################################################################
# VLESS + WebSocket Auto Installer для обхода блокировок
# Поддержка: Ubuntu 20.04+, Debian 10+
# Автор: WhiteKnight VPN Setup
#####################################################################

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Лого
print_logo() {
    clear
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════════════════╗"
    echo "║                                                       ║"
    echo "║       VLESS + WebSocket VPN Auto Installer           ║"
    echo "║        Максимальная защита и обход блокировок         ║"
    echo "║                                                       ║"
    echo "╚═══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Функция логирования
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Проверка root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Этот скрипт должен быть запущен с правами root (sudo)"
        exit 1
    fi
}

# Определение ОС
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        log_error "Не удалось определить операционную систему"
        exit 1
    fi

    if [[ ! "$OS" =~ ^(ubuntu|debian)$ ]]; then
        log_error "Поддерживаются только Ubuntu и Debian"
        exit 1
    fi

    log_info "Обнаружена ОС: $OS $OS_VERSION"
}

# Получение внешнего IP
get_public_ip() {
    PUBLIC_IP=$(curl -s4 ifconfig.me || curl -s4 icanhazip.com || curl -s4 api.ipify.org)
    if [[ -z "$PUBLIC_IP" ]]; then
        log_error "Не удалось получить внешний IP адрес"
        exit 1
    fi
    log_info "Внешний IP: $PUBLIC_IP"
}

# Генерация UUID
generate_uuid() {
    cat /proc/sys/kernel/random/uuid
}

# Генерация случайного пути
generate_random_path() {
    echo "/$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
}

# Установка зависимостей
install_dependencies() {
    log_info "Установка необходимых пакетов..."

    apt-get update -qq
    apt-get install -y \
        curl \
        wget \
        unzip \
        tar \
        openssl \
        ca-certificates \
        gnupg \
        lsb-release \
        ufw \
        jq \
        qrencode \
        >/dev/null 2>&1

    log_info "Зависимости установлены"
}

# Установка Xray-core
install_xray() {
    log_info "Установка Xray-core (последняя версия)..."

    # Удаление старой версии если есть
    systemctl stop xray >/dev/null 2>&1 || true
    rm -rf /usr/local/bin/xray /usr/local/etc/xray /var/log/xray

    # Скачивание и установка
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

    # Создание директорий
    mkdir -p /usr/local/etc/xray
    mkdir -p /var/log/xray
    mkdir -p /usr/local/share/xray

    log_info "Xray-core установлен"
}

# Генерация самоподписанного сертификата
generate_certificate() {
    log_info "Генерация самоподписанного сертификата..."

    CERT_DIR="/usr/local/etc/xray/cert"
    mkdir -p "$CERT_DIR"

    # Генерация приватного ключа и сертификата
    openssl req -x509 -newkey rsa:4096 \
        -keyout "$CERT_DIR/private.key" \
        -out "$CERT_DIR/cert.crt" \
        -days 3650 \
        -nodes \
        -subj "/C=US/ST=State/L=City/O=Organization/OU=Department/CN=$PUBLIC_IP" \
        >/dev/null 2>&1

    chmod 644 "$CERT_DIR/cert.crt"
    chmod 600 "$CERT_DIR/private.key"

    log_info "Сертификат создан"
}

# Создание конфигурации Xray
create_xray_config() {
    log_info "Создание конфигурации Xray с VLESS + WebSocket + TLS..."

    UUID=$(generate_uuid)
    WS_PATH=$(generate_random_path)
    PORT=443

    # Создание конфигурационного файла
    cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "inbounds": [
    {
      "port": $PORT,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "level": 0
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/usr/local/etc/xray/cert/cert.crt",
              "keyFile": "/usr/local/etc/xray/cert/private.key"
            }
          ],
          "minVersion": "1.2",
          "cipherSuites": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
          "alpn": [
            "h2",
            "http/1.1"
          ]
        },
        "wsSettings": {
          "path": "$WS_PATH",
          "headers": {
            "Host": "$PUBLIC_IP"
          }
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {},
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "block"
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "ip": [
          "geoip:private"
        ],
        "outboundTag": "block"
      },
      {
        "type": "field",
        "protocol": [
          "bittorrent"
        ],
        "outboundTag": "block"
      }
    ]
  }
}
EOF

    # Сохранение данных для вывода
    echo "$UUID" > /tmp/vless_uuid
    echo "$WS_PATH" > /tmp/vless_path
    echo "$PORT" > /tmp/vless_port

    log_info "Конфигурация создана"
}

# Настройка файрвола
configure_firewall() {
    log_info "Настройка файрвола..."

    # Отключаем UFW если активен
    ufw --force disable >/dev/null 2>&1 || true

    # Очищаем правила
    ufw --force reset >/dev/null 2>&1 || true

    # Настраиваем правила
    ufw default deny incoming >/dev/null 2>&1
    ufw default allow outgoing >/dev/null 2>&1
    ufw allow 22/tcp comment 'SSH' >/dev/null 2>&1
    ufw allow 443/tcp comment 'VLESS XHTTP' >/dev/null 2>&1

    # Включаем UFW
    echo "y" | ufw enable >/dev/null 2>&1

    log_info "Файрвол настроен"
}

# Запуск и включение Xray
start_xray() {
    log_info "Запуск Xray сервиса..."

    systemctl daemon-reload
    systemctl enable xray >/dev/null 2>&1
    systemctl restart xray

    sleep 2

    if systemctl is-active --quiet xray; then
        log_info "Xray успешно запущен"
    else
        log_error "Не удалось запустить Xray. Проверьте логи: journalctl -u xray -n 50"
        exit 1
    fi
}

# Генерация строки подключения VLESS
generate_vless_link() {
    UUID=$(cat /tmp/vless_uuid)
    WS_PATH=$(cat /tmp/vless_path)
    PORT=$(cat /tmp/vless_port)

    # VLESS ссылка для AmneziaVPN (WebSocket + TLS)
    VLESS_LINK="vless://${UUID}@${PUBLIC_IP}:${PORT}?encryption=none&security=tls&type=ws&host=${PUBLIC_IP}&path=${WS_PATH}#WhiteKnight-VPN"

    echo "$VLESS_LINK" > /root/vless_config.txt
}

# Вывод результата
display_result() {
    UUID=$(cat /tmp/vless_uuid)
    WS_PATH=$(cat /tmp/vless_path)
    PORT=$(cat /tmp/vless_port)
    VLESS_LINK=$(cat /root/vless_config.txt)

    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                               ║${NC}"
    echo -e "${GREEN}║           УСТАНОВКА УСПЕШНО ЗАВЕРШЕНА!                       ║${NC}"
    echo -e "${GREEN}║                                                               ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}═══════════════════ ДАННЫЕ ДЛЯ ПОДКЛЮЧЕНИЯ ═══════════════════${NC}"
    echo ""
    echo -e "${YELLOW}Протокол:${NC} VLESS + WebSocket"
    echo -e "${YELLOW}IP адрес:${NC} $PUBLIC_IP"
    echo -e "${YELLOW}Порт:${NC} $PORT"
    echo -e "${YELLOW}UUID:${NC} $UUID"
    echo -e "${YELLOW}Путь:${NC} $WS_PATH"
    echo -e "${YELLOW}Шифрование:${NC} TLS 1.2+ (ChaCha20-Poly1305, AES-256-GCM)"
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${GREEN}VLESS ключ для AmneziaVPN:${NC}"
    echo ""
    echo -e "${YELLOW}$VLESS_LINK${NC}"
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${GREEN}QR-код для подключения:${NC}"
    echo ""
    qrencode -t ANSIUTF8 "$VLESS_LINK"
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${GREEN}Конфигурация сохранена в:${NC} /root/vless_config.txt"
    echo ""
    echo -e "${YELLOW}Команды управления:${NC}"
    echo -e "  Статус: ${GREEN}systemctl status xray${NC}"
    echo -e "  Стоп:   ${GREEN}systemctl stop xray${NC}"
    echo -e "  Старт:  ${GREEN}systemctl start xray${NC}"
    echo -e "  Рестарт: ${GREEN}systemctl restart xray${NC}"
    echo -e "  Логи:   ${GREEN}journalctl -u xray -f${NC}"
    echo ""
    echo -e "${GREEN}Просмотр ключа:${NC} cat /root/vless_config.txt"
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Создание файла с информацией
create_info_file() {
    UUID=$(cat /tmp/vless_uuid)
    WS_PATH=$(cat /tmp/vless_path)
    PORT=$(cat /tmp/vless_port)
    VLESS_LINK=$(cat /root/vless_config.txt)

    cat > /root/whiteknight_info.txt <<EOF
╔═══════════════════════════════════════════════════════════════╗
║         WhiteKnight VPN - Информация о подключении            ║
╚═══════════════════════════════════════════════════════════════╝

ДАННЫЕ ДЛЯ ПОДКЛЮЧЕНИЯ:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Протокол: VLESS + WebSocket
IP адрес: $PUBLIC_IP
Порт: $PORT
UUID: $UUID
Путь: $WS_PATH
Шифрование: TLS 1.2+ (ChaCha20-Poly1305, AES-256-GCM)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

VLESS КЛЮЧ (скопируйте целиком):
$VLESS_LINK

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ИНСТРУКЦИЯ ПО ПОДКЛЮЧЕНИЮ В AMNEZIAVPN:

1. Скачайте AmneziaVPN с официального сайта
2. Откройте приложение
3. Выберите "Добавить сервер вручную"
4. Выберите протокол "VLESS"
5. Вставьте VLESS ключ полностью
6. Нажмите "Подключиться"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

КОМАНДЫ УПРАВЛЕНИЯ:

Проверить статус:    systemctl status xray
Остановить сервис:   systemctl stop xray
Запустить сервис:    systemctl start xray
Перезапуск:          systemctl restart xray
Просмотр логов:      journalctl -u xray -f
Просмотр ключа:      cat /root/vless_config.txt

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

БЕЗОПАСНОСТЬ:

✓ TLS 1.2+ с сильным шифрованием
✓ ChaCha20-Poly1305 + AES-256-GCM
✓ WebSocket транспорт для обхода DPI
✓ Рандомизированный путь подключения
✓ Sniffing для оптимизации маршрутизации

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Дата установки: $(date)
Версия Xray: $(xray version | head -n 1)

╔═══════════════════════════════════════════════════════════════╗
║              Сохраните этот файл в безопасном месте!          ║
╚═══════════════════════════════════════════════════════════════╝
EOF

    log_info "Информация сохранена в /root/whiteknight_info.txt"
}

# Очистка временных файлов
cleanup() {
    rm -f /tmp/vless_uuid /tmp/vless_path /tmp/vless_port
}

# Основная функция
main() {
    print_logo

    log_info "Начало установки WhiteKnight VPN..."
    echo ""

    check_root
    detect_os
    get_public_ip

    echo ""
    log_warn "ВНИМАНИЕ! Сейчас начнется установка. Это может занять несколько минут."
    log_warn "Убедитесь, что порт 443 открыт на вашем VPS!"
    echo ""
    read -p "Нажмите Enter для продолжения или Ctrl+C для отмены..."
    echo ""

    install_dependencies
    install_xray
    generate_certificate
    create_xray_config
    configure_firewall
    start_xray
    generate_vless_link
    create_info_file
    display_result
    cleanup

    echo ""
    log_info "Установка завершена! Приятного использования!"
    echo ""
}

# Запуск
main
