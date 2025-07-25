#!/bin/bash

# =======================================
# PRODUCTION-READY Web Server Stack Installer
# (NGINX, PHP, MySQL, Redis)
# Version: 2.0
# Last Updated: 2024-05-20
# =======================================

# === Configuration (Customize These) ===
INSTALL_NGINX=1
INSTALL_PHP=1
INSTALL_MYSQL=1
INSTALL_REDIS=1
INSTALL_COMMON_TOOLS=1
ENABLE_FIREWALL=1
ENABLE_TLS=0  # Set to 1 if you have a domain ready for Let's Encrypt

# Defaults
PHP_VERSION="8.4"
MYSQL_ROOT_PASSWORD="password"
DOMAIN_NAME="yourdomain.com"  # Only needed if ENABLE_TLS=1
MYSQL_PASSWORD_POLICY="LOW"  # LOW|MEDIUM|STRONG
LOG_FILE="/var/log/webserver_install.log"
CREDENTIALS_FILE="/root/webserver_credentials.txt"

# === Initialization ===
set -eo pipefail
exec > >(tee -a "$LOG_FILE") 2>&1

ERROR_COUNT=0

# === Pre-Flight Checks ===
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_system() {
    local total_mem
    total_mem=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    if [ "$total_mem" -lt 1000000 ]; then
        log_error "Insufficient RAM (Minimum: 1GB)"
        exit 1
    fi

    local free_disk
    free_disk=$(df --output=avail / | tail -1)
    if [ "$free_disk" -lt 5000000 ]; then
        log_error "Insufficient disk space (Minimum: 5GB free)"
        exit 1
    fi
}

setup_logging() {
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE" && chmod 640 "$LOG_FILE"
    echo "=== Installation Started $(date) ===" >> "$LOG_FILE"
}

# === Core Functions ===
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log_error() {
    log "ERROR: $1"
    ((ERROR_COUNT++))
}

install_package() {
    if ! dpkg -l | grep -qw "$1"; then
        log "Installing: $1"
        DEBIAN_FRONTEND=noninteractive apt-get install -yq "$1" || {
            log_error "Failed to install $1"
            return 1
        }
    else
        log "$1 already installed"
    fi
}

secure_mysql() {
    log "Securing MySQL installation"
    local sql_commands=(
        "DELETE FROM mysql.user WHERE User='';"
        "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
        "DROP DATABASE IF EXISTS test;"
        "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"
        "FLUSH PRIVILEGES;"
    )

    for cmd in "${sql_commands[@]}"; do
        mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e "$cmd" || {
            log_error "MySQL secure command failed: $cmd"
            return 1
        }
    done
}

configure_php() {
    if [ "$INSTALL_PHP" -ne 1 ]; then return; fi

    local php_ini="/etc/php/$PHP_VERSION/fpm/php.ini"
    log "Hardening PHP configuration"

    if [ ! -f "$php_ini" ]; then
        log_error "$php_ini not found"
        return 1
    fi

    declare -A php_settings=(
        ["expose_php"]="Off"
        ["disable_functions"]="exec,passthru,shell_exec,system,proc_open,popen"
        ["open_basedir"]="/var/www:/tmp"
        ["opcache.enable"]="1"
        ["opcache.validate_timestamps"]="0"
        ["session.cookie_httponly"]="1"
        ["session.cookie_secure"]="1"
    )

    for key in "${!php_settings[@]}"; do
        if grep -q "^$key\s*=" "$php_ini"; then
            log "$key already set, skipping"
        else
            echo "$key = ${php_settings[$key]}" >> "$php_ini"
            log "Set $key = ${php_settings[$key]}"
        fi
    done

    systemctl restart "php$PHP_VERSION-fpm"
}

configure_nginx() {
    if [ "$INSTALL_NGINX" -ne 1 ]; then return; fi

    if [ ! -d "/etc/nginx/conf.d" ]; then
        mkdir -p /etc/nginx/conf.d
    fi

    local conf_path="/etc/nginx/conf.d/security.conf"

    if [ -f "$conf_path" ]; then
        log "$conf_path already exists, skipping"
    else
        log "Creating security headers config for Nginx"
        cat > "$conf_path" << 'EOL'
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
EOL
    fi

    if [ "$ENABLE_TLS" -eq 1 ]; then
        install_package certbot python3-certbot-nginx
        certbot --nginx -d "$DOMAIN_NAME" --non-interactive --agree-tos --redirect
    fi
}

configure_redis() {
    if [ "$INSTALL_REDIS" -ne 1 ]; then return; fi

    local conf="/etc/redis/redis.conf"
    if [ ! -f "$conf" ]; then
        log_error "Redis config file missing"
        return 1
    fi

    if grep -q "^requirepass" "$conf"; then
        log "Redis already has a password configured, skipping"
        return 0
    fi

    log "Securing Redis"
    local redis_pass
    redis_pass=$(openssl rand -hex 32)
    echo "Redis Password: $redis_pass" >> "$CREDENTIALS_FILE"

    sed -i 's/^# requirepass .*/requirepass '"$redis_pass"'/' "$conf"
    sed -i 's/^supervised no/supervised systemd/' "$conf"
    sed -i 's/^bind 127.0.0.1 ::1/bind 127.0.0.1/' "$conf"

    systemctl restart redis-server
}

check_service_deps() {
    [ "$INSTALL_PHP" -eq 1 ] && [ "$INSTALL_NGINX" -ne 1 ] && {
        log_error "PHP requires Nginx"
        exit 1
    }
    [ "$INSTALL_REDIS" -eq 1 ] && ! command -v redis-cli &>/dev/null && {
        log_error "Redis installation failed"
        exit 1
    }
}

# === Main Execution ===
check_root
setup_logging
check_system

log "Starting installation..."

if [ "$INSTALL_MYSQL" -eq 1 ] && [ -z "$MYSQL_ROOT_PASSWORD" ]; then
    log_error "MYSQL_ROOT_PASSWORD cannot be empty"
    exit 1
fi

if [ "$INSTALL_PHP" -eq 1 ]; then
    if ! apt-cache show "php$PHP_VERSION-fpm" &>/dev/null; then
        log_error "PHP $PHP_VERSION is not available"
        exit 1
    fi
fi

log "Updating system packages"
apt-get update -y && apt-get upgrade -y

check_service_deps

if [ "$INSTALL_NGINX" -eq 1 ]; then
    install_package nginx
    configure_nginx
    systemctl enable --now nginx
fi

if [ "$INSTALL_PHP" -eq 1 ]; then
    add-apt-repository ppa:ondrej/php -y
    apt-get update

    PHP_PACKAGES=(
        "php$PHP_VERSION-fpm"
        "php$PHP_VERSION-mysql"
        "php$PHP_VERSION-curl"
        "php$PHP_VERSION-gd"
        "php$PHP_VERSION-mbstring"
        "php$PHP_VERSION-xml"
        "php$PHP_VERSION-zip"
        "php$PHP_VERSION-opcache"
    )

    for pkg in "${PHP_PACKAGES[@]}"; do
        install_package "$pkg"
    done

    configure_php
fi

if [ "$INSTALL_MYSQL" -eq 1 ]; then
    install_package mysql-server

    log "Configuring MySQL password policy"
    mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '$MYSQL_ROOT_PASSWORD';"
    mysql -e "UNINSTALL PLUGIN validate_password;" 2>/dev/null || true
    mysql -e "INSTALL PLUGIN validate_password SONAME 'validate_password.so';"

    case "$MYSQL_PASSWORD_POLICY" in
        LOW)    mysql -e "SET GLOBAL validate_password.policy = 0; SET GLOBAL validate_password.length = 8;";;
        MEDIUM) mysql -e "SET GLOBAL validate_password.policy = 1; SET GLOBAL validate_password.length = 10;";;
        STRONG) mysql -e "SET GLOBAL validate_password.policy = 2; SET GLOBAL validate_password.length = 12;";;
    esac

    secure_mysql
fi

if [ "$INSTALL_REDIS" -eq 1 ]; then
    install_package redis-server
    configure_redis
fi

if [ "$INSTALL_COMMON_TOOLS" -eq 1 ]; then
    install_package fail2ban unattended-upgrades git unzip
    echo "unattended-upgrades unattended-upgrades/enable_auto_updates boolean true" | debconf-set-selections
    dpkg-reconfigure -f noninteractive unattended-upgrades
fi

if [ "$ENABLE_FIREWALL" -eq 1 ]; then
    install_package ufw
    ufw allow ssh
    ufw allow 'Nginx Full'
    ufw --force enable
fi

# Final Checks
log "Verifying services..."
services=()
[ "$INSTALL_NGINX" -eq 1 ] && services+=("nginx")
[ "$INSTALL_PHP" -eq 1 ] && services+=("php$PHP_VERSION-fpm")
[ "$INSTALL_MYSQL" -eq 1 ] && services+=("mysql")
[ "$INSTALL_REDIS" -eq 1 ] && services+=("redis-server")

for service in "${services[@]}"; do
    if systemctl is-active --quiet "$service"; then
        log "$service is running"
    else
        log_error "$service failed to start"
    fi
done

# Completion
log "Installation completed at $(date)"
log "Credentials saved to: $CREDENTIALS_FILE"
log "Next steps:"
log "1. Review $CREDENTIALS_FILE for sensitive credentials"
log "2. Set up monitoring (e.g., netdata, prometheus)"
log "3. Configure regular backups"

if [ "$ERROR_COUNT" -gt 0 ]; then
    log "Completed with $ERROR_COUNT errors. Review $LOG_FILE"
else
    log "✅ Successfully deployed production-ready web server stack"
fi
