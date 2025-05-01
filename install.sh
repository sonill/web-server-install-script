#!/bin/bash

# Installation flags (1 = Install, 0 = Skip)
INSTALL_NGINX=1
INSTALL_PHP=1
INSTALL_MYSQL=1
INSTALL_REDIS=1
INSTALL_COMMON_TOOLS=1

# Default values for variables
PHP_VERSION="8.1"
MYSQL_ROOT_PASSWORD=""
MYSQL_PASSWORD_POLICY="MEDIUM"  # Options: LOW, MEDIUM, STRONG
LOG_FILE="/var/log/webserver_install.log"
CREDENTIALS_FILE="/root/webserver_credentials.txt"

set -e

if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root or with sudo."
    exit 1
fi

touch "$LOG_FILE"
chmod 640 "$LOG_FILE"
chown root:adm "$LOG_FILE"

touch "$CREDENTIALS_FILE"
chmod 600 "$CREDENTIALS_FILE"
chown root:root "$CREDENTIALS_FILE"

log() {
    echo "$(date) - $1"
    echo "$(date) - $1" >> "$LOG_FILE"
}

log_error() {
    echo "$(date) - ERROR: $1" >> "$LOG_FILE"
    echo "$(date) - ERROR: $1"
    ((ERROR_COUNT++))
}

ERROR_COUNT=0

# Ask for PHP version
if [ $INSTALL_PHP -eq 1 ]; then
    read -p "Enter PHP version (e.g., 8.1, 8.2, 8.3) [8.1]: " input_php_version
    PHP_VERSION=${input_php_version:-8.1}
    if [[ ! "$PHP_VERSION" =~ ^[0-9]+\.[0-9]+$ ]]; then
        log_error "Invalid PHP version format."
        exit 1
    fi
fi

# Ask for MySQL root password
if [ $INSTALL_MYSQL -eq 1 ]; then
    read -sp "Enter MySQL root password: " MYSQL_ROOT_PASSWORD
    echo
    if [ -z "$MYSQL_ROOT_PASSWORD" ]; then
        log_error "MySQL root password cannot be empty."
        exit 1
    fi
    echo "MySQL Root Password: $MYSQL_ROOT_PASSWORD" > "$CREDENTIALS_FILE"

    # Ask for MySQL password policy
    read -p "Enter MySQL password policy (LOW, MEDIUM, STRONG) [MEDIUM]: " policy_input
    MYSQL_PASSWORD_POLICY=${policy_input:-MEDIUM}
    if [[ ! "$MYSQL_PASSWORD_POLICY" =~ ^(LOW|MEDIUM|STRONG)$ ]]; then
        log_error "Invalid MySQL password policy. Must be LOW, MEDIUM, or STRONG."
        exit 1
    fi
fi

# Confirmation
read -p "This script will install a web server stack. Do you wish to continue? (y/n): " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Exiting script."
    exit 0
fi

log "Starting installation process..."
sudo apt update -y
sudo apt upgrade -y

is_package_installed() {
    dpkg -l | grep -qw "$1"
}

is_service_running() {
    systemctl is-active --quiet "$1"
}

install_package() {
    if ! is_package_installed "$1"; then
        log "Installing $1..."
        sudo apt install -y "$1" || { log_error "Failed to install $1"; exit 1; }
    else
        log "$1 is already installed. Skipping."
    fi
}

start_service() {
    log "Starting $1..."
    sudo systemctl enable "$1" || { log_error "Failed to enable $1"; exit 1; }
    sudo systemctl restart "$1" || { log_error "Failed to restart $1"; exit 1; }
    if ! is_service_running "$1"; then
        log_error "$1 failed to start."
        exit 1
    fi
}

# NGINX
if [ $INSTALL_NGINX -eq 1 ]; then
    install_package nginx
    start_service nginx
else
    log "Skipping Nginx installation."
fi

# PHP
if [ $INSTALL_PHP -eq 1 ]; then
    if ! is_package_installed "php$PHP_VERSION"; then
        log "Adding PHP repository..."
        sudo add-apt-repository ppa:ondrej/php -y
        sudo apt update -y
        install_package "php$PHP_VERSION"
        install_package "php$PHP_VERSION-fpm"
        install_package "php$PHP_VERSION-mysql"
        install_package "php$PHP_VERSION-xml"
        install_package "php$PHP_VERSION-mbstring"
        install_package "php$PHP_VERSION-curl"
        install_package "php$PHP_VERSION-json"
        install_package "php$PHP_VERSION-zip"
        install_package "php$PHP_VERSION-opcache"
        install_package "php$PHP_VERSION-cli"
        start_service "php$PHP_VERSION-fpm"
    else
        log "PHP $PHP_VERSION is already installed."
    fi
else
    log "Skipping PHP installation."
fi

# MySQL
if [ $INSTALL_MYSQL -eq 1 ]; then
    if ! is_package_installed mysql-server; then
        install_package mysql-server

        log "Securing MySQL..."
        case "$MYSQL_PASSWORD_POLICY" in
            LOW)    policy_level=0 ;;
            MEDIUM) policy_level=1 ;;
            STRONG) policy_level=2 ;;
        esac

        sudo mysql -e "SET GLOBAL validate_password.policy = $policy_level;"
        sudo mysql -e "SET GLOBAL validate_password.length = 8;"
        sudo mysql -e "SET GLOBAL validate_password.mixed_case_count = 1;"
        sudo mysql -e "SET GLOBAL validate_password.number_count = 1;"
        sudo mysql -e "SET GLOBAL validate_password.special_char_count = 1;"
        sudo mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '$MYSQL_ROOT_PASSWORD';"
        sudo mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test_%';"
        sudo mysql -e "DROP DATABASE IF EXISTS test;"
        sudo mysql -e "FLUSH PRIVILEGES;"
    else
        log "MySQL already installed."
    fi
    start_service mysql
else
    log "Skipping MySQL installation."
fi

# Redis
if [ $INSTALL_REDIS -eq 1 ]; then
    install_package redis-server
    start_service redis
else
    log "Skipping Redis installation."
fi

# Common tools
if [ $INSTALL_COMMON_TOOLS -eq 1 ]; then
    for tool in git unzip wget curl nano; do
        install_package "$tool"
    done
else
    log "Skipping common tools."
fi

# Firewall
log "Configuring UFW firewall..."
install_package ufw
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw --force enable

# Service check
log "Checking service statuses..."
services=()
[ $INSTALL_NGINX -eq 1 ] && services+=("nginx")
[ $INSTALL_PHP -eq 1 ] && services+=("php$PHP_VERSION-fpm")
[ $INSTALL_MYSQL -eq 1 ] && services+=("mysql")
[ $INSTALL_REDIS -eq 1 ] && services+=("redis")

for service in "${services[@]}"; do
    if is_service_running "$service"; then
        log "$service is running."
    else
        log_error "$service is not running."
    fi
done

# Summary
log "Installation Summary:"
[ $INSTALL_NGINX -eq 1 ] && log "- Nginx"
[ $INSTALL_PHP -eq 1 ] && log "- PHP $PHP_VERSION"
[ $INSTALL_MYSQL -eq 1 ] && log "- MySQL"
[ $INSTALL_REDIS -eq 1 ] && log "- Redis"
[ $INSTALL_COMMON_TOOLS -eq 1 ] && log "- Common tools"
log "- Credentials saved in: $CREDENTIALS_FILE"
log "- Check logs in $LOG_FILE"

if [ $ERROR_COUNT -gt 0 ]; then
    log "Installation finished with $ERROR_COUNT errors. See log for details."
else
    log "Installation completed successfully!"
fi
