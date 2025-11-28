#!/bin/bash
# CIS-Style Services Hardening Script (with Rollback Support)
# Modes: scan | fix | rollback

MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DB_PATH="$SCRIPT_DIR/services_hardening.db"
BACKUP_DIR="$SCRIPT_DIR/backups"
TOPIC="Services"

mkdir -p "$BACKUP_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
FIXED_CHECKS=0

# =========================
# DB Setup
# =========================
initialize_db() {
    if [ ! -f "$DB_PATH" ]; then
        sqlite3 "$DB_PATH" "CREATE TABLE IF NOT EXISTS configurations (
            topic TEXT,
            rule_id TEXT PRIMARY KEY,
            rule_name TEXT,
            original_value TEXT,
            status TEXT
        );"
    fi
}

save_config() {
    sqlite3 "$DB_PATH" <<EOF
INSERT OR REPLACE INTO configurations
(topic, rule_id, rule_name, original_value, status)
VALUES ('$TOPIC', '$1', '$2', '$3', 'stored');
EOF
}

get_original() {
    sqlite3 "$DB_PATH" "SELECT original_value FROM configurations WHERE rule_id='$1';"
}

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

# =========================
# Service Status Checker
# =========================
is_disabled() {
    local state
    state=$(systemctl is-enabled "$1" 2>/dev/null)
    case "$state" in
        disabled|masked|static|indirect|not-found)
            return 0 ;;
        *)  return 1 ;;
    esac
}

disable_service() {
    systemctl stop "$1" 2>/dev/null
    systemctl disable "$1" 2>/dev/null
    systemctl mask "$1" 2>/dev/null
}

enable_service() {
    systemctl unmask "$1" 2>/dev/null
    systemctl enable "$1" 2>/dev/null
    systemctl start "$1" 2>/dev/null
}

# =========================
# Service Hardening
# =========================
SERVER_SERVICES=(
autofs avahi-daemon isc-dhcp-server bind9 dnsmasq vsftpd slapd dovecot
nfs-kernel-server nis cups rpcbind rsync smbd snmpd tftpd-hpa squid apache2
xinetd gdm postfix nfs-common telnetd rsh-server talkd nscd ntpdate lpd rsyslog
)

SERVER_RULES=(
"Disable autofs"
"Disable avahi-daemon"
"Disable DHCP server"
"Disable DNS server (bind9)"
"Disable dnsmasq"
"Disable FTP server"
"Disable LDAP server"
"Disable Dovecot (IMAP/POP3)"
"Disable NFS server"
"Disable NIS server"
"Disable Cups printing service"
"Disable rpcbind"
"Disable rsync daemon"
"Disable Samba"
"Disable snmp daemon"
"Disable tftp server"
"Disable Squid proxy"
"Disable Apache2 web server"
"Disable xinetd"
"Disable GDM (GUI login manager)"
"Disable Postfix MTA"
"Disable NFS common"
"Disable Telnet server"
"Disable rsh server"
"Disable talk server"
"Disable nscd service"
"Disable ntpdate service"
"Disable LPD printing service"
"Disable rsyslog"
)

CLIENT_PACKAGES=(nis rsh-client talk telnet ftp ldap-utils)
CLIENT_RULES=(
"Remove NIS client"
"Remove rsh client"
"Remove talk client"
"Remove telnet client"
"Remove ftp client"
"Remove ldap-utils"
)

check_and_fix_service() {
    local id="$1" name="$2" svc="$3"
    ((TOTAL_CHECKS++))

    echo -e "\nChecking: $name"
    if [ "$MODE" = "scan" ]; then
        if is_disabled "$svc"; then
            log_pass "$svc is disabled"
            ((PASSED_CHECKS++))
        else
            log_fail "$svc is enabled"
            ((FAILED_CHECKS++))
        fi
    elif [ "$MODE" = "fix" ]; then
        save_config "$id" "$name" "$(systemctl is-enabled "$svc" 2>/dev/null)"
        disable_service "$svc"
        log_info "$svc disabled + masked"
        ((FIXED_CHECKS++))
    else # rollback
        original=$(get_original "$id")
        if [[ "$original" == "enabled" ]]; then
            enable_service "$svc"
            log_info "$svc restored to enabled"
        fi
    fi
}

check_and_fix_package() {
    local id="$1" name="$2" pkg="$3"
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: $name"

    if [ "$MODE" = "scan" ]; then
        if dpkg -l | grep -q "^ii.*$pkg"; then
            log_fail "$pkg installed"
            ((FAILED_CHECKS++))
        else
            log_pass "$pkg not installed"
            ((PASSED_CHECKS++))
        fi
    elif [ "$MODE" = "fix" ]; then
        if dpkg -l | grep -q "^ii.*$pkg"; then
            save_config "$id" "$name" "installed"
            apt remove -y "$pkg"
            log_info "$pkg removed"
            ((FIXED_CHECKS++))
        fi
    else
        original=$(get_original "$id")
        if [[ "$original" = "installed" ]]; then
            apt install -y "$pkg"
            log_info "$pkg restored"
        fi
    fi
}

# =========================
# Time Sync — Chrony only (CIS)
# =========================
check_time_sync() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: Time Sync — only chrony allowed"

    if [ "$MODE" = "scan" ]; then
        if systemctl is-active chrony >/dev/null && systemctl is-enabled chrony >/dev/null; then
            log_pass "Chrony active"
            ((PASSED_CHECKS++))
        else
            log_fail "Chrony not configured"
            ((FAILED_CHECKS++))
        fi
    elif [ "$MODE" = "fix" ]; then
        save_config "TIME" "Time sync" "chrony"
        systemctl stop systemd-timesyncd 2>/dev/null
        systemctl disable systemd-timesyncd 2>/dev/null
        systemctl mask systemd-timesyncd 2>/dev/null

        apt install -y chrony
        systemctl enable chrony
        systemctl start chrony
        log_info "Chrony enabled, timesyncd disabled"
        ((FIXED_CHECKS++))
    fi
}

# =========================
# Missing Checks Added
# =========================
check_ports() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: Only approved ports open"
    local allowed="22 53 80 443 123"
    local bad=""

    while read -r line; do
        port=$(echo "$line" | awk -F':' '{print $NF}' | cut -d' ' -f1)
        [[ "$allowed" =~ $port ]] || bad="$bad $port"
    done < <(ss -tuln | awk 'NR>1 {print $5}')

    if [ -z "$bad" ]; then
        log_pass "No unauthorized ports"
        ((PASSED_CHECKS++))
    else
        log_fail "Unauthorized: $bad"
        ((FAILED_CHECKS++))
    fi
}

check_approved_services() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: Only approved services are listening on a network interface"

    local allowed_services=("sshd" "httpd" "https" "chrony")
    local unauthorized_services=""

    while read -r service; do
        service_name=$(echo "$service" | awk '{print $1}')
        if [[ ! " ${allowed_services[@]} " =~ " ${service_name} " ]]; then
            unauthorized_services="$unauthorized_services $service_name"
        fi
    done < <(ss -tuln | awk 'NR>1 {print $1}')

    if [ -z "$unauthorized_services" ]; then
        log_pass "Only approved services are listening"
        ((PASSED_CHECKS++))
    else
        log_fail "Unauthorized services: $unauthorized_services"
        ((FAILED_CHECKS++))
    fi
}

# =========================
# Other Security Checks
# =========================
check_rsyslog() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: Ensure rsyslog is running and disabled for remote logging"

    if systemctl is-active rsyslog >/dev/null && ! grep -q "^*.* @@.*" /etc/rsyslog.conf; then
        log_pass "rsyslog active and local-only"
        ((PASSED_CHECKS++))
    else
        log_fail "rsyslog inactive or remote logging enabled"
        ((FAILED_CHECKS++))

        if [ "$MODE" = "fix" ]; then
            save_config "RSYSLOG" "rsyslog" "inactive or remote"
            systemctl stop rsyslog
            systemctl disable rsyslog
            sed -i '/^*.* @@/d' /etc/rsyslog.conf
            systemctl enable rsyslog
            systemctl start rsyslog
            log_info "rsyslog configured local-only"
            ((FIXED_CHECKS++))
        fi
    fi
}

check_nfs_client() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: Ensure NFS client is not installed"

    if dpkg -l | grep -q "^ii.*nfs-common"; then
        log_fail "NFS client installed"
        ((FAILED_CHECKS++))

        if [ "$MODE" = "fix" ]; then
            save_config "NFS_CLIENT" "NFS client" "installed"
            apt remove -y nfs-common
            log_info "NFS client removed"
            ((FIXED_CHECKS++))
        fi
    else
        log_pass "NFS client not installed"
        ((PASSED_CHECKS++))
    fi
}

check_mail_server() {
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: Mail server configured for local-only mode"

    if systemctl is-enabled postfix >/dev/null && ! grep -q "^mydestination = \$myhostname, localhost.$" /etc/postfix/main.cf; then
        log_fail "Mail server not local-only"
        ((FAILED_CHECKS++))
    else
        log_pass "Mail server local-only"
        ((PASSED_CHECKS++))
    fi
}

# =========================
# Main Execution
# =========================
initialize_db

# Server services
for i in "${!SERVER_SERVICES[@]}"; do
    check_and_fix_service "SRV-$i" "${SERVER_RULES[$i]}" "${SERVER_SERVICES[$i]}"
done

# Client packages
for i in "${!CLIENT_PACKAGES[@]}"; do
    check_and_fix_package "CLT-$i" "${CLIENT_RULES[$i]}" "${CLIENT_PACKAGES[$i]}"
done

# Time sync
check_time_sync

# Newly added checks
check_ports
check_approved_services

# Other security checks
check_rsyslog
check_nfs_client
check_mail_server

# =========================
# Summary
# =========================
echo -e "\n========================================================"
echo "Summary"
echo "========================================================"
echo "Total Checks: $TOTAL_CHECKS"
echo "Passed: $PASSED_CHECKS"
echo "Failed: $FAILED_CHECKS"
echo "Fixed: $FIXED_CHECKS"
echo "========================================================"

if [ "$FAILED_CHECKS" -gt 0 ]; then
    echo -e "${RED}[FAIL] Issues detected.${NC}"
else
    echo -e "${GREEN}[PASS] All checks passed.${NC}"
fi

