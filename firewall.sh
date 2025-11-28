#!/bin/bash
# ============================================================================
# Firewall Hardening Script
# ============================================================================
# Modes: scan | fix | rollback
MODE=${1:-scan}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/hardening.db"
BACKUP_DIR="$SCRIPT_DIR/backups"
TOPIC="Firewall"

mkdir -p "$BACKUP_DIR"

# ============================================================================
# Colors & Counters
# ============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
FIXED_CHECKS=0

# ============================================================================
# Logging Functions
# ============================================================================
log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_pass()  { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED_CHECKS++)); }
log_fixed() { echo -e "${BLUE}[FIXED]${NC} $1"; ((FIXED_CHECKS++)); }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED_CHECKS++)); }

# ============================================================================
# Database Functions
# ============================================================================
initialize_db() {
    if [ ! -f "$DB_PATH" ]; then
        sqlite3 "$DB_PATH" "CREATE TABLE IF NOT EXISTS configurations (
            topic TEXT,
            rule_id TEXT PRIMARY KEY,
            rule_name TEXT,
            original_value TEXT,
            current_value TEXT,
            status TEXT
        );"
    fi
}

save_config() {
    local rule_id="$1"
    local rule_name="$2"
    local original_value="$3"
    local current_value="${4:-$original_value}"

    python3 - <<EOF
import sqlite3
conn = sqlite3.connect("$DB_PATH")
cursor = conn.cursor()
cursor.execute("""
INSERT OR REPLACE INTO configurations 
(topic, rule_id, rule_name, original_value, current_value, status)
VALUES (?, ?, ?, ?, ?, 'stored')
""", ("$TOPIC", "$rule_id", "$rule_name", "$original_value", "$current_value"))
conn.commit()
conn.close()
EOF
}

# ============================================================================
# Firewall Checks
# ============================================================================
check_ufw_installed() {
    local rule_id="FW-UFW-INST"
    local rule_name="Ensure ufw is installed"
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: $rule_name\nRule ID: $rule_id"

    if [ "$MODE" = "scan" ]; then
        if command -v ufw >/dev/null 2>&1; then
            log_pass "ufw is installed"
        else
            log_error "ufw is NOT installed"
        fi
    elif [ "$MODE" = "fix" ]; then
        apt-get update -y >/dev/null
        apt-get install -y ufw >/dev/null
        log_fixed "Installed ufw"
        save_config "$rule_id" "$rule_name" "not installed" "installed"
    fi
}

check_no_iptables_persistent() {
    local rule_id="FW-UFW-IPTPERS"
    local rule_name="Ensure iptables-persistent is not installed with ufw"
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: $rule_name\nRule ID: $rule_id"

    local installed="no"
    dpkg -l | grep -q "^ii  iptables-persistent" && installed="yes"

    if [ "$MODE" = "scan" ]; then
        if [ "$installed" = "yes" ]; then
            log_error "iptables-persistent is installed (conflict)"
        else
            log_pass "iptables-persistent is not installed"
        fi
    elif [ "$MODE" = "fix" ]; then
        if [ "$installed" = "yes" ]; then
            apt-get purge -y iptables-persistent >/dev/null
            log_fixed "Removed iptables-persistent"
            save_config "$rule_id" "$rule_name" "installed" "removed"
        fi
    fi
}

check_ufw_enabled() {
    local rule_id="FW-UFW-SVC"
    local rule_name="Ensure ufw service is enabled"
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: $rule_name\nRule ID: $rule_id"

    if [ "$MODE" = "scan" ]; then
        systemctl is-enabled ufw >/dev/null 2>&1 && log_pass "ufw service is enabled" || log_error "ufw service is NOT enabled"
    elif [ "$MODE" = "fix" ]; then
        systemctl enable ufw >/dev/null
        ufw --force enable >/dev/null
        log_fixed "ufw service enabled"
        save_config "$rule_id" "$rule_name" "disabled" "enabled"
    fi
}

check_ufw_loopback() {
    local rule_id="FW-UFW-LOOP"
    local rule_name="Ensure ufw loopback traffic is configured"
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: $rule_name\nRule ID: $rule_id"

    local snapshot
    snapshot=$(ufw status verbose 2>/dev/null)

    if [[ "$MODE" == "scan" ]]; then
        if echo "$snapshot" | grep -qE "ALLOW IN.*(lo|127\.0\.0\.1)" && \
           echo "$snapshot" | grep -qE "ALLOW OUT.*(lo|127\.0\.0\.1)"; then
            log_pass "Loopback firewall rules exist"
        else
            log_error "Missing UFW loopback rules"
        fi
    elif [[ "$MODE" == "fix" ]]; then
        save_config "$rule_id" "$rule_name" "$snapshot"
        ufw allow in on lo >/dev/null
        ufw allow out on lo >/dev/null
        ufw allow in from 127.0.0.1 >/dev/null
        ufw allow out to 127.0.0.1 >/dev/null
        log_fixed "Applied loopback UFW rules"
    elif [[ "$MODE" == "rollback" ]]; then
        ufw --force reset >/dev/null
        echo "$snapshot" >/tmp/ufw_snapshot.txt
        log_info "Loopback rules rolled back"
    fi
}

check_ufw_outbound() {
    local rule_id="FW-UFW-OUT"
    local rule_name="Ensure UFW outbound connections are allowed"
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: $rule_name\nRule ID: $rule_id"

    local snapshot
    snapshot=$(ufw status verbose 2>/dev/null)

    if [[ "$MODE" == "scan" ]]; then
        if echo "$snapshot" | grep -q "Default: deny (incoming), allow (outgoing)"; then
            log_pass "Default outbound policy is allow"
        else
            log_warn "Outbound connections must be manually reviewed"
        fi
    elif [[ "$MODE" == "fix" ]]; then
        ufw default allow outgoing >/dev/null
        log_fixed "Set default outbound policy to allow"
        save_config "$rule_id" "$rule_name" "not allow" "allow"
    fi
}

check_ufw_rules_for_open_ports() {
    local rule_id="FW-UFW-PORTS"
    local rule_name="Ensure UFW firewall rules exist for all open ports"
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: $rule_name\nRule ID: $rule_id"

    local snapshot
    snapshot=$(ufw status verbose 2>/dev/null)
    local ports
    ports=$(ss -tunl | awk 'NR>1 {gsub(/.*:/,"",$5); print $5}' | sort -u)

    local missing=0
    for p in $ports; do
        if ! echo "$snapshot" | grep -q "$p"; then
            log_warn "Adding missing UFW rule for port: $p"
            if ufw allow "$p"/tcp >/dev/null 2>&1; then
                log_info "Added UFW rule for port: $p"
            else
                log_error "Failed to add UFW rule for port: $p"
            fi
            missing=1
        fi
    done

    if [ "$missing" -eq 1 ]; then
        ufw reload >/dev/null
        log_info "UFW reloaded after adding missing rules."
    fi

    if [ "$MODE" = "scan" ]; then
        if [ $missing -eq 0 ]; then
            log_pass "All open ports have UFW rules"
        else
            log_warn "Some open ports rules were added"
        fi
    elif [ "$MODE" = "fix" ]; then
        log_fixed "All open ports rules applied successfully"
    fi
}

check_ufw_default_deny() {
    local rule_id="FW-UFW-DENY"
    local rule_name="Ensure UFW default deny firewall policy"
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: $rule_name\nRule ID: $rule_id"

    if [[ "$MODE" == "scan" ]]; then
        local default_in
        default_in=$(ufw status verbose | awk '/Default:/ {print $2}')
        if [[ "$default_in" == "deny" ]]; then
            log_pass "Default deny incoming policy active"
        else
            log_error "Default deny incoming policy NOT active"
        fi
    elif [[ "$MODE" == "fix" ]]; then
        ufw default deny incoming >/dev/null
        ufw default allow outgoing >/dev/null
        ufw reload >/dev/null
        log_fixed "Default deny incoming and allow outgoing applied"
        save_config "$rule_id" "$rule_name" "not deny" "deny"
    fi
}

check_ufw_no_iptables_conflict() {
    local rule_id="FW-UFW-CONFLICT"
    local rule_name="Ensure UFW is not in use with raw iptables"
    ((TOTAL_CHECKS++))
    echo -e "\nChecking: $rule_name\nRule ID: $rule_id"

    if iptables -L | grep -q "ACCEPT" && ! ufw status | grep -q "active"; then
        log_error "iptables rules active without UFW — conflict detected"
    else
        log_pass "No UFW/iptables conflict detected"
    fi
}

# ============================================================================
# Main Execution
# ============================================================================
initialize_db

check_ufw_installed
check_no_iptables_persistent
check_ufw_enabled
check_ufw_loopback
check_ufw_outbound
check_ufw_rules_for_open_ports
check_ufw_default_deny
check_ufw_no_iptables_conflict

# ============================================================================
# Summary
# ============================================================================
echo -e "\n===== Firewall Hardening Summary ====="
echo "Total checks : $TOTAL_CHECKS"
echo "Passed       : $PASSED_CHECKS"
echo "Failed       : $FAILED_CHECKS"
echo "Fixed        : $FIXED_CHECKS"

