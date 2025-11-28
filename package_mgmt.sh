#!/bin/bash
# ============================================================================
# Package Management Hardening Script
# Covers: GRUB, Process Hardening, Warning Banners, Package Security
# Mode: scan | fix
# ============================================================================
MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/hardening.db"
BACKUP_DIR="$SCRIPT_DIR/backups"
TOPIC="Package Management"
mkdir -p "$BACKUP_DIR"

# ----------------------------------------------------------------------------
# Colors
# ----------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
FIXED_CHECKS=0

# ----------------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------------
log_info()  { 
    echo -e "${GREEN}[INFO]${NC} $1"
    save_config "INFO" "Log Info" "$1"
}
log_pass()  { 
    echo -e "${GREEN}[PASS]${NC} $1"
    save_config "PASS" "Log Pass" "$1"
    ((PASSED_CHECKS++))
}
log_fixed() { 
    echo -e "${BLUE}[FIXED]${NC} $1"
    save_config "FIXED" "Log Fixed" "$1"
    ((FIXED_CHECKS++))
}
log_warn()  { 
    echo -e "${YELLOW}[WARN]${NC} $1"
    save_config "WARN" "Log Warn" "$1"
}
log_error() { 
    echo -e "${RED}[FAIL]${NC} $1"
    save_config "FAIL" "Log Error" "$1"
    ((FAILED_CHECKS++))
}

# ----------------------------------------------------------------------------
# Database functions
# ----------------------------------------------------------------------------
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
try:
    conn = sqlite3.connect('$DB_PATH')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO configurations
        (topic, rule_id, rule_name, original_value, current_value, status)
        VALUES (?, ?, ?, ?, ?, 'stored')
    ''', ('$TOPIC', '$rule_id', '$rule_name', '$original_value', '$current_value'))
    conn.commit()
    conn.close()
except Exception as e:
    print(f"Error: {str(e)}")
EOF
}

get_original_config() {
    local rule_id="$1"
    python3 - <<EOF
import sqlite3
conn = sqlite3.connect('$DB_PATH')
cursor = conn.cursor()
cursor.execute('SELECT original_value FROM configurations WHERE topic=? AND rule_id=?', ('$TOPIC', '$rule_id'))
res = cursor.fetchone()
conn.close()
print(res[0] if res else '')
EOF
}

# ----------------------------------------------------------------------------
# GRUB functions
# ----------------------------------------------------------------------------
get_grub_cfg() {
    local grub_paths=(
        "/boot/grub/grub.cfg"
        "/boot/grub2/grub.cfg"
        "/boot/efi/EFI/kali/grub.cfg"
        "/boot/efi/EFI/ubuntu/grub.cfg"
        "/boot/efi/EFI/fedora/grub.cfg"
    )
    for path in "${grub_paths[@]}"; do
        if [ -f "$path" ]; then
            echo "$path"
            return 0
        fi
    done
    log_warn "No GRUB configuration file found"
    return 1
}

fix_grub_security() {
    log_info "Starting GRUB security hardening..."
    local grub_cfg
    grub_cfg=$(get_grub_cfg)
    if [ -z "$grub_cfg" ]; then
        log_warn "Cannot fix GRUB password automatically. Manual step required."
        return 1
    fi
    chown root:root "$grub_cfg"
    chmod 400 "$grub_cfg"
    log_info "GRUB config permissions set to 400 root:root"
}

# ----------------------------------------------------------------------------
# Checks
# ----------------------------------------------------------------------------
check_bootloader_password() {
    local rule_name="Ensure bootloader password is set"
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"

    local grub_cfg
    grub_cfg=$(get_grub_cfg)
    if [ -z "$grub_cfg" ]; then
        log_error "GRUB config not found"
        return 1
    fi

    if grep -q "^password_pbkdf2" "$grub_cfg" 2>/dev/null; then
        log_pass "Bootloader password is configured"
    else
        if [ "$MODE" = "fix" ]; then
            fix_grub_security
            echo ""
            echo "Manual step required: Add your GRUB password hash to /etc/grub.d/40_custom"
            echo "Then run 'update-grub' to apply it."
            read -p "Press ENTER once done..."
            if grep -q "^password_pbkdf2" "$grub_cfg" 2>/dev/null; then
                log_fixed "Bootloader password configured successfully"
            else
                log_error "Bootloader password is still not configured"
            fi
        else
            log_error "Bootloader password is not set"
        fi
    fi
}

check_bootloader_config_permissions() {
    local rule_name="Ensure access to bootloader config is restricted"
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"

    local grub_cfg
    grub_cfg=$(get_grub_cfg)
    if [ -z "$grub_cfg" ]; then
        log_warn "No GRUB config found"
        return 1
    fi

    local perms owner group
    perms=$(stat -c %a "$grub_cfg")
    owner=$(stat -c %U "$grub_cfg")
    group=$(stat -c %G "$grub_cfg")

    if [ "$perms" = "400" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
        log_pass "Bootloader config permissions correct"
    else
        if [ "$MODE" = "fix" ]; then
            chown root:root "$grub_cfg"
            chmod 400 "$grub_cfg"
            log_fixed "Bootloader config permissions set to 400 root:root"
        else
            log_error "Bootloader config permissions incorrect: $perms $owner:$group"
        fi
    fi
}

check_aslr() {
    local rule_name="Ensure ASLR is enabled"
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"

    local value
    value=$(sysctl -n kernel.randomize_va_space 2>/dev/null)
    if [ "$value" = "2" ]; then
        log_pass "ASLR is enabled"
    else
        if [ "$MODE" = "fix" ]; then
            save_config "PKG-PROC-ASLR" "$rule_name" "$value"
            sysctl -w kernel.randomize_va_space=2
            grep -q "kernel.randomize_va_space" /etc/sysctl.conf || echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
            sed -i 's/^kernel.randomize_va_space.*/kernel.randomize_va_space = 2/' /etc/sysctl.conf
            log_fixed "ASLR enabled"
        else
            log_error "ASLR is disabled"
        fi
    fi
}

check_ptrace_scope() {
    local rule_name="Ensure ptrace_scope is restricted"
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"

    local value
    value=$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null)
    if [ "$value" = "1" ] || [ "$value" = "2" ]; then
        log_pass "ptrace_scope is restricted ($value)"
    else
        if [ "$MODE" = "fix" ]; then
            save_config "PKG-PROC-PTRACE" "$rule_name" "$value"
            sysctl -w kernel.yama.ptrace_scope=1
            grep -q "kernel.yama.ptrace_scope" /etc/sysctl.conf || echo "kernel.yama.ptrace_scope = 1" >> /etc/sysctl.conf
            sed -i 's/^kernel.yama.ptrace_scope.*/kernel.yama.ptrace_scope = 1/' /etc/sysctl.conf
            log_fixed "ptrace_scope restricted"
        else
            log_error "ptrace_scope is not restricted ($value)"
        fi
    fi
}

check_core_dumps() {
    local rule_name="Ensure core dumps are restricted"
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"

    local suid_dumpable
    suid_dumpable=$(sysctl -n fs.suid_dumpable 2>/dev/null)
    if grep -q "* hard core 0" /etc/security/limits.conf 2>/dev/null && [ "$suid_dumpable" = "0" ]; then
        log_pass "Core dumps are restricted"
    else
        if [ "$MODE" = "fix" ]; then
            cp /etc/security/limits.conf "$BACKUP_DIR/limits.conf.$(date +%Y%m%d_%H%M%S)"
            save_config "PKG-PROC-COREDUMP" "$rule_name" "not_restricted"
            grep -q "* hard core" /etc/security/limits.conf || echo "* hard core 0" >> /etc/security/limits.conf
            sysctl -w fs.suid_dumpable=0
            grep -q "fs.suid_dumpable" /etc/sysctl.conf || echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
            log_fixed "Core dumps restricted"
        else
            log_error "Core dumps are not restricted"
        fi
    fi
}

check_prelink() {
    local rule_name="Ensure prelink is not installed"
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"

    if dpkg -l | grep -q "^ii.*prelink"; then
        if [ "$MODE" = "fix" ]; then
            save_config "PKG-PROC-PRELINK" "$rule_name" "installed"
            apt-get remove -y prelink 2>/dev/null
            log_fixed "prelink removed"
        else
            log_error "prelink is installed"
        fi
    else
        log_pass "prelink not installed"
    fi
}

check_apport() {
    local rule_name="Ensure Automatic Error Reporting is not enabled"
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"

    if systemctl is-enabled apport 2>/dev/null | grep -q "enabled"; then
        if [ "$MODE" = "fix" ]; then
            save_config "PKG-PROC-APPORT" "$rule_name" "enabled"
            systemctl disable apport
            systemctl stop apport
            log_fixed "Apport disabled"
        else
            log_error "Apport is enabled"
        fi
    else
        log_pass "Apport is disabled"
    fi
}

check_gpg_keys() {
    local rule_name="Ensure GPG keys are configured for package management"
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"

    if [ -d /etc/apt/trusted.gpg.d ] && [ "$(ls -1 /etc/apt/trusted.gpg.d | wc -l)" -gt 0 ]; then
        log_pass "APT GPG keyrings are configured"
    else
        if [ "$MODE" = "fix" ]; then
            log_warn "GPG keys missing – cannot auto-fix securely"
        else
            log_error "GPG keys not configured"
        fi
    fi
}

check_secure_repos() {
    local rule_name="Ensure package repositories use secure protocols (HTTPS)"
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"

    if grep -R "^[^#].*http://" /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; then
        if [ "$MODE" = "fix" ]; then
            save_config "PKG-REPO-HTTPS" "$rule_name" "insecure_http_detected"
            sed -i 's|http://|https://|g' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null
            log_fixed "Converted HTTP repo entries to HTTPS"
        else
            log_error "Insecure HTTP repositories detected"
        fi
    else
        log_pass "All package repositories use HTTPS or secure protocols"
    fi
}

check_unattended_upgrades() {
    local rule_name="Ensure unattended-upgrades is enabled"
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"

    if systemctl is-enabled unattended-upgrades 2>/dev/null | grep -q "enabled"; then
        log_pass "unattended-upgrades is enabled"
    else
        if [ "$MODE" = "fix" ]; then
            save_config "PKG-AUTO-UPDATES" "$rule_name" "disabled"
            apt-get install -y unattended-upgrades 2>/dev/null
            systemctl enable unattended-upgrades
            systemctl start unattended-upgrades
            log_fixed "unattended-upgrades enabled"
        else
            log_error "unattended-upgrades is disabled"
        fi
    fi
}

check_issue_banner() {
    local rule_name="Ensure local login warning banner is configured properly"
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"

    if [ -f /etc/issue ] && [ -s /etc/issue ] && ! grep -qE "\\\\v|\\\\r|\\\\m|\\\\s" /etc/issue; then
        log_pass "/etc/issue banner configured"
    else
        if [ "$MODE" = "fix" ]; then
            cp /etc/issue "$BACKUP_DIR/issue.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
            cat > /etc/issue << 'EOF'
***************************************************************************
                            NOTICE TO USERS
This computer system is for authorized use only.
***************************************************************************
EOF
            log_fixed "/etc/issue banner configured"
        else
            log_error "/etc/issue banner misconfigured or missing"
        fi
    fi
}

check_issue_net_banner() {
    local rule_name="Ensure remote login warning banner is configured properly"
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"

    if [ -f /etc/issue.net ] && [ -s /etc/issue.net ] && ! grep -qE "\\\\v|\\\\r|\\\\m|\\\\s" /etc/issue.net; then
        log_pass "/etc/issue.net banner configured"
    else
        if [ "$MODE" = "fix" ]; then
            cp /etc/issue.net "$BACKUP_DIR/issue.net.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
            cat > /etc/issue.net << 'EOF'
***************************************************************************
                            NOTICE TO REMOTE USERS
This system is for authorized use only.
***************************************************************************
EOF
            log_fixed "/etc/issue.net banner configured"
        else
            log_error "/etc/issue.net banner misconfigured or missing"
        fi
    fi
}

# ----------------------------------------------------------------------------
# Main Execution
# ----------------------------------------------------------------------------
initialize_db

# GRUB Security & Password
fix_grub_security
check_bootloader_password
check_bootloader_config_permissions

# Process Hardening
check_aslr
check_ptrace_scope
check_core_dumps
check_prelink
check_apport

# Warning Banners & Package Security
check_issue_banner
check_issue_net_banner
check_gpg_keys
check_secure_repos
check_unattended_upgrades

# ----------------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------------
echo ""
echo "========================================================================"
echo "Package Management Hardening Summary"
echo "========================================================================"
echo "Total Checks: $TOTAL_CHECKS"
echo "Passed: $PASSED_CHECKS"
echo "Failed: $FAILED_CHECKS"
echo "Fixed: $FIXED_CHECKS"
echo "========================================================================"

if [ "$FAILED_CHECKS" -gt 0 ]; then
    echo -e "${RED}[FAIL] Some checks failed. See above for details.${NC}"
else
    echo -e "${GREEN}[PASS] All checks passed or fixed.${NC}"
fi

