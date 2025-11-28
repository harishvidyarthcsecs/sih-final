#!/usr/bin/env bash
#
# system_maintenance.sh — Kali/Ubuntu-friendly security audit script
# FULL VERSION — uniform logging and accurate TOTAL_CHECKS
#

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DB_FILE="$SCRIPT_DIR/hardening.db"
LOG="$SCRIPT_DIR/security_check_log.txt"

TOTAL_CHECKS=-10
PASSED_CHECKS=0
FAILED_CHECKS=0
FIXED_CHECKS=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "Security Check Log" > "$LOG"
echo "====================" >> "$LOG"
echo "Running Scan Mode..." >> "$LOG"

# Initialize SQLite Database and table
initialize_db() {
    if [ ! -f "$DB_FILE" ]; then
        echo "Database does not exist, creating now..."
    fi

    sqlite3 "$DB_FILE" "CREATE TABLE IF NOT EXISTS configurations (
        topic TEXT,
        rule_id TEXT PRIMARY KEY,
        rule_name TEXT,
        original_value TEXT,
        current_value TEXT,
        status TEXT
    );"
    
    echo "Database initialized or already exists."
}

# Logging helpers
log_info() { echo -e "${GREEN}[INFO]${NC} $1" | tee -a "$LOG"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$LOG"; ((PASSED_CHECKS++)); ((TOTAL_CHECKS++)); save_config "$1" "pass"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1" | tee -a "$LOG"; ((FAILED_CHECKS++)); ((TOTAL_CHECKS++)); save_config "$1" "fail"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG"; }

# Save configuration to database
save_config() {
    local rule_name="$1"
    local status="$2"
    local original_value="$3"
    local current_value="$4"

    python3 - <<EOF
import sqlite3
conn = sqlite3.connect("$DB_FILE")
cursor = conn.cursor()
cursor.execute("""
INSERT OR REPLACE INTO configurations 
(topic, rule_id, rule_name, original_value, current_value, status)
VALUES (?, ?, ?, ?, ?, ?)
""", ("System Maintenance", "$rule_name", "$rule_name", "$original_value", "$current_value", "$status"))
conn.commit()
conn.close()
EOF
}

# Check file permissions and save status in DB
check_perm() {
    local file="$1"
    local acceptable="$2"
    local rule_name="$3"

    ((TOTAL_CHECKS++))

    if [[ ! -e "$file" ]]; then
        log_warn "$file does not exist (skipped)"
        save_config "$rule_name" "warn" "N/A" "N/A"
        return
    fi

    mode=$(stat -c "%a" "$file")
    IFS=',' read -ra allowed <<< "$acceptable"

    # Check if current mode is acceptable
    for val in "${allowed[@]}"; do
        if [[ "$mode" == "$val" ]]; then
            log_pass "$file permissions correct ($mode)"
            save_config "$rule_name" "pass" "$mode" "$mode"
            return
        fi
    done

    # Not acceptable → fail
    log_fail "$file permissions $mode (expected: $acceptable)"
    save_config "$rule_name" "fail" "$mode" "$acceptable"

    # If fix mode, try to correct
    if [[ "$MODE" == "fix" ]]; then
        target="${allowed[0]}"
        if sudo chmod "$target" "$file"; then
            log_info "Fixed permissions for $file → $target"
            ((FIXED_CHECKS++))
            save_config "$rule_name" "fixed" "$mode" "$target"
        else
            log_fail "Failed to fix permissions for $file"
        fi
    fi
}

# Initialize the database before any checks
initialize_db

# System File Checks — Permissions
check_perm /etc/passwd "644" "Ensure permissions on /etc/passwd"
check_perm /etc/passwd- "600,644" "Ensure permissions on /etc/passwd-"
check_perm /etc/group "644" "Ensure permissions on /etc/group"
check_perm /etc/group- "600,644" "Ensure permissions on /etc/group-"
check_perm /etc/shadow "600,640" "Ensure permissions on /etc/shadow"
check_perm /etc/shadow- "600" "Ensure permissions on /etc/shadow-"
check_perm /etc/gshadow "600,640" "Ensure permissions on /etc/gshadow"
check_perm /etc/gshadow- "600" "Ensure permissions on /etc/gshadow-"
check_perm /etc/shells "644" "Ensure permissions on /etc/shells"
check_perm /etc/security/opasswd "600,644" "Ensure permissions on /etc/security/opasswd"

# ---------------------------------------------------------------------------
# Shadow password and empty fields
# ---------------------------------------------------------------------------
if pwck -r 2>&1 | grep -q "no shadow"; then
    log_fail "Some accounts are not using shadow passwords"
    save_config "Ensure all accounts use shadow passwords" "fail" "N/A" "N/A"
else
    log_pass "All accounts use shadow passwords"
    save_config "Ensure all accounts use shadow passwords" "pass" "N/A" "N/A"
fi

empty_fields=$(awk -F: '($2 == "") {print $1}' /etc/shadow)
if [[ -z "$empty_fields" ]]; then
    log_pass "No empty password fields"
    save_config "Ensure /etc/shadow password fields are not empty" "pass" "N/A" "N/A"
else
    log_fail "Empty password fields found: $empty_fields"
    save_config "Ensure /etc/shadow password fields are not empty" "fail" "$empty_fields" "N/A"
fi

# ---------------------------------------------------------------------------
# Duplicate UIDs, GIDs, usernames, group names
# ---------------------------------------------------------------------------
dup_uids=$(awk -F: '($3 >= 1000){print $3}' /etc/passwd | sort -n | uniq -d)
[[ -z "$dup_uids" ]] && log_pass "No duplicate UIDs (real users)" || log_fail "Duplicate UIDs found: $dup_uids"

dup_gids=$(awk -F: '($3 >= 1000){print $3}' /etc/group | sort -n | uniq -d)
[[ -z "$dup_gids" ]] && log_pass "No duplicate GIDs (real users)" || log_fail "Duplicate GIDs found: $dup_gids"

dup_users=$(awk -F: '{print $1}' /etc/passwd | sort | uniq -d)
[[ -z "$dup_users" ]] && log_pass "No duplicate usernames" || log_fail "Duplicate usernames found: $dup_users"

dup_groupnames=$(awk -F: '{print $1}' /etc/group | sort | uniq -d)
[[ -z "$dup_groupnames" ]] && log_pass "No duplicate group names" || log_fail "Duplicate group names found: $dup_groupnames"

# ---------------------------------------------------------------------------
# Home directories check (informational)
# ---------------------------------------------------------------------------
homes=$(awk -F: '($3>=1000 && $1!="nobody"){print $6}' /etc/passwd | grep -v "^/home")
[[ -z "$homes" ]] && log_info "All real user home directories under /home" || log_info "System service homes outside /home detected: $homes"

# ---------------------------------------------------------------------------
# Dotfiles permissions
# ---------------------------------------------------------------------------
dangerous_dotfiles=$(find /home -maxdepth 3 -type f -name ".*" -perm /022 2>/dev/null)
[[ -n "$dangerous_dotfiles" ]] && log_fail "Dangerous dotfile permissions found:\n$dangerous_dotfiles" || log_pass "No dangerous dotfile permissions"

# ---------------------------------------------------------------------------
# World-writable files
# ---------------------------------------------------------------------------
world_write=$(find / -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o \
    -path /run -prune -o -path /tmp -prune -o -path /var/tmp -prune -o -type f -perm -0002 -print 2>/dev/null)
[[ -n "$world_write" ]] && log_fail "World-writable files found:\n$world_write" || log_pass "No unsafe world-writable files"

# ---------------------------------------------------------------------------
# System files ownership
# ---------------------------------------------------------------------------
nog=$(find / -path /home -prune -o -path /tmp -prune -o -path /var/tmp -prune -o \
    -path /run/user -prune -o -path /proc -prune -o -path /sys -prune -o \
    -path /run -prune -o -path /dev -prune -o -nouser -o -nogroup -print 2>/dev/null)
[[ -n "$nog" ]] && log_fail "System files without owner/group found:\n$nog" || log_pass "All system files have valid owners/groups"

# ---------------------------------------------------------------------------
# SUID/SGID files (informational)
# ---------------------------------------------------------------------------
suid=$(find / -xdev -perm -4000 2>/dev/null)
sgid=$(find / -xdev -perm -2000 2>/dev/null)
log_info "SUID files found: $(echo "$suid" | wc -l)"
log_info "SGID files found: $(echo "$sgid" | wc -l)"

# ---------------------------------------------------------------------------
# Invalid shells
# ---------------------------------------------------------------------------
invalid_shells=$(pwck -r 2>&1 | grep "invalid shell")
[[ -n "$invalid_shells" ]] && log_fail "Invalid shells detected:\n$invalid_shells" || log_pass "All users have valid shells"

# ---------------------------------------------------------------------------
# sudoers and opasswd
# ---------------------------------------------------------------------------
[[ -e /etc/sudoers ]] && log_pass "sudoers file exists" || log_fail "sudoers missing"
[[ -e /etc/security/opasswd ]] && log_pass "opasswd file exists" || log_fail "opasswd missing"

# ---------------------------------------------------------------------------
# hosts.allow and hosts.deny
# ---------------------------------------------------------------------------
[[ -e /etc/hosts.allow ]] && log_pass "hosts.allow exists" || log_fail "hosts.allow missing"
[[ -e /etc/hosts.deny ]] && log_pass "hosts.deny exists" || log_fail "hosts.deny missing"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo -e "\n==================== Summary ====================" | tee -a "$LOG"
echo "Total Checks : $TOTAL_CHECKS" | tee -a "$LOG"
echo "Passed       : $PASSED_CHECKS" | tee -a "$LOG"
echo "Failed       : $FAILED_CHECKS" | tee -a "$LOG"
echo "Fixed        : $FIXED_CHECKS" | tee -a "$LOG"
echo -e "=================================================" | tee -a "$LOG"

if [ "$FAILED_CHECKS" -gt 0 ]; then
    echo -e "${RED}[FAIL] Issues detected.${NC}" | tee -a "$LOG"
else
    echo -e "${GREEN}[PASS] All checks passed.${NC}" | tee -a "$LOG"
fi

