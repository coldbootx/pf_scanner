#!/bin/ksh
# OpenBSD v7.8
# KSH v5.2.14 99/07/13.2
# pf_scanner.ksh - OpenBSD pflog analyzer and auto-blocker

set -eu
set -o pipefail 2>/dev/null || true
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
export PATH
umask 027

# Verify script is run as root
if [ "$(id -u)" -ne 0 ]; then
  print "This script must be run as root. Exiting."
  exit 1
fi

# Colors
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
NC="\033[0m" # Reset

# Function for colored messages
function print_msg {
  local msg_type=$1
  shift
  case "$msg_type" in
    info) print "${GREEN}[INFO]${NC} $*";;
    warn) print "${YELLOW}[WARNING]${NC} $*";;
    error) print "${RED}[ERROR]${NC} $*";;
    success) print "${BLUE}[SUCCESS]${NC} $*";;
    status) print "${BLUE}[STATUS]${NC} $*";;
    *) print "$*";;
  esac
}

# Function to pause
function pause {
  print -n "${YELLOW}Press Enter to continue . . .${NC}"
  read -r
}

# Function to display usage message
function usagemsg_displaymsg {
  print "
${BLUE}Program:${NC} ${YELLOW}pf_scanner.ksh V-1.0${NC}
${BLUE}Author:${NC} ${YELLOW}Coldboot${NC}
${BLUE}License:${NC} ${YELLOW}MIT.${NC}
"
}

# Configuration
LOGFILE="/var/log/pflog"
BLOCKLIST_FILE="/etc/blocklist/myblocklist.txt"
REPORT_FILE="pf_scan.log"
PF_TABLE="myblocklist"

# Log message with timestamp
function log_msg {
    echo "$(date '+%m-%d-%y %H:%M:%S') - $*" | tee -a "$REPORT_FILE"
}

# Function to validate IP address
function validate_ip {
    local ip="$1"
    
    # Check basic format
    if ! echo "$ip" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
        return 1
    fi
    
    # Check each octet is 0-255
    IFS='.' read -r a b c d <<EOF
$ip
EOF
    if [ "$a" -le 255 ] && [ "$a" -ge 0 ] &&
       [ "$b" -le 255 ] && [ "$b" -ge 0 ] &&
       [ "$c" -le 255 ] && [ "$c" -ge 0 ] &&
       [ "$d" -le 255 ] && [ "$d" -ge 0 ]; then
        return 0
    else
        return 1
    fi
}

# Function to clean blocklist file
function clean_blocklist {
    log_msg info "Cleaning blocklist file..."
    
    if [ ! -f "$BLOCKLIST_FILE" ] || [ ! -s "$BLOCKLIST_FILE" ]; then
        log_msg info "Blocklist file is empty or doesn't exist"
        return 0
    fi
    
    local temp_file=$(mktemp /tmp/blocklist_clean.XXXXXX)
    local removed_count=0
    local valid_count=0
    
    # Read each line from the blocklist file
    while IFS= read -r line; do
        # Skip empty lines
        [ -z "$line" ] && continue
        
        # Remove leading/trailing whitespace
        ip=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        
        # Validate IP
        if validate_ip "$ip"; then
            echo "$ip" >> "$temp_file"
            valid_count=$((valid_count + 1))
        else
            log_msg warn "Removing invalid entry: '$ip'"
            removed_count=$((removed_count + 1))
        fi
    done < "$BLOCKLIST_FILE"
    
    # Remove duplicates from valid IPs
    if [ -s "$temp_file" ]; then
        sort -u "$temp_file" > "${temp_file}.dedup"
        mv "${temp_file}.dedup" "$temp_file"
        valid_count=$(wc -l < "$temp_file" 2>/dev/null || echo 0)
    fi
    
    # Replace the blocklist file
    if [ "$valid_count" -gt 0 ]; then
        mv "$temp_file" "$BLOCKLIST_FILE"
        chmod 644 "$BLOCKLIST_FILE"
        log_msg success "Cleaned blocklist: $valid_count valid IPs, removed $removed_count invalid entries"
    else
        # Empty blocklist
        > "$BLOCKLIST_FILE"
        log_msg warn "Blocklist is now empty after cleaning"
    fi
    
    rm -f "$temp_file" "${temp_file}.dedup" 2>/dev/null
}

# Function to update PF blocklist table
function update_pf_table {
    if [ ! -s "$BLOCKLIST_FILE" ]; then
        log_msg info "Blocklist file is empty, nothing to update"
        return 0
    fi
    
    log_msg info "Updating PF blocklist table '$PF_TABLE'..."
    
    # Check if the table exists in pf.conf
    if ! grep -q "^table <${PF_TABLE}>" /etc/pf.conf 2>/dev/null; then
        log_msg warn "Table '$PF_TABLE' not found in /etc/pf.conf"
        log_msg info "Add this to /etc/pf.conf:"
        log_msg info "  table <${PF_TABLE}> persist file \"$BLOCKLIST_FILE\""
        log_msg info "  block in quick from <${PF_TABLE}>"
        return 1
    fi
    
    # Count entries before update
    local before_count=0
    if pfctl -t "$PF_TABLE" -T show 2>/dev/null | head -1 >/dev/null 2>&1; then
        before_count=$(pfctl -t "$PF_TABLE" -T show 2>/dev/null | wc -l)
    fi
    
    # Load the IPs into the PF table
    if pfctl -t "$PF_TABLE" -T replace -f "$BLOCKLIST_FILE" 2>/dev/null; then
        local after_count=$(pfctl -t "$PF_TABLE" -T show 2>/dev/null | wc -l)
        local file_count=$(wc -l < "$BLOCKLIST_FILE" 2>/dev/null || echo 0)
        
        log_msg success "PF table '$PF_TABLE' updated successfully"
        log_msg info "File entries: $file_count, PF table entries: $after_count (was: $before_count)"
        
        if [ "$file_count" -ne "$after_count" ]; then
            log_msg warn "Count mismatch: file has $file_count entries, PF table has $after_count"
        fi
        
        return 0
    else
        log_msg error "Failed to update PF table '$PF_TABLE'"
        log_msg info "Try creating the table manually: pfctl -t $PF_TABLE -T create"
        return 1
    fi
}

# Function to add IP to PF table immediately
function add_ip_to_pf {
    local ip="$1"
    
    # Validate IP first
    if ! validate_ip "$ip"; then
        log_msg warn "Invalid IP format, skipping: $ip"
        return 1
    fi
    
    # First ensure the table exists
    if ! pfctl -t "$PF_TABLE" -T show 2>/dev/null | head -1 >/dev/null 2>&1; then
        log_msg warn "Table '$PF_TABLE' doesn't exist in PF, creating it..."
        pfctl -t "$PF_TABLE" -T create 2>/dev/null || {
            log_msg error "Failed to create table '$PF_TABLE'"
            return 1
        }
    fi
    
    # Check if IP already exists in table
    if pfctl -t "$PF_TABLE" -T show 2>/dev/null | grep -q "^${ip}$"; then
        log_msg info "IP already in PF table: $ip"
        return 0
    fi
    
    # Add IP to PF table
    if pfctl -t "$PF_TABLE" -T add "$ip" 2>/dev/null; then
        log_msg success "Added $ip to PF table '$PF_TABLE'"
        return 0
    else
        log_msg error "Failed to add $ip to PF table '$PF_TABLE'"
        return 1
    fi
}

# Cleanup function
function cleanup {
    log_msg info "Exiting script."
    exit 0
}

trap cleanup INT TERM EXIT

# Check if pflog exists
if [ ! -f "$LOGFILE" ]; then
    print_msg error "pflog file $LOGFILE not found"
    exit 1
fi

# Check if tcpdump is available
if ! command -v tcpdump >/dev/null 2>&1; then
    print_msg error "tcpdump not found"
    exit 1
fi

# Ensure blocklist directory exists
mkdir -p /etc/blocklist 2>/dev/null
touch "$BLOCKLIST_FILE" 2>/dev/null
touch "$REPORT_FILE" 2>/dev/null

# Start analysis
print_msg info "### OPENBSD PFLOG AUTO BLOCKING SYSTEM ###"
log_msg info "Script started"

# 1. Clean blocklist first
clean_blocklist

# 2. Total packets
TOTAL_PACKETS=$(tcpdump -n -r "$LOGFILE" 2>/dev/null | wc -l)
log_msg info "Total packets in pflog: $TOTAL_PACKETS"

if [ "$TOTAL_PACKETS" -eq 0 ]; then
    log_msg warn "No packets found in pflog. Exiting."
    exit 0
fi

# 3. Auto-blocking logic
print_msg info "### AUTO BLOCKING ATTACKERS ###"

PORTS="22 23 80 443 3389 21 25 53 135 139 445 1433 3306 5432"
PORT_HITS=0

for port in $PORTS; do
    COUNT=$(tcpdump -n -r "$LOGFILE" "tcp dst port $port" 2>/dev/null | wc -l)
    if [ "$COUNT" -gt 0 ]; then
        log_msg info "Port $port: $COUNT connection attempts"
        PORT_HITS=$((PORT_HITS + COUNT))
    fi
done

log_msg info "Total port scan attempts: $PORT_HITS"

# 4. Find IPs making connections - SIMPLIFIED AND FIXED
log_msg info "Identifying active attackers..."

# Create temporary files
TEMP_IPS=$(mktemp /tmp/pfscan_ips.XXXXXX)

# Extract source IPs from tcpdump output
# Format: 04:36:22.977393 79.124.62.230.57833 > 45.63.66.32.9222
# We want the source IP (second field after timestamp, before the port)
tcpdump -n -r "$LOGFILE" 2>/dev/null | awk '
{
    # Skip empty lines
    if (NF < 4) next
    
    # The source IP is the second field, but we need to remove the port
    # Field 2 looks like: "79.124.62.230.57833"
    split($2, parts, ".")
    if (length(parts) >= 4) {
        # Reconstruct IP from first 4 parts
        ip = parts[1] "." parts[2] "." parts[3] "." parts[4]
        
        # Basic IP validation
        if (ip ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
            print ip
        }
    }
}' | sort -u > "$TEMP_IPS"

# Filter out private IPs
TEMP_FILTERED=$(mktemp /tmp/pfscan_filtered.XXXXXX)
while IFS= read -r ip; do
    [ -z "$ip" ] && continue
    
    # Validate IP
    if ! validate_ip "$ip"; then
        continue
    fi
    
    # Check if it's a private IP
    if echo "$ip" | grep -qE '^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|224\.|240\.)'; then
        continue
    fi
    
    echo "$ip"
done < "$TEMP_IPS" | sort -u > "$TEMP_FILTERED"

mv "$TEMP_FILTERED" "$TEMP_IPS"

# Count unique IPs found
UNIQUE_IPS=$(wc -l < "$TEMP_IPS" 2>/dev/null || echo 0)
log_msg info "Found $UNIQUE_IPS unique external IP addresses"

# Show what we found for debugging
if [ "$UNIQUE_IPS" -gt 0 ]; then
    log_msg info "IPs found in pflog:"
    cat "$TEMP_IPS" | while read ip; do
        log_msg info "  $ip"
    done
fi

if [ "$UNIQUE_IPS" -eq 0 ]; then
    log_msg warn "No external IPs found despite $PORT_HITS scan attempts"
    log_msg info "This could mean all scans are from private IPs or localhost"
    rm -f "$TEMP_IPS"
    exit 0
fi

# 5. Merge existing blocklist with new IPs
log_msg info "Processing new IPs..."
TEMP_COMBINED=$(mktemp /tmp/pfscan_combined.XXXXXX)

{
    # Keep existing entries
    [ -f "$BLOCKLIST_FILE" ] && cat "$BLOCKLIST_FILE" 2>/dev/null
    # Add new IPs
    cat "$TEMP_IPS" 2>/dev/null
} | sort -u > "$TEMP_COMBINED"

# Calculate how many new IPs were added
OLD_COUNT=$(wc -l < "$BLOCKLIST_FILE" 2>/dev/null || echo 0)
NEW_COUNT=$(wc -l < "$TEMP_COMBINED" 2>/dev/null || echo 0)
ADDED_COUNT=$((NEW_COUNT - OLD_COUNT))

# Replace the blocklist file with updated version
if [ "$ADDED_COUNT" -gt 0 ]; then
    cp "$TEMP_COMBINED" "$BLOCKLIST_FILE"
    chmod 644 "$BLOCKLIST_FILE"
    log_msg success "Updated blocklist file: $BLOCKLIST_FILE"
    print_msg status "Added $ADDED_COUNT new IPs to blocklist"
    
    # Show the new IPs
    log_msg info "New IPs found:"
    # Use comm to find differences, or just show all from TEMP_IPS
    cat "$TEMP_IPS" | while read ip; do
        log_msg info "  $ip"
    done
    
    # Add new IPs to PF table immediately
    log_msg info "Adding new IPs to PF table..."
    ADDED_TO_PF=0
    while IFS= read -r ip; do
        [ -z "$ip" ] && continue
        
        if add_ip_to_pf "$ip"; then
            ADDED_TO_PF=$((ADDED_TO_PF + 1))
        fi
    done < "$TEMP_IPS"
    
    log_msg info "Added $ADDED_TO_PF IPs to PF table"
else
    log_msg info "No new IPs to add to blocklist"
fi

# Backup old blocklist for comparison next time
cp "$BLOCKLIST_FILE" "$BLOCKLIST_FILE.old" 2>/dev/null || true

# Clean up temp files
rm -f "$TEMP_IPS" "$TEMP_COMBINED"

# 6. Clean blocklist again to ensure no invalid entries
clean_blocklist

# 7. Show current blocklist count
CURRENT_BLOCKS=$(wc -l < "$BLOCKLIST_FILE" 2>/dev/null || echo 0)
log_msg info "Current blocklist contains: $CURRENT_BLOCKS IP addresses"

# 8. Update PF table with complete blocklist
print_msg info "### UPDATING PF CONFIGURATION ###"
update_pf_table

# 9. Show PF table status
log_msg info "### PF TABLE STATUS ###"
if pfctl -t "$PF_TABLE" -T show 2>/dev/null | head -5 >/dev/null 2>&1; then
    TABLE_SIZE=$(pfctl -t "$PF_TABLE" -T show 2>/dev/null | wc -l)
    log_msg info "PF table '$PF_TABLE' contains: $TABLE_SIZE entries"
    
    if [ "$TABLE_SIZE" -gt 0 ]; then
        log_msg info "Sample of blocked IPs:"
        pfctl -t "$PF_TABLE" -T show 2>/dev/null | head -5 | while read ip; do
            log_msg info "  $ip"
        done
        
        if [ "$TABLE_SIZE" -gt 5 ]; then
            log_msg info "  ... and $((TABLE_SIZE - 5)) more"
        fi
    fi
else
    log_msg warn "PF table '$PF_TABLE' is empty or doesn't exist"
fi

# 10. Final verification
log_msg info "### VERIFICATION ###"
log_msg info "1. Check PF table: pfctl -t $PF_TABLE -T show | wc -l"
log_msg info "2. Reload PF if needed: pfctl -f /etc/pf.conf"
log_msg info "3. Check PF status: pfctl -s rules | grep $PF_TABLE"

log_msg success "PF log analysis completed successfully"
log_msg info "Report saved to: $REPORT_FILE"

log_msg info "Blocklist saved to: $BLOCKLIST_FILE"
