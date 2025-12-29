pf_scanner.ksh - OpenBSD PF Log Analyzer & Auto-Blocker

Overview:

pf_scanner.ksh is an automated security tool for OpenBSD that analyzes pflog files, detects attackers, and automatically blocks malicious IPs using PF (Packet Filter).

Features:

Real-time PF log analysis
Automatic IP blocking
Port scan detection (SSH, HTTP, RDP, etc.)
IP validation & deduplication
PF table synchronization
Detailed colored logging
Root-only security

Requirements:

OS: OpenBSD (tested on v7.8)
Shell: KornShell (ksh v5.2.14+)
Root access: Required
Tools: tcpdump, pfctl

Installation
1. Copy Script
cp pf_scanner.ksh /usr/local/bin/
chmod 750 /usr/local/bin/pf_scanner.ksh

2. Create Blocklist Directory
mkdir -p /etc/blocklist
touch /etc/blocklist/myblocklist.txt
chmod 644 /etc/blocklist/myblocklist.txt

3. Configure PF
Edit /etc/pf.conf and add:
table <myblocklist> persist file "/etc/blocklist/myblocklist.txt"
block in quick from <myblocklist>

Reload PF:
pfctl -f /etc/pf.conf

4. Enable pflogd

rcctl enable pflogd
rcctl start pflogd

Usage
Manual Run
doas ./pf_scanner.ksh

Automated (Cron)

Add to root's crontab (crontab -e):

# Run every 15 minutes
*/15 * * * * /usr/local/bin/pf_scanner.ksh

Configuration:
Edit these variables in the script:

LOGFILE="/var/log/pflog"                    # PF log file
BLOCKLIST_FILE="/etc/blocklist/myblocklist.txt"  # Blocklist storage
REPORT_FILE="pf_scan.log"                   # Script log file
PF_TABLE="myblocklist"                      # PF table name

# Ports to monitor
PORTS="22 23 80 443 3389 21 25 53 135 139 445 1433 3306 5432"

      

How It Works:

Checks root permissions
Validates files & tools
Cleans existing blocklist
Analyzes pflog for attacks
Extracts malicious external IPs
Updates blocklist & PF table
Generates detailed report

Output Files:

/etc/blocklist/myblocklist.txt - Blocked IPs
pf_scan.log - Execution log (script directory)
/etc/blocklist/myblocklist.txt.old - Backup

Verification Commands:

# Show blocked IPs
pfctl -t myblocklist -T show

# Count blocked IPs
pfctl -t myblocklist -T show | wc -l

# Check PF rules
pfctl -s rules | grep myblocklist

      

Safety Features:

Validates all IPv4 addresses
Never blocks private IPs (RFC 1918)
Removes duplicates automatically
Comprehensive error handling
Clean exit on termination

Troubleshooting:
Common Issues:
"pflog file not found" run rcctl check pflogd
ls -la /var/log/pflog
"tcpdump not found" run pkg_add tcpdump

PF table issues:
pfctl -f /etc/pf.conf
pfctl -t myblocklist -T show

      

Permission denied:
doas ./pf_scanner.ksh

Debug Mode:

Add set -x near top of script for verbose output.
Sample Log

01-01-24 14:30:45 - [INFO] Script started
01-01-24 14:30:46 - [INFO] Total packets in pflog: 1250
01-01-24 14:30:47 - [INFO] Port 22: 45 connection attempts
01-01-24 14:30:48 - [SUCCESS] Added 192.0.2.100 to PF table

License: MIT License
Author: Coldboot
Version: 1.0
Security Notes:
Requires root - review code before use

Monitor blocklist regularly
