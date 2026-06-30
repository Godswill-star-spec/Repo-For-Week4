#!/bin/bash

LOGFILE="payliteNG_auth.log"
NMAPFILE="vuln_scan2.nmap"

echo "=== Failed login count ==="
grep -c "Failed password" "$LOGFILE"

echo "=== Failed attempts by user and source IP ==="
grep "Failed password" "$LOGFILE" | awk '{print $8, $10}' | sort | uniq -c

echo "=== Successful logins ==="
grep "Accepted password" "$LOGFILE"

echo "=== Sessions opened ==="
grep "session opened" "$LOGFILE"

echo "=== Sudo activity ==="
grep "sudo:" "$LOGFILE"

echo "=== Sessions closed ==="
grep "session closed" "$LOGFILE"

echo "=== Unique source IPs in auth log ==="
grep -Eo "([0-9]{1,3}\.){3}[0-9]{1,3}" "$LOGFILE" | sort -u

echo "=== Root account targeted ==="
grep "for root" "$LOGFILE"

echo "=== Open ports and services from Nmap scan ==="
grep -E "^[0-9]+/tcp" "$NMAPFILE"

echo "=== Target IP from Nmap scan ==="
grep "Nmap scan report for" "$NMAPFILE" | awk '{print $5}'

echo "=== vsftpd version check ==="
grep -i "vsftpd" "$NMAPFILE"

echo "=== CVE and CVSS reference list ==="
echo "CVE-2011-2523 | vsftpd 2.3.4 Backdoor | CVSS v3.0: 9.8 CRITICAL | https://nvd.nist.gov/vuln/detail/CVE-2011-2523"
echo "CVE-2010-2075 | UnrealIRCd 3.2.8.1 Backdoor | CVSS v3.0: 9.8 CRITICAL | https://nvd.nist.gov/vuln/detail/CVE-2010-2075"
echo "CVE-2007-2447 | Samba usermap_script Command Execution | CVSS v2: 6.0 MEDIUM | https://nvd.nist.gov/vuln/detail/CVE-2007-2447"
echo "CVE-2011-3556 | Java RMI Registry Remote Code Execution class | CVSS v2: 7.5 HIGH | https://nvd.nist.gov/vuln/detail/CVE-2011-3556"

echo "=== MITRE ATT&CK reference list ==="
echo "TA0043 Reconnaissance | https://attack.mitre.org/tactics/TA0043/"
echo "T1595.001 Active Scanning: Scanning IP Blocks | https://attack.mitre.org/techniques/T1595/001/"
echo "TA0001 Initial Access | https://attack.mitre.org/tactics/TA0001/"
echo "T1190 Exploit Public-Facing Application | https://attack.mitre.org/techniques/T1190/"
echo "TA0002 Execution | https://attack.mitre.org/tactics/TA0002/"
echo "T1059.004 Command and Scripting Interpreter: Unix Shell | https://attack.mitre.org/techniques/T1059/004/"
echo "TA0007 Discovery | https://attack.mitre.org/tactics/TA0007/"
echo "T1083 File and Directory Discovery | https://attack.mitre.org/techniques/T1083/"
