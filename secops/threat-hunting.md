# Threat Hunting Guide

This guide helps security teams proactively hunt for threats, analyze indicators of compromise, and detect advanced persistent threats in their environment.

## Table of Contents

- [Threat Hunting Methodology](#threat-hunting-methodology)
- [Indicators of Compromise](#indicators-of-compromise)
- [Behavioral Analysis](#behavioral-analysis)
- [Network-Based Hunting](#network-based-hunting)
- [Host-Based Hunting](#host-based-hunting)
- [Cloud Environment Hunting](#cloud-environment-hunting)
- [Container and Kubernetes Hunting](#container-and-kubernetes-hunting)
- [Automated Threat Detection](#automated-threat-detection)

## Threat Hunting Methodology

### The SANS Threat Hunting Process

**Phase 1: Hypothesis Generation**
```bash
# Create threat hunting hypothesis
cat > create-hunting-hypothesis.sh << 'EOF'
#!/bin/bash
echo " Threat Hunting Hypothesis Generator "

THREAT_TYPE=$1
if [ -z "$THREAT_TYPE" ]; then
    echo "Usage: $0 <threat-type>"
    echo "Types: apt, insider, ransomware, cryptomining, lateral-movement, data-exfil"
    exit 1
fi

case $THREAT_TYPE in
    "apt")
        echo "APT Threat Hunting Hypothesis:"
        echo "- Attackers may use legitimate tools for persistence"
        echo "- Look for: unusual scheduled tasks, WMI events, registry modifications"
        echo "- Timeline: Focus on after-hours activity"
        echo "- Network: Beaconing patterns, unusual DNS queries"
        ;;
    "insider")
        echo "Insider Threat Hunting Hypothesis:"
        echo "- Users accessing data outside normal patterns"
        echo "- Look for: bulk downloads, after-hours access, privilege escalation"
        echo "- Timeline: Focus on user behavior changes"
        echo "- Data: Unusual file access patterns, large data transfers"
        ;;
    "ransomware")
        echo "Ransomware Threat Hunting Hypothesis:"
        echo "- Attackers encrypt files systematically"
        echo "- Look for: high entropy file writes, process injection, shadow copy deletion"
        echo "- Timeline: Rapid file modification patterns"
        echo "- Network: C2 communication before encryption"
        ;;
    "cryptomining")
        echo "Cryptomining Threat Hunting Hypothesis:"
        echo "- Unauthorized use of compute resources"
        echo "- Look for: high CPU usage, mining pool connections"
        echo "- Timeline: Consistent resource utilization"
        echo "- Network: Stratum protocol connections"
        ;;
    "lateral-movement")
        echo "Lateral Movement Hunting Hypothesis:"
        echo "- Attackers move between systems after initial compromise"
        echo "- Look for: unusual authentication patterns, remote execution"
        echo "- Timeline: Sequential system access"
        echo "- Network: Internal reconnaissance, credential relay"
        ;;
    "data-exfil")
        echo "Data Exfiltration Hunting Hypothesis:"
        echo "- Attackers extract sensitive data"
        echo "- Look for: large outbound transfers, data compression"
        echo "- Timeline: Off-hours bulk transfers"
        echo "- Network: Unusual upload patterns, encrypted channels"
        ;;
esac

echo ""
echo "Recommended hunting timeframe: 30-90 days"
echo "Key data sources: logs, network traffic, endpoint telemetry"
echo "Success criteria: Identify at least 3 potential indicators"
EOF

chmod +x create-hunting-hypothesis.sh
```

**Phase 2: Investigation**
```bash
# Threat hunting investigation framework
cat > threat-hunt-investigate.sh << 'EOF'
#!/bin/bash
echo " Threat Hunting Investigation Framework ==="

HUNT_TYPE=$1
TIMEFRAME=${2:-"7d"}
OUTPUT_DIR="hunt-$(date +%Y%m%d-%H%M%S)"

mkdir -p $OUTPUT_DIR/{network,host,timeline,indicators}

echo "Starting threat hunt: $HUNT_TYPE"
echo "Timeframe: $TIMEFRAME"
echo "Output directory: $OUTPUT_DIR"

# Host-based investigation
echo "1. Collecting host-based artifacts..."

# Process analysis
ps aux --sort=-%cpu | head -20 > $OUTPUT_DIR/host/high-cpu-processes.txt
ps aux --sort=-%mem | head -20 > $OUTPUT_DIR/host/high-memory-processes.txt

# Find processes with network connections
lsof -i | grep ESTABLISHED > $OUTPUT_DIR/host/network-connections.txt

# Check for unusual process trees
pstree -p > $OUTPUT_DIR/host/process-tree.txt

# Look for persistence mechanisms
crontab -l > $OUTPUT_DIR/host/user-crontab.txt 2>/dev/null || echo "No user crontab" > $OUTPUT_DIR/host/user-crontab.txt
cat /etc/crontab > $OUTPUT_DIR/host/system-crontab.txt 2>/dev/null

# Check systemd services
systemctl list-units --type=service --state=running > $OUTPUT_DIR/host/running-services.txt

# Network investigation
echo "2. Collecting network artifacts..."

# Active connections
netstat -tulpn > $OUTPUT_DIR/network/listening-ports.txt
ss -tulpn > $OUTPUT_DIR/network/socket-stats.txt

# DNS analysis
if [ -f /var/log/syslog ]; then
    grep -E "dnsmasq|named|resolver" /var/log/syslog | tail -100 > $OUTPUT_DIR/network/dns-activity.txt
fi

# Look for unusual network patterns
netstat -an | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn > $OUTPUT_DIR/network/connection-summary.txt

# Timeline analysis
echo "3. Creating timeline..."
echo "Timeline Analysis for $HUNT_TYPE hunt" > $OUTPUT_DIR/timeline/hunt-timeline.txt
echo "Generated: $(date)" >> $OUTPUT_DIR/timeline/hunt-timeline.txt
echo "" >> $OUTPUT_DIR/timeline/hunt-timeline.txt

# System events timeline
if [ -f /var/log/auth.log ]; then
    echo "Authentication Events:" >> $OUTPUT_DIR/timeline/hunt-timeline.txt
    grep -E "session opened|session closed|sudo:" /var/log/auth.log | tail -50 >> $OUTPUT_DIR/timeline/hunt-timeline.txt
fi

# Process creation timeline
if command -v auditctl > /dev/null; then
    echo "Process Execution Events:" >> $OUTPUT_DIR/timeline/hunt-timeline.txt
    ausearch -m EXECVE -ts recent | head -20 >> $OUTPUT_DIR/timeline/hunt-timeline.txt 2>/dev/null || echo "No audit logs available" >> $OUTPUT_DIR/timeline/hunt-timeline.txt
fi

# Indicator extraction
echo "4. Extracting indicators..."

# IP addresses
grep -E -o "([0-9]{1,3}\.){3}[0-9]{1,3}" $OUTPUT_DIR/network/*.txt | sort | uniq > $OUTPUT_DIR/indicators/ip-addresses.txt

# Domain names
grep -E -o "[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}" $OUTPUT_DIR/network/*.txt | grep -v -E "(localhost|127\.0\.0\.1)" | sort | uniq > $OUTPUT_DIR/indicators/domains.txt

# File hashes (if files modified recently)
find /tmp /var/tmp -type f -mtime -1 -exec sha256sum {} \; 2>/dev/null > $OUTPUT_DIR/indicators/recent-file-hashes.txt

# Process names
awk '{print $11}' $OUTPUT_DIR/host/high-cpu-processes.txt | sort | uniq > $OUTPUT_DIR/indicators/process-names.txt

echo "Investigation complete. Review findings in $OUTPUT_DIR/"
EOF

chmod +x threat-hunt-investigate.sh
```

## Indicators of Compromise

### Network IoCs
```bash
# Network-based IoC detection
cat > hunt-network-iocs.sh << 'EOF'
#!/bin/bash
echo "Network IoC Hunting"

# DNS-based indicators
echo "1. Hunting DNS anomalies..."

# Look for DNS tunneling
if command -v tcpdump > /dev/null; then
    echo "  Checking for DNS tunneling indicators..."
    tcpdump -i any -c 100 -nn "port 53" 2>/dev/null | \
    awk '{if(length($NF) > 20) print "Long DNS query: " $NF}' > dns-anomalies.txt
fi

# Check for DGA (Domain Generation Algorithm) patterns
echo "  Analyzing domain names for DGA patterns..."
cat > detect-dga.py << 'DGA_SCRIPT'
#!/usr/bin/env python3
import re
import sys
from collections import Counter

def analyze_domain(domain):
    """Analyze domain for DGA characteristics"""
    if not domain or '.' not in domain:
        return False
    
    # Remove TLD for analysis
    domain_name = domain.split('.')[0]
    
    # DGA indicators
    indicators = 0
    
    # Length check (DGA domains often long)
    if len(domain_name) > 12:
        indicators += 1
    
    # Entropy check (randomness)
    char_freq = Counter(domain_name.lower())
    entropy = -sum((freq/len(domain_name)) * 
                  __import__('math').log2(freq/len(domain_name)) 
                  for freq in char_freq.values())
    
    if entropy > 3.5:  # High entropy suggests randomness
        indicators += 1
    
    # Consonant clusters
    consonant_clusters = len(re.findall(r'[bcdfghjklmnpqrstvwxyz]{3,}', domain_name.lower()))
    if consonant_clusters > 2:
        indicators += 1
    
    # Vowel ratio
    vowels = len(re.findall(r'[aeiou]', domain_name.lower()))
    if vowels < len(domain_name) * 0.2:  # Less than 20% vowels
        indicators += 1
    
    # Dictionary words check (simple)
    common_words = ['the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'her', 'was', 'one', 'our', 'had', 'day']
    has_common_word = any(word in domain_name.lower() for word in common_words)
    if not has_common_word and len(domain_name) > 8:
        indicators += 1
    
    return indicators >= 3

# Test with domains from network logs
domains = [
    "google.com",
    "kjhgfdsaqwertyuio.com",
    "xvzpqmkjhgfd.net", 
    "facebook.com",
    "qwertasdfzxcv.org"
]

print("DGA Domain Analysis:")
for domain in domains:
    result = "SUSPICIOUS" if analyze_domain(domain) else "LEGITIMATE"
    print(f"  {domain}: {result}")
DGA_SCRIPT

python3 detect-dga.py

# HTTP/HTTPS traffic analysis
echo "2. Analyzing HTTP traffic patterns..."

# Look for unusual User-Agent strings
if [ -f /var/log/apache2/access.log ] || [ -f /var/log/nginx/access.log ]; then
    echo "  Checking for suspicious User-Agent strings..."
    for log in /var/log/apache2/access.log /var/log/nginx/access.log; do
        if [ -f "$log" ]; then
            awk -F'"' '{print $6}' "$log" | sort | uniq -c | sort -nr | head -10 > suspicious-user-agents.txt
        fi
    done
fi

# Certificate analysis
echo "3. SSL/TLS certificate hunting..."
echo "  Looking for suspicious certificates..."

# Check for self-signed certificates in connections
openssl s_client -connect google.com:443 -servername google.com < /dev/null 2>/dev/null | \
openssl x509 -noout -subject -issuer 2>/dev/null | grep -E "Subject:|Issuer:" || echo "No certificate analysis available"

echo "Network IoC hunting complete"
EOF

chmod +x hunt-network-iocs.sh
```

### Host-Based IoCs
```bash
# Host-based IoC detection
cat > hunt-host-iocs.sh << 'EOF'
#!/bin/bash
echo "Host-Based IoC Hunting ==="

# File system indicators
echo "1. File system IoC hunting..."

# Look for recently modified system files
echo "  Checking for recently modified system files..."
find /bin /sbin /usr/bin /usr/sbin -type f -mtime -7 -ls 2>/dev/null | head -20 > recent-system-files.txt

# Check for unusual file locations
echo "  Scanning for files in unusual locations..."
find /tmp /var/tmp /dev/shm -type f -name ".*" -o -name "*backup*" -o -name "*tmp*" 2>/dev/null > suspicious-files.txt

# Look for large files (potential data collection)
echo "  Finding large files (potential data staging)..."
find / -type f -size +100M 2>/dev/null | grep -v -E "/proc|/sys|/dev" | head -10 > large-files.txt

# Registry/configuration hunting
echo "2. Configuration and persistence hunting..."

# Check for unusual scheduled tasks
echo "  Analyzing scheduled tasks..."
crontab -l > user-crontabs.txt 2>/dev/null || echo "No user crontab"
ls -la /etc/cron.* > system-cron-files.txt 2>/dev/null

# Systemd persistence
echo "  Checking systemd services..."
systemctl list-unit-files | grep enabled | grep -v "@" > enabled-services.txt

# Process analysis
echo "3. Process-based hunting..."

# Look for processes without parent processes (orphans)
echo "  Finding orphaned processes..."
ps -eo pid,ppid,cmd | awk '$2 == 1 && $1 != 1 {print}' > orphaned-processes.txt

# Check for processes running from unusual locations
echo "  Processes from unusual locations..."
ps aux | grep -E "/tmp|/var/tmp|/dev/shm" | grep -v grep > processes-unusual-locations.txt

# Memory analysis indicators
echo "4. Memory-based hunting..."

# Check for process hollowing indicators
echo "  Looking for process hollowing indicators..."
ps aux | awk '{print $2, $11}' | while read pid cmd; do
    if [ -d "/proc/$pid" ]; then
        exe_path=$(readlink "/proc/$pid/exe" 2>/dev/null)
        if [ "$exe_path" != "$cmd" ] && [ -n "$exe_path" ]; then
            echo "Process $pid: exe=$exe_path, cmd=$cmd" >> process-hollowing-indicators.txt
        fi
    fi
done

# Network connections from processes
echo "5. Network-based process analysis..."
lsof -i | grep ESTABLISHED | while read line; do
    process=$(echo "$line" | awk '{print $1}')
    pid=$(echo "$line" | awk '{print $2}')
    connection=$(echo "$line" | awk '{print $9}')
    
    # Check if process is commonly seen with network connections
    if echo "$process" | grep -qE "^(nc|netcat|ncat|socat|curl|wget)$"; then
        echo "Suspicious network process: $process (PID: $pid) -> $connection" >> suspicious-network-processes.txt
    fi
done

# Lateral movement indicators
echo "6. Lateral movement hunting..."

# Check for unusual authentication patterns
if [ -f /var/log/auth.log ]; then
    echo "  Analyzing authentication patterns..."
    
    # Multiple failed then successful logins
    grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr | head -10 > failed-login-sources.txt
    
    # Successful logins from previously failed IPs
    failed_ips=$(awk '{print $2}' failed-login-sources.txt)
    for ip in $failed_ips; do
        if grep -q "Accepted.*from $ip" /var/log/auth.log; then
            echo "IP $ip: Failed logins followed by successful login" >> lateral-movement-indicators.txt
        fi
    done
fi

# Check for remote execution tools
echo "  Looking for remote execution indicators..."
ps aux | grep -E "psexec|winrm|wmic|powershell|ssh.*-t.*bash" | grep -v grep > remote-execution-tools.txt

echo "Host-based IoC hunting complete"
echo "Review generated files: *.txt"
EOF

chmod +x hunt-host-iocs.sh
```

## Behavioral Analysis

### User Behavior Analytics
```bash
# User behavior analysis for threat hunting
cat > hunt-user-behavior.sh << 'EOF'
#!/bin/bash
echo "User Behavior Analysis"

# Authentication behavior analysis
echo "1. Authentication behavior analysis..."

if [ -f /var/log/auth.log ]; then
    # Analyze login times
    echo "  Analyzing login time patterns..."
    grep "session opened" /var/log/auth.log | awk '{print $3, $9}' | sort > user-login-times.txt
    
    # Find after-hours activity (outside 6 AM - 10 PM)
    echo "  Identifying after-hours activity..."
    awk '{
        time = $1
        user = $2
        hour = int(substr(time, 1, 2))
        if (hour < 6 || hour > 22) {
            print "After-hours login: " user " at " time
        }
    }' user-login-times.txt > after-hours-activity.txt
    
    # Multiple simultaneous sessions
    echo "  Checking for concurrent sessions..."
    grep "session opened" /var/log/auth.log | awk '{print $9}' | sort | uniq -c | awk '$1 > 3 {print "Multiple sessions: " $2 " (" $1 " concurrent)"}' > multiple-sessions.txt
fi

# Data access patterns
echo "2. Data access behavior analysis..."

# File access monitoring
echo "  Monitoring file access patterns..."
if command -v auditctl > /dev/null; then
    # Look for bulk file access
    ausearch -m PATH -ts recent | grep -E "\.doc|\.pdf|\.xls|\.txt|\.csv" | awk '{print $NF}' | sort | uniq -c | sort -nr | head -20 > bulk-file-access.txt
fi

# Large file operations
echo "  Analyzing large file operations..."
find /home -type f -size +50M -exec ls -lah {} \; 2>/dev/null | awk '{print $6, $7, $8, $9}' > large-file-activity.txt

# Network behavior analysis
echo "3. Network behavior analysis..."

# Unusual data transfer volumes
echo "  Checking data transfer patterns..."
if command -v iftop > /dev/null; then
    # This would typically be run for monitoring, showing usage pattern
    echo "Monitor network usage with: iftop -t -s 60 -L 10"
fi

# Process behavior analysis
echo "4. Process execution behavior..."

# Unusual process execution patterns
echo "  Analyzing process execution..."
ps aux --sort=pcpu | head -20 | while read line; do
    user=$(echo "$line" | awk '{print $1}')
    cpu=$(echo "$line" | awk '{print $3}')
    cmd=$(echo "$line" | awk '{for(i=11;i<=NF;i++) printf "%s ", $i; print ""}')
    
    # Flag high CPU usage by non-system users
    if [ "$user" != "root" ] && [ "$user" != "www-data" ] && [ "$user" != "mysql" ]; then
        if (( $(echo "$cpu > 20" | bc -l 2>/dev/null || echo 0) )); then
            echo "High CPU usage by $user: $cpu% - $cmd" >> unusual-process-activity.txt
        fi
    fi
done 2>/dev/null

echo "User behavior analysis complete"
EOF

chmod +x hunt-user-behavior.sh
```

## Automated Threat Detection

### Machine Learning-Based Detection
```bash
# Automated threat detection using statistical analysis
cat > automated-threat-detection.sh << 'EOF'
#!/bin/bash
echo "Automated Threat Detection"

# Statistical anomaly detection
echo "1. Statistical anomaly detection..."

# Create baseline metrics
cat > create-baseline.py << 'BASELINE_SCRIPT'
#!/usr/bin/env python3
import json
import statistics
from collections import defaultdict, Counter
import subprocess
import re
from datetime import datetime, timedelta

class ThreatHunter:
    def __init__(self):
        self.baselines = {}
        self.anomalies = []
    
    def collect_network_metrics(self):
        """Collect network connection metrics"""
        try:
            result = subprocess.run(['netstat', '-tuln'], capture_output=True, text=True)
            connections = result.stdout.split('\n')
            
            listening_ports = []
            for conn in connections:
                if 'LISTEN' in conn:
                    port = re.search(r':(\d+)', conn)
                    if port:
                        listening_ports.append(int(port.group(1)))
            
            return {
                'listening_ports_count': len(listening_ports),
                'unique_ports': len(set(listening_ports)),
                'ports': listening_ports
            }
        except:
            return {'listening_ports_count': 0, 'unique_ports': 0, 'ports': []}
    
    def collect_process_metrics(self):
        """Collect process metrics"""
        try:
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            processes = result.stdout.split('\n')[1:]  # Skip header
            
            cpu_usage = []
            mem_usage = []
            process_names = []
            
            for proc in processes:
                if proc.strip():
                    parts = proc.split()
                    if len(parts) >= 11:
                        try:
                            cpu = float(parts[2])
                            mem = float(parts[3])
                            name = parts[10]
                            
                            cpu_usage.append(cpu)
                            mem_usage.append(mem)
                            process_names.append(name)
                        except ValueError:
                            continue
            
            return {
                'total_processes': len(process_names),
                'avg_cpu': statistics.mean(cpu_usage) if cpu_usage else 0,
                'max_cpu': max(cpu_usage) if cpu_usage else 0,
                'avg_mem': statistics.mean(mem_usage) if mem_usage else 0,
                'process_diversity': len(set(process_names))
            }
        except:
            return {'total_processes': 0, 'avg_cpu': 0, 'max_cpu': 0, 'avg_mem': 0, 'process_diversity': 0}
    
    def detect_anomalies(self, current_metrics, baseline_metrics):
        """Detect statistical anomalies"""
        anomalies = []
        
        for metric, current_value in current_metrics.items():
            if metric in baseline_metrics:
                baseline_value = baseline_metrics[metric]
                
                # Simple threshold-based detection (could be improved with ML)
                if isinstance(current_value, (int, float)) and isinstance(baseline_value, (int, float)):
                    if baseline_value > 0:
                        change_percentage = abs(current_value - baseline_value) / baseline_value
                        if change_percentage > 0.5:  # 50% change threshold
                            anomalies.append({
                                'metric': metric,
                                'current': current_value,
                                'baseline': baseline_value,
                                'change_percent': change_percentage * 100,
                                'severity': 'HIGH' if change_percentage > 1.0 else 'MEDIUM'
                            })
        
        return anomalies
    
    def run_detection(self):
        """Main detection logic"""
        print("Collecting current metrics...")
        
        current_network = self.collect_network_metrics()
        current_process = self.collect_process_metrics()
        
        current_metrics = {**current_network, **current_process}
        
        # For demo purposes, create a baseline (normally loaded from historical data)
        baseline_metrics = {
            'listening_ports_count': 15,
            'unique_ports': 12,
            'total_processes': 150,
            'avg_cpu': 2.5,
            'max_cpu': 15.0,
            'avg_mem': 1.8,
            'process_diversity': 85
        }
        
        print("Detecting anomalies...")
        anomalies = self.detect_anomalies(current_metrics, baseline_metrics)
        
        print("\nThreat Detection Results:")
        print("=" * 40)
        
        if anomalies:
            for anomaly in anomalies:
                print(f"[{anomaly['severity']}] {anomaly['metric']}")
                print(f"  Current: {anomaly['current']}")
                print(f"  Baseline: {anomaly['baseline']}")
                print(f"  Change: {anomaly['change_percent']:.1f}%")
                print()
        else:
            print("No significant anomalies detected")
        
        # Save results
        with open('threat-detection-results.json', 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'current_metrics': current_metrics,
                'baseline_metrics': baseline_metrics,
                'anomalies': anomalies
            }, f, indent=2)

if __name__ == "__main__":
    hunter = ThreatHunter()
    hunter.run_detection()
BASELINE_SCRIPT

python3 create-baseline.py

# IOC correlation
echo "2. IoC correlation analysis..."

# Create IoC database
cat > correlate-iocs.sh << 'IOC_CORRELATE'
#!/bin/bash

# Collect all IoCs from hunt activities
IOC_DB="threat-iocs.txt"
echo "# Threat IoC Database - $(date)" > $IOC_DB

# Extract IPs from previous hunts
if [ -f ip-addresses.txt ]; then
    echo "# IP Addresses" >> $IOC_DB
    cat ip-addresses.txt >> $IOC_DB
fi

# Extract domains
if [ -f domains.txt ]; then
    echo "# Domains" >> $IOC_DB
    cat domains.txt >> $IOC_DB
fi

# Extract file hashes
if [ -f recent-file-hashes.txt ]; then
    echo "# File Hashes" >> $IOC_DB
    cat recent-file-hashes.txt >> $IOC_DB
fi

# Cross-reference with threat intelligence
echo "Cross-referencing with known IoCs..."

# Simulate threat intelligence lookup (replace with real TI feeds)
cat > check-threat-intel.py << 'TI_CHECK'
#!/usr/bin/env python3
import re
import requests
import json

def check_ip_reputation(ip):
    # Placeholder for real threat intelligence lookup
    # In practice, you'd use APIs like VirusTotal, AlienVault OTX, etc.
    suspicious_ips = ['192.168.100.100', '10.0.0.50']  # Example suspicious IPs
    return ip in suspicious_ips

def check_domain_reputation(domain):
    # Placeholder for domain reputation check
    suspicious_domains = ['malicious.com', 'badactor.net']
    return domain in suspicious_domains

# Read IoCs and check reputation
print("Threat Intelligence Correlation:")
print("=" * 40)

with open('threat-iocs.txt', 'r') as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith('#'):
            # Check if it's an IP
            if re.match(r'\d+\.\d+\.\d+\.\d+', line):
                if check_ip_reputation(line):
                    print(f" MALICIOUS IP: {line}")
            
            # Check if it's a domain
            elif '.' in line and not line.startswith('/'):
                if check_domain_reputation(line):
                    print(f" MALICIOUS DOMAIN: {line}")

TI_CHECK

python3 check-threat-intel.py

echo "Automated threat detection complete"
EOF

chmod +x automated-threat-detection.sh
```

This threat hunting guide provides systematic approaches to proactively hunt for threats using hypothesis-driven investigation, behavioral analysis, and automated detection techniques. The scripts help security teams identify advanced threats that may evade traditional security controls.