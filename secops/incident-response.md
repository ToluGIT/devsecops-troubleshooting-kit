# Security Incident Response & Digital Forensics Guide

This guide provides procedures for responding to security incidents, conducting digital forensics, and managing crisis situations in environments.



## Incident Classification & Triage

### Initial Assessment Framework

#### Issue: Determining incident severity and response priority

**Classification Matrix:**
```bash
# Incident classification script
cat > classify-incident.sh << 'EOF'
#!/bin/bash
echo "Security Incident Classification"

# Get incident details
read -p "Incident Type (malware/breach/dos/insider/other): " INCIDENT_TYPE
read -p "System Impact (none/low/medium/high/critical): " IMPACT
read -p "Data Classification (public/internal/confidential/restricted): " DATA_CLASS
read -p "Business Impact (none/low/medium/high/critical): " BUSINESS_IMPACT
read -p "Systems Affected (single/multiple/critical): " SYSTEMS_AFFECTED

# Calculate severity score
SEVERITY_SCORE=0

case $IMPACT in
    "critical") SEVERITY_SCORE=$((SEVERITY_SCORE + 5)) ;;
    "high") SEVERITY_SCORE=$((SEVERITY_SCORE + 4)) ;;
    "medium") SEVERITY_SCORE=$((SEVERITY_SCORE + 3)) ;;
    "low") SEVERITY_SCORE=$((SEVERITY_SCORE + 2)) ;;
    "none") SEVERITY_SCORE=$((SEVERITY_SCORE + 1)) ;;
esac

case $DATA_CLASS in
    "restricted") SEVERITY_SCORE=$((SEVERITY_SCORE + 4)) ;;
    "confidential") SEVERITY_SCORE=$((SEVERITY_SCORE + 3)) ;;
    "internal") SEVERITY_SCORE=$((SEVERITY_SCORE + 2)) ;;
    "public") SEVERITY_SCORE=$((SEVERITY_SCORE + 1)) ;;
esac

case $BUSINESS_IMPACT in
    "critical") SEVERITY_SCORE=$((SEVERITY_SCORE + 5)) ;;
    "high") SEVERITY_SCORE=$((SEVERITY_SCORE + 4)) ;;
    "medium") SEVERITY_SCORE=$((SEVERITY_SCORE + 3)) ;;
    "low") SEVERITY_SCORE=$((SEVERITY_SCORE + 2)) ;;
    "none") SEVERITY_SCORE=$((SEVERITY_SCORE + 1)) ;;
esac

# Determine incident level
if [ $SEVERITY_SCORE -ge 12 ]; then
    INCIDENT_LEVEL="CRITICAL"
    RESPONSE_TIME="Immediate (< 15 minutes)"
    ESCALATION="C-Level, Legal, PR"
elif [ $SEVERITY_SCORE -ge 9 ]; then
    INCIDENT_LEVEL="HIGH"
    RESPONSE_TIME="< 1 hour"
    ESCALATION="Security Manager, IT Director"
elif [ $SEVERITY_SCORE -ge 6 ]; then
    INCIDENT_LEVEL="MEDIUM"
    RESPONSE_TIME="< 4 hours"
    ESCALATION="Security Team Lead"
else
    INCIDENT_LEVEL="LOW"
    RESPONSE_TIME="< 24 hours"
    ESCALATION="Security Analyst"
fi

# Generate incident summary
INCIDENT_ID="INC-$(date +%Y%m%d-%H%M%S)"

cat > "incident-${INCIDENT_ID}.md" << INCIDENT_REPORT
# Security Incident Report

**Incident ID:** ${INCIDENT_ID}
**Classification:** ${INCIDENT_LEVEL}
**Created:** $(date)
**Reporter:** $(whoami)

## Incident Details
- **Type:** ${INCIDENT_TYPE}
- **Impact:** ${IMPACT}
- **Data Classification:** ${DATA_CLASS}
- **Business Impact:** ${BUSINESS_IMPACT}
- **Systems Affected:** ${SYSTEMS_AFFECTED}

## Response Parameters
- **Severity Score:** ${SEVERITY_SCORE}/15
- **Response Time:** ${RESPONSE_TIME}
- **Escalation Required:** ${ESCALATION}

## Initial Response Checklist
- [ ] Incident commander assigned
- [ ] Response team assembled
- [ ] Communication channels established
- [ ] Evidence preservation initiated
- [ ] Containment strategy developed

## Next Steps
1. Assemble incident response team
2. Begin evidence collection
3. Implement containment measures
4. Establish communication cadence
5. Document all actions taken

INCIDENT_REPORT

echo "ncident classified as: ${INCIDENT_LEVEL}"
echo "Report created: incident-${INCIDENT_ID}.md"
echo "Response time requirement: ${RESPONSE_TIME}"
echo "Escalation required: ${ESCALATION}"

# Auto-create response directories
mkdir -p "incident-${INCIDENT_ID}"/{evidence,communications,analysis,reports}
echo "Response directories created"
EOF

chmod +x classify-incident.sh
```

### Rapid Triage Process

**5-Minute Triage Checklist:**
```bash
# Rapid incident triage
cat > rapid-triage.sh << 'EOF'
#!/bin/bash
INCIDENT_ID=$1

if [ -z "$INCIDENT_ID" ]; then
    INCIDENT_ID="INC-$(date +%Y%m%d-%H%M%S)"
fi

echo "5-MINUTE SECURITY INCIDENT TRIAGE"
echo "Incident ID: $INCIDENT_ID"
echo "Start Time: $(date)"

# Create triage log
TRIAGE_LOG="triage-${INCIDENT_ID}.log"

echo "$(date): Starting rapid triage for $INCIDENT_ID" > $TRIAGE_LOG

# Question 1: Is this an active attack?
echo "1. ACTIVE ATTACK ASSESSMENT:"
read -p "   Are systems currently under active attack? (y/n): " ACTIVE_ATTACK
echo "$(date): Active attack: $ACTIVE_ATTACK" >> $TRIAGE_LOG

if [ "$ACTIVE_ATTACK" = "y" ]; then
    echo "   ACTIVE ATTACK - IMMEDIATE RESPONSE REQUIRED"
    echo "   Actions: Isolate affected systems, preserve evidence, notify incident commander"
fi

# Question 2: Data exposure assessment
echo "2. DATA EXPOSURE ASSESSMENT:"
read -p "   Is sensitive data potentially exposed? (y/n): " DATA_EXPOSED
echo "$(date): Data exposure: $DATA_EXPOSED" >> $TRIAGE_LOG

if [ "$DATA_EXPOSED" = "y" ]; then
    read -p "   Data type (PII/PHI/Financial/IP/Other): " DATA_TYPE
    echo "$(date): Data type: $DATA_TYPE" >> $TRIAGE_LOG
    echo " DATA EXPOSURE - Legal/Compliance notification may be required"
fi

# Question 3: Business impact
echo "3. BUSINESS IMPACT ASSESSMENT:"
read -p "   Are critical business operations affected? (y/n): " BUSINESS_IMPACT
echo "$(date): Business impact: $BUSINESS_IMPACT" >> $TRIAGE_LOG

if [ "$BUSINESS_IMPACT" = "y" ]; then
    echo " BUSINESS IMPACT - Executive notification required"
fi

# Question 4: System availability
echo "4. SYSTEM AVAILABILITY:"
read -p "   Are production systems down or degraded? (y/n): " SYSTEM_DOWN
echo "$(date): System availability: $SYSTEM_DOWN" >> $TRIAGE_LOG

# Question 5: Public exposure
echo "5. PUBLIC EXPOSURE:"
read -p "   Is this incident publicly visible/reported? (y/n): " PUBLIC_EXPOSURE
echo "$(date): Public exposure: $PUBLIC_EXPOSURE" >> $TRIAGE_LOG

if [ "$PUBLIC_EXPOSURE" = "y" ]; then
    echo " PUBLIC EXPOSURE - PR/Communications team notification required"
fi

# Calculate triage priority
PRIORITY_SCORE=0
[ "$ACTIVE_ATTACK" = "y" ] && PRIORITY_SCORE=$((PRIORITY_SCORE + 5))
[ "$DATA_EXPOSED" = "y" ] && PRIORITY_SCORE=$((PRIORITY_SCORE + 4))
[ "$BUSINESS_IMPACT" = "y" ] && PRIORITY_SCORE=$((PRIORITY_SCORE + 3))
[ "$SYSTEM_DOWN" = "y" ] && PRIORITY_SCORE=$((PRIORITY_SCORE + 3))
[ "$PUBLIC_EXPOSURE" = "y" ] && PRIORITY_SCORE=$((PRIORITY_SCORE + 2))

# Determine response level
if [ $PRIORITY_SCORE -ge 10 ]; then
    RESPONSE_LEVEL="EMERGENCY"
    RESPONSE_TIME="Immediate"
    TEAM_SIZE="Full response team"
elif [ $PRIORITY_SCORE -ge 6 ]; then
    RESPONSE_LEVEL="URGENT"
    RESPONSE_TIME="< 30 minutes"
    TEAM_SIZE="Core response team"
elif [ $PRIORITY_SCORE -ge 3 ]; then
    RESPONSE_LEVEL="STANDARD"
    RESPONSE_TIME="< 2 hours"
    TEAM_SIZE="Primary responders"
else
    RESPONSE_LEVEL="LOW"
    RESPONSE_TIME="< 8 hours"
    TEAM_SIZE="Security analyst"
fi

echo "$(date): Priority score: $PRIORITY_SCORE, Response level: $RESPONSE_LEVEL" >> $TRIAGE_LOG

echo ""
echo " TRIAGE RESULTS "
echo "Priority Score: $PRIORITY_SCORE/17"
echo "Response Level: $RESPONSE_LEVEL"
echo "Response Time: $RESPONSE_TIME"
echo "Team Required: $TEAM_SIZE"
echo "Triage Duration: $(($(date +%s) - $(stat -c %Y $TRIAGE_LOG))) seconds"

# Generate immediate actions
echo ""
echo " IMMEDIATE ACTIONS "
if [ "$ACTIVE_ATTACK" = "y" ]; then
    echo "1. ISOLATE affected systems immediately"
    echo "2. PRESERVE evidence before containment"
    echo "3. ACTIVATE incident commander"
fi

if [ "$DATA_EXPOSED" = "y" ]; then
    echo "4. ASSESS data exposure scope"
    echo "5. NOTIFY legal/compliance team"
fi

if [ "$PUBLIC_EXPOSURE" = "y" ]; then
    echo "6. ENGAGE communications team"
    echo "7. PREPARE public statement if needed"
fi

echo "$(date): Triage completed" >> $TRIAGE_LOG
echo "Triage log saved: $TRIAGE_LOG"
EOF

chmod +x rapid-triage.sh
```

## Digital Forensics & Evidence Collection

### Evidence Collection Framework

#### Volatile Evidence Collection

**Memory and System State:**
```bash
# Volatile evidence collection script
cat > collect-volatile-evidence.sh << 'EOF'
#!/bin/bash
TARGET_HOST=${1:-$(hostname)}
CASE_ID=${2:-"CASE-$(date +%Y%m%d-%H%M%S)"}
EVIDENCE_DIR="evidence/${CASE_ID}/volatile"

echo "VOLATILE EVIDENCE COLLECTION"
echo "Target: $TARGET_HOST"
echo "Case ID: $CASE_ID"
echo "Start Time: $(date)"

# Create evidence directory structure
mkdir -p "$EVIDENCE_DIR"/{memory,network,processes,filesystem,logs}

# Document collection environment
cat > "$EVIDENCE_DIR/collection-environment.txt" << ENV_INFO
Collection Details:
- Target Host: $TARGET_HOST
- Case ID: $CASE_ID
- Collector: $(whoami)
- Collection Time: $(date)
- Collection Host: $(hostname)
- Collection User: $(id)
- Working Directory: $(pwd)

System Information:
- OS: $(uname -a)
- Uptime: $(uptime)
- Current Time: $(date)
- Timezone: $(timedatectl show --no-pager --property=Timezone | cut -d= -f2)
ENV_INFO

echo "1. Collecting memory information..."
# Process memory information
ps aux --sort=-%mem | head -20 > "$EVIDENCE_DIR/memory/top-memory-processes.txt"
cat /proc/meminfo > "$EVIDENCE_DIR/memory/meminfo.txt"
free -h > "$EVIDENCE_DIR/memory/memory-usage.txt"

# Memory dump (if possible and appropriate)
if command -v memdump &>/dev/null && [ "$(id -u)" = "0" ]; then
    echo "   Creating memory dump..."
    memdump > "$EVIDENCE_DIR/memory/memory-dump.raw" 2>/dev/null || echo "Memory dump failed" > "$EVIDENCE_DIR/memory/memory-dump-failed.txt"
fi

echo "2. Collecting process information..."
ps auxwwef > "$EVIDENCE_DIR/processes/process-list-full.txt"
ps -eo pid,ppid,user,comm,args --forest > "$EVIDENCE_DIR/processes/process-tree.txt"
lsof +L1 > "$EVIDENCE_DIR/processes/deleted-files.txt" 2>/dev/null || true
lsof -i > "$EVIDENCE_DIR/processes/network-connections.txt" 2>/dev/null || true

# Process file descriptors for suspicious processes
mkdir -p "$EVIDENCE_DIR/processes/file-descriptors"
ps aux | awk 'NR>1 {print $2}' | head -20 | while read pid; do
    if [ -d "/proc/$pid/fd" ]; then
        ls -la "/proc/$pid/fd" > "$EVIDENCE_DIR/processes/file-descriptors/pid-$pid.txt" 2>/dev/null || true
    fi
done

echo "3. Collecting network information..."
netstat -tulpn > "$EVIDENCE_DIR/network/listening-ports.txt"
netstat -an > "$EVIDENCE_DIR/network/all-connections.txt"
ss -tulpn > "$EVIDENCE_DIR/network/socket-statistics.txt"
arp -a > "$EVIDENCE_DIR/network/arp-table.txt"
route -n > "$EVIDENCE_DIR/network/routing-table.txt"
ip route show > "$EVIDENCE_DIR/network/ip-routes.txt"

# Active connections with process information
lsof -i -P -n > "$EVIDENCE_DIR/network/connections-with-processes.txt" 2>/dev/null || true

echo "4. Collecting filesystem information..."
mount > "$EVIDENCE_DIR/filesystem/mounts.txt"
df -h > "$EVIDENCE_DIR/filesystem/disk-usage.txt"
lsof +L1 > "$EVIDENCE_DIR/filesystem/deleted-but-open-files.txt" 2>/dev/null || true

# Recent file modifications (last 24 hours)
find / -type f -mtime -1 -ls 2>/dev/null | head -1000 > "$EVIDENCE_DIR/filesystem/recent-modifications.txt"

# SUID/SGID files
find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null > "$EVIDENCE_DIR/filesystem/suid-sgid-files.txt"

echo "5. Collecting user and authentication info..."
who -a > "$EVIDENCE_DIR/processes/logged-in-users.txt"
last -n 50 > "$EVIDENCE_DIR/processes/login-history.txt"
lastlog > "$EVIDENCE_DIR/processes/last-login.txt"
w > "$EVIDENCE_DIR/processes/user-activity.txt"

# Check for unusual cron jobs
crontab -l > "$EVIDENCE_DIR/processes/user-crontab.txt" 2>/dev/null || echo "No user crontab" > "$EVIDENCE_DIR/processes/user-crontab.txt"
ls -la /etc/cron* > "$EVIDENCE_DIR/processes/system-cron.txt" 2>/dev/null || true

echo "6. Collecting system logs..."
# Copy recent system logs
if [ -d "/var/log" ]; then
    # System logs
    cp /var/log/syslog "$EVIDENCE_DIR/logs/" 2>/dev/null || true
    cp /var/log/auth.log "$EVIDENCE_DIR/logs/" 2>/dev/null || true
    cp /var/log/secure "$EVIDENCE_DIR/logs/" 2>/dev/null || true
    
    # Application logs (common locations)
    cp /var/log/apache2/access.log "$EVIDENCE_DIR/logs/" 2>/dev/null || true
    cp /var/log/nginx/access.log "$EVIDENCE_DIR/logs/" 2>/dev/null || true
fi

# Journal logs (systemd)
if command -v journalctl &>/dev/null; then
    journalctl --since "24 hours ago" > "$EVIDENCE_DIR/logs/systemd-journal-24h.txt"
    journalctl -u ssh --since "7 days ago" > "$EVIDENCE_DIR/logs/ssh-service-7d.txt" 2>/dev/null || true
fi

echo "7. Collecting containerized environment info..."
if command -v docker &>/dev/null; then
    docker ps -a > "$EVIDENCE_DIR/processes/docker-containers.txt" 2>/dev/null || true
    docker images > "$EVIDENCE_DIR/processes/docker-images.txt" 2>/dev/null || true
    docker network ls > "$EVIDENCE_DIR/network/docker-networks.txt" 2>/dev/null || true
fi

if command -v kubectl &>/dev/null; then
    kubectl get pods --all-namespaces -o wide > "$EVIDENCE_DIR/processes/kubernetes-pods.txt" 2>/dev/null || true
    kubectl get events --all-namespaces --sort-by='.lastTimestamp' > "$EVIDENCE_DIR/logs/kubernetes-events.txt" 2>/dev/null || true
fi

echo "8. Creating evidence integrity hashes..."
find "$EVIDENCE_DIR" -type f -exec md5sum {} \; > "$EVIDENCE_DIR/evidence-hashes.md5"
find "$EVIDENCE_DIR" -type f -exec sha256sum {} \; > "$EVIDENCE_DIR/evidence-hashes.sha256"

# Generate collection report
cat > "$EVIDENCE_DIR/collection-report.md" << REPORT
# Volatile Evidence Collection Report

**Case ID:** $CASE_ID
**Target Host:** $TARGET_HOST
**Collection Time:** $(date)
**Collector:** $(whoami)

## Collection Summary
- Process Information: Collected
- Memory Information: Collected
- Network Information: Collected
- Filesystem Information: Collected
- User Activity: Collected
- System Logs: Collected
- Container Information: $(command -v docker &>/dev/null && echo "Collected" || echo "Not Available")
- Kubernetes Information: $(command -v kubectl &>/dev/null && echo "Collected" || echo "Not Available")

## File Count
$(find "$EVIDENCE_DIR" -type f | wc -l) evidence files collected

## Evidence Integrity
- MD5 hashes: evidence-hashes.md5
- SHA256 hashes: evidence-hashes.sha256

## Next Steps
1. Archive evidence collection
2. Begin static analysis
3. Correlate with other evidence sources
4. Generate forensic timeline

REPORT

echo "Volatile evidence collection completed"
echo "Evidence location: $EVIDENCE_DIR"
echo "Files collected: $(find "$EVIDENCE_DIR" -type f | wc -l)"
echo "Integrity hashes generated"
echo "Collection duration: $(($(date +%s) - START_TIME)) seconds" 2>/dev/null || echo "Collection completed at $(date)"

# Create compressed archive for transfer
tar -czf "${CASE_ID}-volatile-evidence.tar.gz" -C "evidence/${CASE_ID}" .
echo "Evidence archived: ${CASE_ID}-volatile-evidence.tar.gz"
EOF

chmod +x collect-volatile-evidence.sh
```

#### Disk Imaging and Static Evidence

**Forensic Disk Imaging:**
```bash
# Forensic disk imaging script
cat > create-disk-image.sh << 'EOF'
#!/bin/bash
DEVICE=$1
CASE_ID=${2:-"CASE-$(date +%Y%m%d-%H%M%S)"}
EVIDENCE_DIR="evidence/${CASE_ID}/disk-images"

if [ -z "$DEVICE" ]; then
    echo "Usage: $0 <device> [case-id]"
    echo "Example: $0 /dev/sda CASE-2024-001"
    echo "Available devices:"
    lsblk
    exit 1
fi

if [ "$(id -u)" != "0" ]; then
    echo "Error: This script requires root privileges for disk imaging"
    exit 1
fi

echo "FORENSIC DISK IMAGING"
echo "Device: $DEVICE"
echo "Case ID: $CASE_ID"
echo "Start Time: $(date)"

# Create evidence directory
mkdir -p "$EVIDENCE_DIR"

# Verify device exists
if [ ! -b "$DEVICE" ]; then
    echo "Error: Device $DEVICE does not exist or is not a block device"
    exit 1
fi

# Get device information
DEVICE_SIZE=$(blockdev --getsize64 "$DEVICE" 2>/dev/null)
DEVICE_INFO=$(fdisk -l "$DEVICE" 2>/dev/null | head -5)

echo "Device size: $DEVICE_SIZE bytes"
echo "Device info: $DEVICE_INFO"

# Create device information file
cat > "$EVIDENCE_DIR/device-info.txt" << DEVICE_INFO
Device Information:
- Device: $DEVICE
- Case ID: $CASE_ID
- Imaging Time: $(date)
- Imaging Host: $(hostname)
- Imaging User: $(whoami)
- Device Size: $DEVICE_SIZE bytes

Block Device Information:
$(lsblk "$DEVICE" -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT)

Partition Information:
$(fdisk -l "$DEVICE" 2>/dev/null || parted "$DEVICE" print 2>/dev/null)

Hash Calculation Start: $(date)
DEVICE_INFO

# Calculate device hash before imaging
echo "Calculating pre-imaging hash..."
PRE_HASH=$(md5sum "$DEVICE" | cut -d' ' -f1)
echo "Pre-imaging MD5: $PRE_HASH" | tee -a "$EVIDENCE_DIR/device-info.txt"

# Create forensic image using dd
IMAGE_FILE="$EVIDENCE_DIR/${CASE_ID}-$(basename "$DEVICE")-image.dd"
LOG_FILE="$EVIDENCE_DIR/${CASE_ID}-$(basename "$DEVICE")-imaging.log"

echo "Creating forensic image..."
echo "Image file: $IMAGE_FILE"

# Use dd with error handling and progress monitoring
dd if="$DEVICE" of="$IMAGE_FILE" bs=64K conv=sync,noerror status=progress 2> "$LOG_FILE"

# Verify imaging completed successfully
if [ $? -eq 0 ]; then
    echo "Disk imaging completed successfully"
else
    echo "Disk imaging encountered errors - check $LOG_FILE"
fi

# Calculate post-imaging hashes
echo "Calculating post-imaging hashes..."
IMAGE_MD5=$(md5sum "$IMAGE_FILE" | cut -d' ' -f1)
IMAGE_SHA256=$(sha256sum "$IMAGE_FILE" | cut -d' ' -f1)

# Verify image integrity
POST_DEVICE_HASH=$(md5sum "$DEVICE" | cut -d' ' -f1)

cat >> "$EVIDENCE_DIR/device-info.txt" << HASH_INFO

Hash Verification:
- Pre-imaging Device MD5: $PRE_HASH
- Post-imaging Device MD5: $POST_DEVICE_HASH
- Image File MD5: $IMAGE_MD5
- Image File SHA256: $IMAGE_SHA256
- Hash Match: $([ "$PRE_HASH" = "$IMAGE_MD5" ] && echo " VERIFIED" || echo "MISMATCH")

Imaging Completed: $(date)
HASH_INFO

# Create hash files for evidence integrity
echo "$IMAGE_MD5 $IMAGE_FILE" > "$EVIDENCE_DIR/${CASE_ID}-hashes.md5"
echo "$IMAGE_SHA256 $IMAGE_FILE" > "$EVIDENCE_DIR/${CASE_ID}-hashes.sha256"

# Create evidence log
cat > "$EVIDENCE_DIR/evidence-log.md" << EVIDENCE_LOG
# Forensic Disk Image Evidence Log

**Case ID:** $CASE_ID
**Device:** $DEVICE
**Image File:** $IMAGE_FILE
**Created:** $(date)
**Created By:** $(whoami) on $(hostname)

## Imaging Details
- **Method:** dd with 64KB block size
- **Options:** conv=sync,noerror
- **Duration:** See imaging log
- **Size:** $(du -h "$IMAGE_FILE" | cut -f1)

## Integrity Verification
- **Pre-imaging MD5:** $PRE_HASH
- **Post-imaging MD5:** $POST_DEVICE_HASH
- **Image MD5:** $IMAGE_MD5
- **Image SHA256:** $IMAGE_SHA256
- **Verification Status:** $([ "$PRE_HASH" = "$IMAGE_MD5" ] && echo "VERIFIED" || echo "FAILED")

## Chain of Custody
- **Acquired By:** $(whoami)
- **Acquisition Date:** $(date)
- **Storage Location:** $EVIDENCE_DIR
- **Access Controls:** $(ls -la "$IMAGE_FILE" | awk '{print $1, $3, $4}')

## Next Steps
1. Mount image read-only for analysis
2. Extract file system artifacts
3. Conduct timeline analysis
4. Generate forensic report

EVIDENCE_LOG

echo ""
echo "=== IMAGING SUMMARY ==="
echo "Image file: $IMAGE_FILE"
echo "Image size: $(du -h "$IMAGE_FILE" | cut -f1)"
echo "Verification: $([ "$PRE_HASH" = "$IMAGE_MD5" ] && echo " PASSED" || echo "FAILED")"
echo "Evidence log: $EVIDENCE_DIR/evidence-log.md"

# Create read-only mount point for analysis
MOUNT_POINT="/mnt/forensic-${CASE_ID}"
echo "Creating read-only mount point: $MOUNT_POINT"
mkdir -p "$MOUNT_POINT"

# Provide next steps
cat << NEXT_STEPS

 NEXT STEPS FOR ANALYSIS 

1. Mount image read-only:
   sudo mount -o ro,loop "$IMAGE_FILE" "$MOUNT_POINT"

2. Extract file system timeline:
   fls -r -m "/" "$IMAGE_FILE" > "$EVIDENCE_DIR/filesystem-timeline.txt"

3. Extract deleted files:
   fls -rd "$IMAGE_FILE" > "$EVIDENCE_DIR/deleted-files.txt"

4. Search for artifacts:
   grep -r "password" "$MOUNT_POINT" 2>/dev/null | head -10

5. Unmount when finished:
   sudo umount "$MOUNT_POINT"

NEXT_STEPS

EOF

chmod +x create-disk-image.sh
```

### Network Evidence Collection

**Network Forensics:**
```bash
# Network evidence collection
cat > collect-network-evidence.sh << 'EOF'
#!/bin/bash
CASE_ID=${1:-"CASE-$(date +%Y%m%d-%H%M%S)"}
DURATION=${2:-300}  # 5 minutes default
EVIDENCE_DIR="evidence/${CASE_ID}/network"

echo "NETWORK EVIDENCE COLLECTION"
echo "Case ID: $CASE_ID"
echo "Duration: ${DURATION}s"
echo "Start Time: $(date)"

mkdir -p "$EVIDENCE_DIR"/{pcap,logs,analysis}

# Document network environment
cat > "$EVIDENCE_DIR/network-environment.txt" << NET_ENV
Network Collection Environment:
- Case ID: $CASE_ID
- Collection Host: $(hostname)
- Collection User: $(whoami)
- Start Time: $(date)
- Duration: ${DURATION} seconds

Network Interfaces:
$(ip addr show)

Routing Table:
$(ip route show)

ARP Table:
$(arp -a)
NET_ENV

# Capture network traffic
echo "1. Starting packet capture..."
if command -v tcpdump &>/dev/null; then
    # Capture all traffic
    timeout "$DURATION" tcpdump -i any -w "$EVIDENCE_DIR/pcap/all-traffic-$(date +%H%M%S).pcap" -s 0 &
    TCPDUMP_PID=$!
    
    # Capture specific protocols
    timeout "$DURATION" tcpdump -i any -w "$EVIDENCE_DIR/pcap/dns-traffic-$(date +%H%M%S).pcap" port 53 &
    timeout "$DURATION" tcpdump -i any -w "$EVIDENCE_DIR/pcap/http-traffic-$(date +%H%M%S).pcap" port 80 or port 8080 &
    timeout "$DURATION" tcpdump -i any -w "$EVIDENCE_DIR/pcap/ssh-traffic-$(date +%H%M%S).pcap" port 22 &
    
    echo "   Packet capture started (PID: $TCPDUMP_PID)"
    echo "   Capturing for ${DURATION} seconds..."
else
    echo " tcpdump not available - install for packet capture"
fi

# Monitor active connections
echo "2. Monitoring network connections..."
for i in $(seq 1 $((DURATION/30))); do
    echo "--- Sample $i at $(date) ---" >> "$EVIDENCE_DIR/logs/connections-timeline.txt"
    netstat -tun >> "$EVIDENCE_DIR/logs/connections-timeline.txt"
    ss -tulpn >> "$EVIDENCE_DIR/logs/socket-stats-timeline.txt"
    sleep 30
done &

# Monitor DNS queries
echo "3. Monitoring DNS activity..."
if [ -f "/var/log/syslog" ]; then
    tail -f /var/log/syslog | grep -i dns > "$EVIDENCE_DIR/logs/dns-activity.txt" &
    DNS_MONITOR_PID=$!
fi

# Monitor suspicious network activity
echo "4. Monitoring for suspicious activity..."
cat > "$EVIDENCE_DIR/analysis/suspicious-activity-monitor.sh" << 'MONITOR'
#!/bin/bash
ALERT_LOG="$1/logs/security-alerts.txt"

while true; do
    # Check for unusual connections
    EXTERNAL_CONNS=$(netstat -tun | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | grep -vE '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' | sort | uniq -c | sort -nr)
    
    if [ ! -z "$EXTERNAL_CONNS" ]; then
        echo "$(date): Unusual external connections:" >> "$ALERT_LOG"
        echo "$EXTERNAL_CONNS" >> "$ALERT_LOG"
    fi
    
    # Check for high connection counts
    HIGH_CONN_PROCS=$(netstat -tun | awk '{print $NF}' | grep -oE '[0-9]+/' | cut -d/ -f1 | sort | uniq -c | sort -nr | head -5)
    echo "$(date): Top connection processes: $HIGH_CONN_PROCS" >> "$ALERT_LOG"
    
    sleep 60
done
MONITOR

chmod +x "$EVIDENCE_DIR/analysis/suspicious-activity-monitor.sh"
timeout "$DURATION" "$EVIDENCE_DIR/analysis/suspicious-activity-monitor.sh" "$EVIDENCE_DIR" &

# Wait for collection to complete
echo "5. Collection in progress..."
sleep "$DURATION"

# Stop background processes
echo "6. Stopping collection processes..."
pkill -P $$ tcpdump 2>/dev/null || true
[ ! -z "$DNS_MONITOR_PID" ] && kill "$DNS_MONITOR_PID" 2>/dev/null || true

# Analyze captured data
echo "7. Analyzing captured data..."
if ls "$EVIDENCE_DIR"/pcap/*.pcap 1>/dev/null 2>&1; then
    for pcap in "$EVIDENCE_DIR"/pcap/*.pcap; do
        if [ -s "$pcap" ]; then
            echo "Analyzing $(basename "$pcap")..."
            
            # Basic statistics
            tcpdump -r "$pcap" -n | wc -l > "$EVIDENCE_DIR/analysis/$(basename "$pcap" .pcap)-packet-count.txt"
            
            # Top talkers
            tcpdump -r "$pcap" -n | awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c | sort -nr | head -10 > "$EVIDENCE_DIR/analysis/$(basename "$pcap" .pcap)-top-sources.txt"
            
            # Unique destinations
            tcpdump -r "$pcap" -n | awk '{print $5}' | cut -d. -f1-4 | sort | uniq -c | sort -nr | head -10 > "$EVIDENCE_DIR/analysis/$(basename "$pcap" .pcap)-top-destinations.txt"
        fi
    done
fi

# Generate network evidence report
cat > "$EVIDENCE_DIR/network-evidence-report.md" << REPORT
# Network Evidence Collection Report

**Case ID:** $CASE_ID
**Collection Duration:** ${DURATION} seconds
**Collection Host:** $(hostname)
**Collection Time:** $(date)

## Captured Data
### Packet Captures
$(ls -la "$EVIDENCE_DIR"/pcap/*.pcap 2>/dev/null || echo "No packet captures available")

### Log Files
- Connection Timeline: $(wc -l < "$EVIDENCE_DIR/logs/connections-timeline.txt" 2>/dev/null || echo "0") entries
- Socket Statistics: $(wc -l < "$EVIDENCE_DIR/logs/socket-stats-timeline.txt" 2>/dev/null || echo "0") entries
- DNS Activity: $(wc -l < "$EVIDENCE_DIR/logs/dns-activity.txt" 2>/dev/null || echo "0") entries
- Security Alerts: $(wc -l < "$EVIDENCE_DIR/logs/security-alerts.txt" 2>/dev/null || echo "0") entries

## Analysis Summary
$(if ls "$EVIDENCE_DIR"/analysis/*-packet-count.txt 1>/dev/null 2>&1; then
    echo "### Packet Statistics"
    for file in "$EVIDENCE_DIR"/analysis/*-packet-count.txt; do
        echo "- $(basename "$file" -packet-count.txt): $(cat "$file") packets"
    done
fi)

## Recommendations
1. Analyze packet captures for malicious traffic patterns
2. Correlate network activity with system logs
3. Investigate unusual external connections
4. Review DNS queries for suspicious domains

## Next Steps
1. Deep packet inspection of captured traffic
2. Correlation with threat intelligence feeds
3. Timeline analysis with other evidence sources
4. Malware communication pattern analysis

REPORT

echo "Network evidence collection completed"
echo "Evidence location: $EVIDENCE_DIR"
echo "Files collected: $(find "$EVIDENCE_DIR" -type f | wc -l)"
echo "Report: $EVIDENCE_DIR/network-evidence-report.md"
EOF

chmod +x collect-network-evidence.sh
```

## Containment Strategies

### Intelligent Isolation Techniques

**Dynamic Containment Decision Matrix:**
```bash
# Intelligent containment system
cat > intelligent-containment.sh << 'EOF'
#!/bin/bash
ASSET_TYPE=$1
THREAT_LEVEL=$2
BUSINESS_IMPACT=$3
CASE_ID=${4:-"CASE-$(date +%Y%m%d-%H%M%S)"}

if [ -z "$ASSET_TYPE" ] || [ -z "$THREAT_LEVEL" ] || [ -z "$BUSINESS_IMPACT" ]; then
    echo "Usage: $0 <asset-type> <threat-level> <business-impact> [case-id]"
    echo "Asset Types: server, workstation, container, network, database, application"
    echo "Threat Levels: low, medium, high, critical"
    echo "Business Impact: low, medium, high, critical"
    exit 1
fi

echo "INTELLIGENT CONTAINMENT SYSTEM"
echo "Case ID: $CASE_ID"
echo "Asset Type: $ASSET_TYPE"
echo "Threat Level: $THREAT_LEVEL"
echo "Business Impact: $BUSINESS_IMPACT"
echo "Analysis Time: $(date)"

# Create containment analysis directory
CONTAINMENT_DIR="containment/${CASE_ID}"
mkdir -p "$CONTAINMENT_DIR"

# Calculate containment score
CONTAINMENT_SCORE=0

case $THREAT_LEVEL in
    "critical") CONTAINMENT_SCORE=$((CONTAINMENT_SCORE + 4)) ;;
    "high") CONTAINMENT_SCORE=$((CONTAINMENT_SCORE + 3)) ;;
    "medium") CONTAINMENT_SCORE=$((CONTAINMENT_SCORE + 2)) ;;
    "low") CONTAINMENT_SCORE=$((CONTAINMENT_SCORE + 1)) ;;
esac

case $BUSINESS_IMPACT in
    "critical") BUSINESS_WEIGHT=4 ;;
    "high") BUSINESS_WEIGHT=3 ;;
    "medium") BUSINESS_WEIGHT=2 ;;
    "low") BUSINESS_WEIGHT=1 ;;
esac

# Determine containment strategy
if [ $CONTAINMENT_SCORE -eq 4 ] && [ $BUSINESS_WEIGHT -le 2 ]; then
    STRATEGY="IMMEDIATE_ISOLATION"
    TIMEFRAME="< 5 minutes"
    APPROVAL="Security Team"
elif [ $CONTAINMENT_SCORE -eq 4 ] && [ $BUSINESS_WEIGHT -ge 3 ]; then
    STRATEGY="CONTROLLED_ISOLATION"
    TIMEFRAME="< 15 minutes"
    APPROVAL="Business Owner + Security Team"
elif [ $CONTAINMENT_SCORE -ge 2 ]; then
    STRATEGY="NETWORK_SEGMENTATION"
    TIMEFRAME="< 30 minutes"
    APPROVAL="Security Team Lead"
else
    STRATEGY="MONITORING_ONLY"
    TIMEFRAME="Continuous"
    APPROVAL="Security Analyst"
fi

# Generate containment plan
cat > "$CONTAINMENT_DIR/containment-plan.md" << PLAN
# Containment Strategy: $STRATEGY

**Case ID:** $CASE_ID
**Asset:** $ASSET_TYPE
**Threat Level:** $THREAT_LEVEL
**Business Impact:** $BUSINESS_IMPACT
**Strategy:** $STRATEGY
**Timeframe:** $TIMEFRAME
**Approval Required:** $APPROVAL

## Containment Actions

PLAN

case $STRATEGY in
    "IMMEDIATE_ISOLATION")
        cat >> "$CONTAINMENT_DIR/containment-plan.md" << 'IMMEDIATE'
### Immediate Isolation Protocol

**Priority: CRITICAL - Execute Immediately**

#### Network Isolation
1. [ ] Disconnect network interfaces
2. [ ] Update firewall rules to block all traffic
3. [ ] Remove from load balancers
4. [ ] Isolate VLAN/subnet

#### System Isolation
1. [ ] Stop non-essential services
2. [ ] Prevent user access
3. [ ] Preserve system state for forensics
4. [ ] Document all actions taken

#### Communication
1. [ ] Notify incident commander
2. [ ] Alert business stakeholders
3. [ ] Inform compliance team
4. [ ] Update status page if customer-facing

IMMEDIATE
        
        # Generate immediate isolation script
        cat > "$CONTAINMENT_DIR/execute-immediate-isolation.sh" << 'ISOLATE'
#!/bin/bash
echo "=== EXECUTING IMMEDIATE ISOLATION ==="
echo "WARNING: This will completely isolate the system"
read -p "Confirm execution (type 'ISOLATE' to proceed): " CONFIRM

if [ "$CONFIRM" != "ISOLATE" ]; then
    echo "Isolation cancelled"
    exit 1
fi

# Network isolation
echo "1. Implementing network isolation..."
if command -v iptables &>/dev/null; then
    # Block all traffic except SSH for management
    iptables -I INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT
    iptables -I INPUT -j DROP
    iptables -I OUTPUT -j DROP
    echo "   Firewall rules applied"
fi

# Document isolation
echo "$(date): IMMEDIATE ISOLATION EXECUTED" >> isolation-log.txt
echo "   Actions taken:" >> isolation-log.txt
echo "   - Network traffic blocked" >> isolation-log.txt
echo "   - System preserved for forensics" >> isolation-log.txt

echo "Immediate isolation completed"
echo "Log: isolation-log.txt"
ISOLATE
        chmod +x "$CONTAINMENT_DIR/execute-immediate-isolation.sh"
        ;;
        
    "CONTROLLED_ISOLATION")
        cat >> "$CONTAINMENT_DIR/containment-plan.md" << 'CONTROLLED'
### Controlled Isolation Protocol

**Priority: HIGH - Coordinate with business stakeholders**

#### Pre-Isolation Steps
1. [ ] Notify business owners
2. [ ] Identify critical dependencies
3. [ ] Plan service failover
4. [ ] Schedule maintenance window

#### Gradual Isolation
1. [ ] Redirect traffic to backup systems
2. [ ] Gracefully stop services
3. [ ] Implement network restrictions
4. [ ] Monitor business impact

#### Rollback Plan
1. [ ] Document rollback procedures
2. [ ] Identify rollback criteria
3. [ ] Test rollback capability
4. [ ] Communicate rollback status

CONTROLLED
        ;;
        
    "NETWORK_SEGMENTATION")
        cat >> "$CONTAINMENT_DIR/containment-plan.md" << 'SEGMENT'
### Network Segmentation Protocol

**Priority: MEDIUM - Limit lateral movement**

#### Segmentation Actions
1. [ ] Create isolated network segment
2. [ ] Move affected systems to quarantine VLAN
3. [ ] Restrict inter-segment communication
4. [ ] Monitor east-west traffic

#### Access Control
1. [ ] Implement strict ACLs
2. [ ] Require VPN for administrative access
3. [ ] Log all access attempts
4. [ ] Review access permissions

#### Monitoring Enhancement
1. [ ] Increase logging verbosity
2. [ ] Deploy additional sensors
3. [ ] Set up real-time alerting
4. [ ] Schedule regular check-ins

SEGMENT
        ;;
        
    "MONITORING_ONLY")
        cat >> "$CONTAINMENT_DIR/containment-plan.md" << 'MONITOR'
### Enhanced Monitoring Protocol

**Priority: LOW - Watch and wait**

#### Monitoring Actions
1. [ ] Deploy additional monitoring tools
2. [ ] Increase log collection frequency
3. [ ] Set up behavioral analysis
4. [ ] Create custom detection rules

#### Documentation
1. [ ] Document all observed activity
2. [ ] Create timeline of events
3. [ ] Collect evidence continuously
4. [ ] Prepare for escalation

#### Thresholds for Escalation
1. [ ] Define escalation criteria
2. [ ] Set automated alerts
3. [ ] Plan rapid response procedures
4. [ ] Test escalation procedures

MONITOR
        ;;
esac

# Add timeline and approval tracking
cat >> "$CONTAINMENT_DIR/containment-plan.md" << 'TRACKING'

## Timeline and Approvals

| Timestamp | Action | Approver | Status |
|-----------|--------|----------|--------|
| $(date) | Containment plan generated | System | Complete |
|         | Business impact assessment | | ⏳ Pending |
|         | Technical approval | | ⏳ Pending |
|         | Containment execution | | ⏳ Pending |

## Risk Assessment

**Containment Risks:**
- Service availability impact
- Data access disruption  
- Customer experience degradation
- Business process interruption

**Non-Containment Risks:**
- Threat escalation
- Data exfiltration
- Lateral movement
- System compromise expansion

## Success Criteria
- [ ] Threat contained within network segment
- [ ] No evidence of lateral movement
- [ ] Business operations minimally impacted
- [ ] Evidence preserved for investigation
- [ ] Communication plan executed successfully

TRACKING

echo "Containment strategy determined: $STRATEGY"
echo "Containment plan: $CONTAINMENT_DIR/containment-plan.md"
echo "Execution timeframe: $TIMEFRAME"
echo "Approval required: $APPROVAL"

if [ -f "$CONTAINMENT_DIR/execute-immediate-isolation.sh" ]; then
    echo "Immediate isolation script ready: $CONTAINMENT_DIR/execute-immediate-isolation.sh"
fi

# Create containment checklist
cat > "$CONTAINMENT_DIR/containment-checklist.txt" << 'CHECKLIST'
CONTAINMENT EXECUTION CHECKLIST

Pre-Execution:
□ Business stakeholders notified
□ Technical team assembled
□ Communication channels established
□ Evidence preservation verified
□ Rollback plan documented

During Execution:
□ Actions logged in real-time
□ Business impact monitored
□ Technical success verified
□ Communication plan activated
□ Evidence integrity maintained

Post-Execution:
□ Containment effectiveness verified
□ Business operations assessed
□ Stakeholder communication complete
□ Next phase planning initiated
□ Lessons learned documented
CHECKLIST

echo "Execution checklist: $CONTAINMENT_DIR/containment-checklist.txt"
EOF

chmod +x intelligent-containment.sh
```

This incident response and forensics guide provides procedures for managing security incidents from detection through recovery. Each section includes both processes and scripts, ensuring responders can handle any situation while preserving evidence and maintaining business continuity.