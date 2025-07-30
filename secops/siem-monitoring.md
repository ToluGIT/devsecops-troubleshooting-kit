# SIEM and Security Monitoring Troubleshooting Guide

This guide helps you troubleshoot Security Information and Event Management (SIEM) systems, log collection, analysis, and security monitoring infrastructure.


## Log Collection Issues

### Issue: Missing or incomplete log data

**Symptoms:**
- Gaps in log collection
- Certain systems not sending logs
- Log sources going offline intermittently

**Diagnosis:**
```bash
# Check log collection health
cat > check-log-collection.sh << 'EOF'
#!/bin/bash
echo "Log Collection Health Check "

# Check syslog daemon status
echo "1. Syslog daemon status:"
systemctl status rsyslog || systemctl status syslog-ng
echo ""

# Check log file sizes and last update times
echo "2. Critical log files status:"
for logfile in /var/log/auth.log /var/log/syslog /var/log/messages /var/log/secure; do
    if [ -f "$logfile" ]; then
        echo "  $logfile:"
        echo "    Size: $(du -sh "$logfile" | cut -f1)"
        echo "    Last modified: $(stat -c %y "$logfile")"
        echo "    Recent entries: $(tail -1 "$logfile" | cut -c1-50)..."
    fi
done
echo ""

# Check remote log forwarding
echo "3. Remote syslog forwarding:"
if grep -q "^*.*@" /etc/rsyslog.conf /etc/rsyslog.d/*; then
    echo "  Remote forwarding configured:"
    grep "^*.*@" /etc/rsyslog.conf /etc/rsyslog.d/* 2>/dev/null
else
    echo "  No remote forwarding configured"
fi
echo ""

# Check log agent status
echo "4. Log shipping agents:"
for agent in filebeat logstash fluentd td-agent; do
    if systemctl is-active --quiet $agent; then
        echo "  $agent: Running"
        if [ "$agent" = "filebeat" ]; then
            filebeat test config 2>/dev/null && echo "    Config: Valid" || echo "    Config: Invalid"
        fi
    elif systemctl list-unit-files | grep -q $agent; then
        echo "  $agent: Stopped"
    fi
done
echo ""

# Check network connectivity to SIEM
echo "5. SIEM connectivity test:"
SIEM_HOST=${1:-siem.company.com}
SIEM_PORT=${2:-514}
if timeout 5 bash -c "</dev/tcp/$SIEM_HOST/$SIEM_PORT"; then
    echo "  Connection to $SIEM_HOST:$SIEM_PORT: Success"
else
    echo "  Connection to $SIEM_HOST:$SIEM_PORT: Failed"
fi

# Check disk space for logs
echo "6. Log storage disk usage:"
df -h /var/log
echo ""

# Check log rotation
echo "7. Log rotation status:"
if [ -f /var/lib/logrotate/status ]; then
    echo "  Last rotation run: $(stat -c %y /var/lib/logrotate/status)"
    echo "  Recent rotations:"
    tail -5 /var/lib/logrotate/status
else
    echo "  Logrotate status file not found"
fi
EOF

chmod +x check-log-collection.sh
./check-log-collection.sh siem-server.local 514
```

**Solution:**
```bash
# Fix log collection issues
cat > fix-log-collection.sh << 'EOF'
#!/bin/bash
echo " Fixing Log Collection Issues "

# Restart syslog service
echo "1. Restarting syslog service..."
systemctl restart rsyslog || systemctl restart syslog-ng
systemctl enable rsyslog || systemctl enable syslog-ng
echo " Syslog service restarted"

# Configure remote log forwarding
echo "2. Configuring remote log forwarding..."
SIEM_SERVER=$1
if [ -z "$SIEM_SERVER" ]; then
    echo "Usage: $0 <siem-server-ip>"
    exit 1
fi

# Create remote logging configuration
cat > /etc/rsyslog.d/50-remote.conf << RSYSLOG
# Send all logs to remote SIEM server
*.*    @@${SIEM_SERVER}:514

# Also send to local files (comment out if not needed)
auth,authpriv.*         /var/log/auth.log
*.*;auth,authpriv.none  /var/log/syslog
daemon.*                /var/log/daemon.log
kern.*                  /var/log/kern.log
mail.*                  /var/log/mail.log
user.*                  /var/log/user.log

# Emergency messages
*.emerg                 :omusrmsg:*

# High priority messages  
*.=debug;*.=info;*.=notice;*.=warn  /var/log/debug
*.err                              /var/log/error

RSYSLOG

# Restart rsyslog to apply changes
systemctl restart rsyslog
echo " Remote logging configured for $SIEM_SERVER"

# Fix log file permissions
echo "3. Fixing log file permissions..."
chmod 640 /var/log/*.log 2>/dev/null || true
chown root:adm /var/log/*.log 2>/dev/null || true
echo " Log file permissions fixed"

# Configure log rotation
echo "4. Configuring log rotation..."
cat > /etc/logrotate.d/security-logs << LOGROTATE
/var/log/auth.log
/var/log/security.log
/var/log/audit.log
{
    daily
    missingok
    rotate 90
    compress
    delaycompress
    notifempty
    create 640 root adm
    sharedscripts
    postrotate
        systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}
LOGROTATE

# Test logrotate configuration
logrotate -d /etc/logrotate.d/security-logs
echo " Log rotation configured"

# Install and configure log shipping agent
echo "5. Installing log shipping agent..."
if command -v apt-get > /dev/null; then
    # Install Filebeat on Debian/Ubuntu
    wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
    echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
    apt-get update && apt-get install -y filebeat
elif command -v yum > /dev/null; then
    # Install Filebeat on RHEL/CentOS
    cat > /etc/yum.repos.d/elastic.repo << YUM
[elastic-7.x]
name=Elastic repository for 7.x packages
baseurl=https://artifacts.elastic.co/packages/7.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
YUM
    yum install -y filebeat
fi

# Configure Filebeat
cat > /etc/filebeat/filebeat.yml << FILEBEAT
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/auth.log
    - /var/log/syslog
    - /var/log/messages
    - /var/log/secure
  fields:
    log_type: system
    
- type: log
  enabled: true
  paths:
    - /var/log/apache2/*.log
    - /var/log/nginx/*.log
  fields:
    log_type: web
    
- type: log
  enabled: true
  paths:
    - /var/log/audit/audit.log
  fields:
    log_type: audit

output.logstash:
  hosts: ["${SIEM_SERVER}:5044"]
  
processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_fields:
      target: ""
      fields:
        environment: production
        datacenter: main

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644
FILEBEAT

# Start and enable Filebeat
systemctl enable filebeat
systemctl start filebeat
echo " Filebeat configured and started"

echo " Log Collection Fix Complete "
echo "Monitor logs to ensure proper forwarding to SIEM"
EOF

chmod +x fix-log-collection.sh
```

## SIEM Platform Troubleshooting

### Issue: SIEM performance problems and data ingestion failures

**Symptoms:**
- Slow search queries
- High CPU/memory usage
- Data ingestion lag
- Missing or delayed alerts

**Diagnosis:**
```bash
# SIEM performance diagnostic
cat > diagnose-siem-performance.sh << 'EOF'
#!/bin/bash
echo " SIEM Performance Diagnostics "

# System resource usage
echo "1. System Resource Usage:"
echo "  CPU Usage:"
top -bn1 | grep "Cpu(s)" | awk '{print $2 $4}'

echo "  Memory Usage:"
free -h | grep -E "Mem:|Swap:"

echo "  Disk Usage:"
df -h | grep -E "/$|/var|/opt"

echo "  Load Average:"
uptime
echo ""

# Check SIEM processes
echo "2. SIEM Process Status:"
for process in elasticsearch logstash kibana splunkd; do
    if pgrep -f $process > /dev/null; then
        echo "  $process: Running"
        echo "    PID: $(pgrep -f $process)"
        echo "    CPU: $(ps -o pcpu= -p $(pgrep -f $process) | tr -d ' ')%"
        echo "    Memory: $(ps -o pmem= -p $(pgrep -f $process) | tr -d ' ')%"
    else
        echo "  $process: Not running"
    fi
done
echo ""

# Check service status
echo "3. SIEM Service Status:"
for service in elasticsearch logstash kibana; do
    if systemctl is-active --quiet $service; then
        echo "  $service: Active"
        echo "    Status: $(systemctl is-active $service)"
        echo "    Enabled: $(systemctl is-enabled $service)"
    else
        echo "  $service: Inactive"
    fi
done
echo ""

# Elasticsearch cluster health (if applicable)
if command -v curl > /dev/null && pgrep -f elasticsearch > /dev/null; then
    echo "4. Elasticsearch Cluster Health:"
    curl -s -X GET "localhost:9200/_cluster/health?pretty" | head -20
    
    echo "5. Elasticsearch Index Status:"
    curl -s -X GET "localhost:9200/_cat/indices?v" | head -10
    
    echo "6. Elasticsearch Node Stats:"
    curl -s -X GET "localhost:9200/_nodes/stats" | jq '.nodes[].jvm.mem.heap_used_percent' 2>/dev/null || echo "JVM heap stats not available"
fi

# Check log ingestion rates
echo "7. Log Ingestion Analysis:"
LOGSTASH_LOG="/var/log/logstash/logstash-plain.log"
if [ -f "$LOGSTASH_LOG" ]; then
    echo "  Recent Logstash activity:"
    tail -20 "$LOGSTASH_LOG" | grep -E "INFO|WARN|ERROR"
    
    echo "  Error count in last 1000 lines:"
    tail -1000 "$LOGSTASH_LOG" | grep -c ERROR
else
    echo "  Logstash log file not found"
fi

# Check disk I/O
echo "8. Disk I/O Performance:"
iostat -x 1 3 2>/dev/null | tail -10 || echo "iostat not available"

# Network connectivity test
echo "9. Network Connectivity:"
netstat -tlpn | grep -E ":514|:5044|:9200|:5601"
EOF

chmod +x diagnose-siem-performance.sh
./diagnose-siem-performance.sh
```

**Solution:**
```bash
# Optimize SIEM performance
cat > optimize-siem-performance.sh << 'EOF'
#!/bin/bash
echo "=== SIEM Performance Optimization ==="

# Elasticsearch optimization
echo "1. Optimizing Elasticsearch..."
if pgrep -f elasticsearch > /dev/null; then
    # Increase heap size (50% of available RAM, max 31GB)
    TOTAL_RAM=$(free -m | awk 'NR==2{print $2}')
    HEAP_SIZE=$((TOTAL_RAM / 2))
    if [ $HEAP_SIZE -gt 31744 ]; then
        HEAP_SIZE=31744
    fi
    
    # Update Elasticsearch JVM options
    sed -i "s/-Xms.*/-Xms${HEAP_SIZE}m/" /etc/elasticsearch/jvm.options
    sed -i "s/-Xmx.*/-Xmx${HEAP_SIZE}m/" /etc/elasticsearch/jvm.options
    
    # Optimize Elasticsearch configuration
    cat >> /etc/elasticsearch/elasticsearch.yml << ES_CONFIG

# Performance optimizations
indices.memory.index_buffer_size: 30%
indices.memory.min_index_buffer_size: 96mb
indices.queries.cache.size: 15%
indices.fielddata.cache.size: 30%

# Thread pool optimization
thread_pool:
    write:
        size: 8
        queue_size: 1000
    search:
        size: 13
        queue_size: 1000

# Disable swapping
bootstrap.memory_lock: true

# Increase refresh interval for better indexing performance
index.refresh_interval: 30s

ES_CONFIG

    systemctl restart elasticsearch
    echo "Elasticsearch optimized and restarted"
fi

# Logstash optimization
echo "2. Optimizing Logstash..."
if pgrep -f logstash > /dev/null; then
    # Create optimized Logstash configuration
    cat > /etc/logstash/conf.d/01-performance.conf << LOGSTASH
input {
  beats {
    port => 5044
    # Increase number of threads
    threads => 8
  }
  
  syslog {
    port => 514
    type => "syslog"
  }
}

filter {
  # Add basic parsing with minimal processing
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:timestamp} %{IPORHOST:host} %{DATA:program}(?:\[%{POSINT:pid}\])?: %{GREEDYDATA:message}" }
    }
    
    date {
      match => [ "timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
  
  # Remove unnecessary fields to improve performance
  mutate {
    remove_field => [ "@version", "beat", "input_type", "offset", "source" ]
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    # Bulk indexing for better performance
    flush_size => 5000
    idle_flush_time => 1
    # Use daily indices
    index => "logstash-%{+YYYY.MM.dd}"
    # Optimize for indexing
    template_name => "logstash"
    template_pattern => "logstash-*"
    template => {
      "index_patterns" => ["logstash-*"],
      "settings" => {
        "number_of_shards" => 1,
        "number_of_replicas" => 0,
        "refresh_interval" => "30s"
      }
    }
  }
}
LOGSTASH

    # Update Logstash JVM settings
    LOGSTASH_HEAP=$((TOTAL_RAM / 4))
    if [ $LOGSTASH_HEAP -lt 512 ]; then
        LOGSTASH_HEAP=512
    fi
    
    echo "-Xms${LOGSTASH_HEAP}m" > /etc/logstash/jvm.options
    echo "-Xmx${LOGSTASH_HEAP}m" >> /etc/logstash/jvm.options
    
    systemctl restart logstash
    echo "Logstash optimized and restarted"
fi

# System-level optimizations
echo "3. Applying system-level optimizations..."

# Increase file descriptor limits
cat >> /etc/security/limits.conf << LIMITS
elasticsearch soft nofile 65536
elasticsearch hard nofile 65536
logstash soft nofile 65536
logstash hard nofile 65536
LIMITS

# Optimize kernel parameters for SIEM workloads
cat > /etc/sysctl.d/99-siem.conf << SYSCTL
# Increase maximum number of open files
fs.file-max = 2097152

# Increase network buffer sizes
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.netdev_max_backlog = 5000

# Optimize TCP settings
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_congestion_control = bbr

# Virtual memory settings
vm.max_map_count = 262144
vm.swappiness = 1
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5

SYSCTL

sysctl -p /etc/sysctl.d/99-siem.conf
echo "System optimizations applied"

# Configure log retention policies
echo "4. Configuring log retention..."
curl -X PUT "localhost:9200/_template/logstash_retention" -H 'Content-Type: application/json' -d'
{
  "index_patterns": ["logstash-*"],
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 0,
    "index.lifecycle.name": "logstash_policy",
    "index.lifecycle.rollover_alias": "logstash"
  }
}
' 2>/dev/null || true

echo "Performance optimization complete"
echo "Monitor system metrics and adjust settings as needed"
EOF

chmod +x optimize-siem-performance.sh
```

## Data Parsing and Normalization

### Issue: Incorrect log parsing and field extraction

**Symptoms:**
- Fields not being extracted correctly
- Unparsed raw log messages
- Inconsistent field naming
- Search queries not returning expected results

**Diagnosis:**
```bash
# Check log parsing issues
cat > check-log-parsing.sh << 'EOF'
#!/bin/bash
echo " Log Parsing Diagnostics"

# Check Logstash parsing configuration
echo "1. Logstash Configuration Analysis:"
if [ -d /etc/logstash/conf.d ]; then
    echo "  Configuration files:"
    ls -la /etc/logstash/conf.d/
    echo ""
    
    echo "  Grok patterns in use:"
    grep -r "grok {" /etc/logstash/conf.d/ | head -10
    echo ""
    
    echo "  Filter configurations:"
    grep -r "filter {" /etc/logstash/conf.d/ -A 5 | head -20
fi

# Test Grok patterns
echo "2. Grok Pattern Testing:"
if command -v logstash > /dev/null; then
    echo "  Testing common log patterns..."
    
    # Create sample log entries
    cat > /tmp/sample-logs.txt << SAMPLES
Jan 15 10:30:45 server01 sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:30:46 server01 kernel: [12345.678] iptables: DROPPED: IN=eth0 OUT= SRC=10.0.0.1 DST=10.0.0.2
2024-01-15T10:30:47.123Z server01 apache2: 192.168.1.50 - - [15/Jan/2024:10:30:47 +0000] "GET /admin HTTP/1.1" 404 512
SAMPLES

    # Test parsing with a simple Logstash config
    cat > /tmp/test-parsing.conf << TESTCONF
input {
  stdin { }
}

filter {
  grok {
    match => { "message" => "%{SYSLOGTIMESTAMP:timestamp} %{IPORHOST:host} %{DATA:program}(?:\[%{POSINT:pid}\])?: %{GREEDYDATA:log_message}" }
    tag_on_failure => ["_grokparsefailure"]
  }
}

output {
  stdout { codec => json_lines }
}
TESTCONF

    echo "  Sample parsing test:"
    timeout 10 logstash -f /tmp/test-parsing.conf < /tmp/sample-logs.txt 2>/dev/null || echo "Logstash test failed"
fi

# Check Elasticsearch field mappings
echo "3. Elasticsearch Field Mappings:"
if command -v curl > /dev/null && pgrep -f elasticsearch > /dev/null; then
    echo "  Current index mappings:"
    curl -s "localhost:9200/logstash-*/_mapping" | jq '.[] | keys' 2>/dev/null | head -20 || echo "Mapping retrieval failed"
    
    echo "  Common parsing failures:"
    curl -s "localhost:9200/logstash-*/_search" -H 'Content-Type: application/json' -d'
    {
      "query": {
        "bool": {
          "must": [
            { "exists": { "field": "tags" } },
            { "term": { "tags": "_grokparsefailure" } }
          ]
        }
      },
      "size": 5,
      "sort": [{"@timestamp": {"order": "desc"}}]
    }
    ' 2>/dev/null | jq '.hits.hits[]._source.message' 2>/dev/null || echo "Failed to query parsing failures"
fi

# Analyze recent log patterns
echo "4. Recent Log Pattern Analysis:"
echo "  Sample raw log entries:"
tail -10 /var/log/auth.log 2>/dev/null || echo "Auth log not accessible"
echo ""
tail -10 /var/log/syslog 2>/dev/null || echo "Syslog not accessible"

# Check field extraction
echo "5. Field Extraction Validation:"
if command -v jq > /dev/null; then
    echo "  Analyzing parsed log structure..."
    # This would typically query your SIEM's API for recent parsed logs
    echo "  (Manual verification needed in SIEM dashboard)"
fi
EOF

chmod +x check-log-parsing.sh
./check-log-parsing.sh
```

**Solution:**
```bash
# Fix log parsing issues
cat > fix-log-parsing.sh << 'EOF'
#!/bin/bash
echo "=== Fixing Log Parsing Issues ==="

# Create comprehensive parsing configuration
echo "1. Creating comprehensive parsing rules..."

# Backup existing configuration
cp -r /etc/logstash/conf.d /etc/logstash/conf.d.backup.$(date +%Y%m%d)

# Create main parsing configuration
cat > /etc/logstash/conf.d/02-parsing.conf << PARSING
filter {
  # SSH authentication logs
  if [program] == "sshd" {
    grok {
      match => { 
        "message" => [
          "Failed password for %{USER:failed_user} from %{IPORHOST:source_ip} port %{INT:source_port}",
          "Accepted password for %{USER:successful_user} from %{IPORHOST:source_ip} port %{INT:source_port}",
          "Invalid user %{USER:invalid_user} from %{IPORHOST:source_ip} port %{INT:source_port}"
        ]
      }
      add_tag => [ "ssh_auth" ]
    }
    
    if [source_ip] {
      geoip {
        source => "source_ip"
        target => "geoip"
      }
    }
  }
  
  # Web server logs (Apache/Nginx)
  if [log_type] == "web" or [program] =~ /apache|nginx|httpd/ {
    grok {
      match => { 
        "message" => "%{COMBINEDAPACHELOG}"
      }
      add_tag => [ "web_access" ]
    }
    
    # Parse user agent
    if [agent] {
      useragent {
        source => "agent"
        target => "user_agent"
      }
    }
    
    # Convert response code to integer
    mutate {
      convert => { "response" => "integer" }
      convert => { "bytes" => "integer" }
    }
    
    # Add severity based on response code
    if [response] >= 400 {
      mutate { add_tag => [ "error" ] }
    }
    if [response] >= 500 {
      mutate { add_tag => [ "server_error" ] }
    }
  }
  
  # Firewall/iptables logs
  if "iptables" in [message] or "DROPPED" in [message] {
    grok {
      match => { 
        "message" => ".*iptables.*: (?<action>ACCEPT|DROP|REJECT).*IN=%{WORD:in_interface}.*SRC=%{IP:source_ip}.*DST=%{IP:dest_ip}.*PROTO=%{WORD:protocol}.*"
      }
      add_tag => [ "firewall" ]
    }
    
    if [source_ip] {
      geoip {
        source => "source_ip"
        target => "source_geoip"
      }
    }
  }
  
  # System authentication logs
  if [program] == "su" or [program] == "sudo" {
    grok {
      match => { 
        "message" => [
          ".*session opened for user %{USER:target_user} by %{USER:source_user}.*",
          ".*FAILED su for %{USER:target_user} by %{USER:source_user}.*",
          ".*%{USER:sudo_user} : TTY=%{DATA:tty} ; PWD=%{DATA:pwd} ; USER=%{DATA:target_user} ; COMMAND=%{GREEDYDATA:command}.*"
        ]
      }
      add_tag => [ "privilege_escalation" ]
    }
  }
  
  # Failed login attempts (generic)
  if "failed" in [message] and "login" in [message] {
    mutate { add_tag => [ "failed_login" ] }
  }
  
  # Malware/security events
  if [program] =~ /clamav|rkhunter|aide/ {
    grok {
      match => { 
        "message" => ".*(?<threat_type>FOUND|INFECTED|WARNING).*: %{GREEDYDATA:threat_details}"
      }
      add_tag => [ "security_alert", "malware" ]
    }
  }
  
  # Normalize timestamps
  date {
    match => [ "timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss", "ISO8601" ]
    target => "@timestamp"
  }
  
  # Add normalized fields
  mutate {
    # Normalize host field
    lowercase => [ "host" ]
    
    # Add environment information
    add_field => { 
      "environment" => "${ENVIRONMENT:production}"
      "log_source" => "%{host}"
    }
    
    # Remove empty fields
    remove_field => [ "beat", "input_type", "offset", "source" ]
  }
  
  # Add severity levels
  if "error" in [tags] or "ERROR" in [message] {
    mutate { add_field => { "severity" => "high" } }
  } else if "warn" in [tags] or "WARNING" in [message] {
    mutate { add_field => { "severity" => "medium" } }
  } else if "security_alert" in [tags] {
    mutate { add_field => { "severity" => "critical" } }
  } else {
    mutate { add_field => { "severity" => "low" } }
  }
}
PARSING

# Create field mapping template
echo "2. Creating Elasticsearch field mappings..."
curl -X PUT "localhost:9200/_template/logstash_security" -H 'Content-Type: application/json' -d'
{
  "index_patterns": ["logstash-*"],
  "mappings": {
    "properties": {
      "@timestamp": { "type": "date" },
      "host": { "type": "keyword" },
      "program": { "type": "keyword" },
      "message": { "type": "text", "analyzer": "standard" },
      "severity": { "type": "keyword" },
      "log_type": { "type": "keyword" },
      "source_ip": { "type": "ip" },
      "dest_ip": { "type": "ip" },
      "source_port": { "type": "integer" },
      "dest_port": { "type": "integer" },
      "protocol": { "type": "keyword" },
      "action": { "type": "keyword" },
      "response": { "type": "integer" },
      "bytes": { "type": "integer" },
      "failed_user": { "type": "keyword" },
      "successful_user": { "type": "keyword" },
      "invalid_user": { "type": "keyword" },
      "target_user": { "type": "keyword" },
      "source_user": { "type": "keyword" },
      "sudo_user": { "type": "keyword" },
      "command": { "type": "text" },
      "threat_type": { "type": "keyword" },
      "threat_details": { "type": "text" },
      "geoip": {
        "properties": {
          "location": { "type": "geo_point" },
          "country_name": { "type": "keyword" },
          "city_name": { "type": "keyword" }
        }
      },
      "user_agent": {
        "properties": {
          "name": { "type": "keyword" },
          "os": { "type": "keyword" },
          "device": { "type": "keyword" }
        }
      }
    }
  },
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 0,
    "refresh_interval": "30s"
  }
}
' 2>/dev/null || echo "Failed to create mapping template"

# Create custom Grok patterns
echo "3. Creating custom Grok patterns..."
mkdir -p /etc/logstash/patterns
cat > /etc/logstash/patterns/security << GROK_PATTERNS
# Security-specific Grok patterns
SECURITY_TIMESTAMP %{TIMESTAMP_ISO8601}|%{SYSLOGTIMESTAMP}
SECURITY_USER [a-zA-Z0-9._-]+
SECURITY_IP %{IPV4}|%{IPV6}
SECURITY_ACTION ACCEPT|DENY|DROP|REJECT|ALLOW|BLOCK
SECURITY_SEVERITY INFO|WARN|WARNING|ERROR|CRITICAL|DEBUG
FAILED_LOGIN .*[Ff]ailed.*[Ll]ogin.*
SUCCESSFUL_LOGIN .*[Ss]uccessful.*[Ll]ogin.*
PRIVILEGE_ESCALATION .*(?:sudo|su|admin|root).*
GROK_PATTERNS

# Test the parsing configuration
echo "4. Testing parsing configuration..."
if command -v logstash > /dev/null; then
    # Create test configuration
    cat > /tmp/test-complete-parsing.conf << TESTCONF
input { stdin { } }
$(cat /etc/logstash/conf.d/02-parsing.conf | grep -A 1000 "filter {")
output { stdout { codec => json_lines } }
TESTCONF

    # Create comprehensive test data
    cat > /tmp/comprehensive-test-logs.txt << TESTLOGS
Jan 15 10:30:45 server01 sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:31:00 server01 sshd[1235]: Accepted password for admin from 192.168.1.50 port 22 ssh2
Jan 15 10:32:15 server01 apache2: 192.168.1.75 - - [15/Jan/2024:10:32:15 +0000] "GET /admin HTTP/1.1" 404 512 "-" "Mozilla/5.0"
Jan 15 10:33:30 server01 kernel: iptables: DROPPED: IN=eth0 OUT= SRC=10.0.0.1 DST=10.0.0.2 PROTO=TCP
Jan 15 10:34:45 server01 sudo: testuser : TTY=pts/0 ; PWD=/home/testuser ; USER=root ; COMMAND=/bin/ls
TESTLOGS

    echo "  Running parsing test..."
    timeout 15 logstash -f /tmp/test-complete-parsing.conf < /tmp/comprehensive-test-logs.txt 2>/dev/null | head -20 || echo "Parsing test completed"
fi

# Restart Logstash with new configuration
echo "5. Restarting Logstash..."
systemctl restart logstash
systemctl status logstash --no-pager -l

# Clean up test files
rm -f /tmp/test-*.conf /tmp/*test-logs.txt /tmp/sample-logs.txt

echo "Log parsing configuration updated"
echo "Monitor Logstash logs for parsing errors: tail -f /var/log/logstash/logstash-plain.log"
EOF

chmod +x fix-log-parsing.sh
```

## Alert and Correlation Issues

### Issue: False positives and missed security events

**Symptoms:**
- Too many false positive alerts
- Critical security events not detected
- Alert fatigue among security team
- Correlation rules not triggering

**Diagnosis:**
```bash
# Analyze alerting effectiveness
cat > analyze-alerting.sh << 'EOF'
#!/bin/bash
echo " SIEM Alerting Analysis "

# Analyze alert volume and patterns
echo "1. Alert Volume Analysis (last 24 hours):"
if command -v curl > /dev/null && pgrep -f elasticsearch > /dev/null; then
    # Query for alerts in the last 24 hours
    curl -s "localhost:9200/logstash-*/_search" -H 'Content-Type: application/json' -d'
    {
      "query": {
        "bool": {
          "must": [
            { "range": { "@timestamp": { "gte": "now-24h" } } },
            { "terms": { "severity": ["high", "critical"] } }
          ]
        }
      },
      "aggs": {
        "alerts_by_severity": {
          "terms": { "field": "severity" }
        },
        "alerts_by_host": {
          "terms": { "field": "host", "size": 10 }
        },
        "alerts_by_type": {
          "terms": { "field": "tags", "size": 10 }
        }
      },
      "size": 0
    }
    ' | jq '.aggregations' 2>/dev/null || echo "Failed to query alert data"
fi

echo ""
echo "2. Common Alert Patterns:"

# Analyze auth logs for patterns
if [ -f /var/log/auth.log ]; then
    echo "  Failed login patterns:"
    grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr | head -10
    
    echo "  SSH connection patterns:"
    grep "sshd.*Accepted" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr | head -10
fi

# Check for potential false positives
echo ""
echo "3. Potential False Positive Sources:"
echo "  High-volume source IPs:"
grep -h "Failed password" /var/log/auth.log 2>/dev/null | awk '{print $11}' | sort | uniq -c | awk '$1 > 10 {print $2, $1 " failures"}' | head -5

echo "  Repeated legitimate activities:"
grep -h "Accepted password" /var/log/auth.log 2>/dev/null | awk '{print $9, $11}' | sort | uniq -c | sort -nr | head -5

# Analyze correlation effectiveness
echo ""
echo "4. Correlation Rule Analysis:"
echo "  Events requiring correlation:"
echo "    - Failed logins followed by successful login from same IP"
echo "    - Privilege escalation after authentication"
echo "    - Multiple failed logins from different IPs (distributed attack)"
echo "    - Unusual outbound connections after authentication"

# Check for missed events
echo ""
echo "5. Potential Missed Events:"
echo "  Looking for indicators of advanced threats..."

# Check for potential lateral movement
if [ -f /var/log/auth.log ]; then
    echo "  Potential lateral movement (successful logins to multiple hosts):"
    grep "Accepted password" /var/log/auth.log | awk '{print $9, $11}' | sort | uniq | wc -l
fi

# Check for unusual process patterns
echo "  Unusual process patterns:"
ps aux | awk '$11 ~ /\.(sh|py|pl)$/ {print $11}' | sort | uniq -c | sort -nr | head -5

# Network connection analysis
echo "  Unusual network connections:"
netstat -tuln | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -10
EOF

chmod +x analyze-alerting.sh
./analyze-alerting.sh
```

**Solution:**
```bash
# Improve SIEM alerting and correlation
cat > improve-alerting.sh << 'EOF'
#!/bin/bash
echo " Improving SIEM Alerting and Correlation "

# Create advanced correlation rules
echo "1. Creating correlation rules..."

# Create correlation configuration for Logstash
cat > /etc/logstash/conf.d/03-correlation.conf << CORRELATION
filter {
  # Failed login correlation (multiple failures from same IP)
  if "ssh_auth" in [tags] and [failed_user] {
    ruby {
      code => '
        @failed_logins ||= {}
        source_ip = event.get("source_ip")
        
        if source_ip
          @failed_logins[source_ip] ||= { count: 0, first_seen: Time.now }
          @failed_logins[source_ip][:count] += 1
          @failed_logins[source_ip][:last_seen] = Time.now
          
          # Alert on 5+ failed logins within 5 minutes
          if @failed_logins[source_ip][:count] >= 5 and 
             (Time.now - @failed_logins[source_ip][:first_seen]) <= 300
            event.set("alert_type", "brute_force_attack")
            event.set("alert_severity", "high")
            event.set("alert_description", "Multiple failed login attempts from #{source_ip}")
            event.set("failed_login_count", @failed_logins[source_ip][:count])
          end
          
          # Clean up old entries (older than 1 hour)
          @failed_logins.delete_if { |ip, data| (Time.now - data[:first_seen]) > 3600 }
        end
      '
    }
  }
  
  # Successful login after failed attempts (potential compromise)
  if "ssh_auth" in [tags] and [successful_user] {
    ruby {
      code => '
        @failed_logins ||= {}
        source_ip = event.get("source_ip")
        
        if source_ip and @failed_logins[source_ip] and @failed_logins[source_ip][:count] > 3
          event.set("alert_type", "suspicious_login_after_failures")
          event.set("alert_severity", "critical")
          event.set("alert_description", "Successful login from #{source_ip} after #{@failed_logins[source_ip][:count]} failed attempts")
          
          # Clear the failed login count for this IP
          @failed_logins.delete(source_ip)
        end
      '
    }
  }
  
  # Privilege escalation detection
  if "privilege_escalation" in [tags] and [sudo_user] and [target_user] == "root" {
    # Check if this is unusual for this user
    ruby {
      code => '
        @sudo_patterns ||= {}
        sudo_user = event.get("sudo_user")
        command = event.get("command")
        
        if sudo_user
          @sudo_patterns[sudo_user] ||= { commands: [], count: 0 }
          @sudo_patterns[sudo_user][:commands] << command
          @sudo_patterns[sudo_user][:count] += 1
          @sudo_patterns[sudo_user][:last_seen] = Time.now
          
          # Alert on unusual commands or high frequency
          dangerous_commands = ["/bin/bash", "/bin/sh", "passwd", "usermod", "userdel", "useradd"]
          
          if dangerous_commands.any? { |cmd| command && command.include?(cmd) }
            event.set("alert_type", "dangerous_privilege_escalation")
            event.set("alert_severity", "high")
            event.set("alert_description", "User #{sudo_user} executed dangerous command: #{command}")
          end
          
          # Alert on high frequency sudo usage
          if @sudo_patterns[sudo_user][:count] > 20
            event.set("alert_type", "excessive_privilege_escalation")
            event.set("alert_severity", "medium")
            event.set("alert_description", "User #{sudo_user} has excessive sudo usage: #{@sudo_patterns[sudo_user][:count]} commands")
          end
        end
      '
    }
  }
  
  # Web attack detection
  if "web_access" in [tags] {
    # SQL injection attempts
    if [request] and [request] =~ /(\%27)|(\')|(\-\-)|(%23)|(#)/i {
      mutate {
        add_field => { 
          "alert_type" => "sql_injection_attempt"
          "alert_severity" => "high"
          "alert_description" => "Potential SQL injection attempt detected"
        }
        add_tag => [ "web_attack", "sql_injection" ]
      }
    }
    
    # XSS attempts
    if [request] and [request] =~ /<script|javascript:|onload=|onerror=/i {
      mutate {
        add_field => { 
          "alert_type" => "xss_attempt"
          "alert_severity" => "high"
          "alert_description" => "Potential XSS attempt detected"
        }
        add_tag => [ "web_attack", "xss" ]
      }
    }
    
    # Directory traversal
    if [request] and [request] =~ /\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\\/i {
      mutate {
        add_field => { 
          "alert_type" => "directory_traversal"
          "alert_severity" => "high"
          "alert_description" => "Directory traversal attempt detected"
        }
        add_tag => [ "web_attack", "directory_traversal" ]
      }
    }
    
    # Multiple 404s from same IP (scanning)
    if [response] == 404 {
      ruby {
        code => '
          @scan_attempts ||= {}
          source_ip = event.get("clientip")
          
          if source_ip
            @scan_attempts[source_ip] ||= { count: 0, first_seen: Time.now }
            @scan_attempts[source_ip][:count] += 1
            @scan_attempts[source_ip][:last_seen] = Time.now
            
            # Alert on 20+ 404s within 5 minutes
            if @scan_attempts[source_ip][:count] >= 20 and 
               (Time.now - @scan_attempts[source_ip][:first_seen]) <= 300
              event.set("alert_type", "web_scanning")
              event.set("alert_severity", "medium")
              event.set("alert_description", "Web scanning detected from #{source_ip}")
              event.set("scan_count", @scan_attempts[source_ip][:count])
            end
            
            # Clean up old entries
            @scan_attempts.delete_if { |ip, data| (Time.now - data[:first_seen]) > 3600 }
          end
        '
      }
    }
  }
  
  # Malware/security alert correlation
  if "security_alert" in [tags] or "malware" in [tags] {
    mutate {
      add_field => { 
        "alert_type" => "security_software_alert"
        "alert_severity" => "critical"
        "alert_description" => "Security software detected threat: %{threat_details}"
      }
    }
  }
  
  # Network-based detection
  if "firewall" in [tags] and [action] == "DROP" {
    ruby {
      code => '
        @blocked_ips ||= {}
        source_ip = event.get("source_ip")
        
        if source_ip
          @blocked_ips[source_ip] ||= { count: 0, first_seen: Time.now }
          @blocked_ips[source_ip][:count] += 1
          
          # Alert on high volume of blocked connections
          if @blocked_ips[source_ip][:count] >= 100
            event.set("alert_type", "persistent_attack")
            event.set("alert_severity", "medium")
            event.set("alert_description", "Persistent attack attempts from #{source_ip}")
            event.set("blocked_count", @blocked_ips[source_ip][:count])
          end
          
          # Clean up old entries
          @blocked_ips.delete_if { |ip, data| (Time.now - data[:first_seen]) > 3600 }
        end
      '
    }
  }
  
  # Add alert metadata if alert fields are present
  if [alert_type] {
    mutate {
      add_field => {
        "event_type" => "alert"
        "alert_timestamp" => "%{@timestamp}"
        "alert_source" => "%{host}"
      }
      add_tag => [ "alert" ]
    }
  }
}
CORRELATION

# Create alert output configuration
echo "2. Creating alert output configuration..."
cat > /etc/logstash/conf.d/04-alerts.conf << ALERTS
output {
  # Send all events to Elasticsearch
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "logstash-%{+YYYY.MM.dd}"
  }
  
  # Send alerts to dedicated alert index
  if "alert" in [tags] {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "security-alerts-%{+YYYY.MM.dd}"
    }
    
    # Send critical alerts to email (configure as needed)
    if [alert_severity] == "critical" {
      email {
        to => "security-team@company.com"
        subject => "Critical Security Alert: %{alert_type}"
        body => "Alert: %{alert_description}\nHost: %{host}\nTime: %{@timestamp}\nDetails: %{message}"
        # Configure SMTP settings as needed
        # smtp_host => "smtp.company.com"
        # smtp_port => 587
        # username => "alerts@company.com"
        # password => "password"
      }
    }
    
    # Send to external security tools (webhook example)
    http {
      url => "https://security-tools.company.com/webhook"
      http_method => "post"
      format => "json"
      mapping => {
        "alert_type" => "%{alert_type}"
        "severity" => "%{alert_severity}"
        "description" => "%{alert_description}"
        "source" => "%{host}"
        "timestamp" => "%{@timestamp}"
      }
    }
  }
}
ALERTS

# Create whitelist for known good activities
echo "3. Creating whitelist for false positive reduction..."
cat > /etc/logstash/conf.d/01-whitelist.conf << WHITELIST
filter {
  # Whitelist known good IPs
  if [source_ip] in ["192.168.1.10", "192.168.1.20", "10.0.1.100"] {
    mutate {
      add_tag => [ "whitelisted_ip" ]
    }
  }
  
  # Whitelist known good users for privilege escalation
  if [sudo_user] in ["backup", "monitoring", "deploy"] and [target_user] == "root" {
    mutate {
      add_tag => [ "whitelisted_sudo" ]
    }
  }
  
  # Whitelist known good web crawlers
  if [agent] and [agent] =~ /Googlebot|bingbot|slurp/i {
    mutate {
      add_tag => [ "whitelisted_crawler" ]
    }
  }
  
  # Skip alerting for whitelisted activities
  if "whitelisted_ip" in [tags] or "whitelisted_sudo" in [tags] or "whitelisted_crawler" in [tags] {
    mutate {
      remove_field => [ "alert_type", "alert_severity", "alert_description" ]
      remove_tag => [ "alert" ]
    }
  }
}
WHITELIST

# Create alert tuning script
echo "4. Creating alert tuning utility..."
cat > /usr/local/bin/tune-siem-alerts.sh << TUNING
#!/bin/bash
# SIEM Alert Tuning Utility

COMMAND=\$1
PARAMETER=\$2

case \$COMMAND in
    "status")
        echo "SIEM Alert Status:"
        curl -s "localhost:9200/security-alerts-*/_search" -H 'Content-Type: application/json' -d'
        {
          "query": { "range": { "@timestamp": { "gte": "now-24h" } } },
          "aggs": {
            "alert_types": { "terms": { "field": "alert_type" } },
            "severities": { "terms": { "field": "alert_severity" } }
          },
          "size": 0
        }
        ' | jq '.aggregations'
        ;;
    "whitelist-ip")
        if [ -z "\$PARAMETER" ]; then
            echo "Usage: \$0 whitelist-ip <ip-address>"
            exit 1
        fi
        sed -i "s/\"10.0.1.100\"]/\"10.0.1.100\", \"\$PARAMETER\"]/" /etc/logstash/conf.d/01-whitelist.conf
        systemctl restart logstash
        echo "IP \$PARAMETER added to whitelist"
        ;;
    "adjust-threshold")
        ALERT_TYPE=\$2
        NEW_THRESHOLD=\$3
        if [ -z "\$NEW_THRESHOLD" ]; then
            echo "Usage: \$0 adjust-threshold <alert-type> <new-threshold>"
            exit 1
        fi
        # This would adjust thresholds in the correlation rules
        echo "Threshold adjustment for \$ALERT_TYPE to \$NEW_THRESHOLD"
        echo "Manual configuration update required in /etc/logstash/conf.d/03-correlation.conf"
        ;;
    "test-parsing")
        echo "Testing current parsing rules..."
        echo 'Jan 15 10:30:45 server01 sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2' | /usr/share/logstash/bin/logstash -f /etc/logstash/conf.d/02-parsing.conf
        ;;
    *)
        echo "SIEM Alert Tuning Utility"
        echo "Usage: \$0 {status|whitelist-ip|adjust-threshold|test-parsing} [parameters]"
        echo ""
        echo "Commands:"
        echo "  status                          - Show current alert status"
        echo "  whitelist-ip <ip>              - Add IP to whitelist"
        echo "  adjust-threshold <type> <num>  - Adjust alert threshold"
        echo "  test-parsing                   - Test current parsing rules"
        ;;
esac
TUNING

chmod +x /usr/local/bin/tune-siem-alerts.sh

# Restart Logstash with new configuration
echo "5. Restarting Logstash with correlation rules..."
systemctl restart logstash

# Create monitoring dashboard configuration
echo "6. Creating monitoring queries..."
cat > /tmp/siem-monitoring-queries.txt << QUERIES
# Useful Elasticsearch queries for SIEM monitoring

# 1. Alert volume by type (last 24 hours)
GET security-alerts-*/_search
{
  "query": { "range": { "@timestamp": { "gte": "now-24h" } } },
  "aggs": { "alert_types": { "terms": { "field": "alert_type" } } },
  "size": 0
}

# 2. Top source IPs for failed logins
GET logstash-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-24h" } } },
        { "exists": { "field": "failed_user" } }
      ]
    }
  },
  "aggs": { "top_ips": { "terms": { "field": "source_ip", "size": 10 } } },
  "size": 0
}

# 3. Web attacks by type
GET logstash-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-24h" } } },
        { "terms": { "tags": ["web_attack"] } }
      ]
    }
  },
  "aggs": { "attack_types": { "terms": { "field": "tags", "size": 10 } } },
  "size": 0
}

# 4. Critical alerts requiring immediate attention
GET security-alerts-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "term": { "alert_severity": "critical" } },
        { "range": { "@timestamp": { "gte": "now-1h" } } }
      ]
    }
  },
  "sort": [{ "@timestamp": { "order": "desc" } }],
  "size": 20
}
QUERIES

echo "SIEM alerting and correlation configuration complete"
echo ""
echo "Key files created:"
echo "  - Correlation rules: /etc/logstash/conf.d/03-correlation.conf"
echo "  - Alert outputs: /etc/logstash/conf.d/04-alerts.conf"
echo "  - Whitelist rules: /etc/logstash/conf.d/01-whitelist.conf"
echo "  - Tuning utility: /usr/local/bin/tune-siem-alerts.sh"
echo "  - Sample queries: /tmp/siem-monitoring-queries.txt"
echo ""
echo "Next steps:"
echo "1. Configure email/webhook endpoints in alert outputs"
echo "2. Adjust correlation thresholds based on your environment"
echo "3. Add organization-specific whitelist entries"
echo "4. Test alert generation with simulated events"
echo "5. Create dashboards for alert monitoring"
EOF

chmod +x improve-alerting.sh
```

This SIEM monitoring guide provides troubleshooting procedures for log collection, data parsing, correlation rules, performance optimization, and alert management. The scripts help identify and resolve common SIEM issues while improving the overall effectiveness of security monitoring operations.
