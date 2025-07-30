# Docker Security Troubleshooting Guide

This guide helps you identify, troubleshoot, and resolve security issues in Docker containers, from image vulnerabilities to runtime security concerns.


## Container Image Security

### Base Image Vulnerabilities

#### Issue: High-severity vulnerabilities in base images

**Symptoms:**
- Security scanners reporting critical CVEs
- Outdated base images with known exploits
- Failed security gates in CI/CD

**Diagnosis:**
```bash
# Scan current image for vulnerabilities
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v $HOME/Library/Caches:/root/.cache/ aquasec/trivy:latest image nginx:latest

# Check base image age and update availability
docker image inspect nginx:latest | jq '.[0].Created'
docker image history nginx:latest

# Compare vulnerability counts across image versions
for tag in "latest" "1.21" "1.20" "alpine"; do
    echo "=== nginx:$tag ==="
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
      aquasec/trivy:latest image --format table nginx:$tag | grep -E "(CRITICAL|HIGH)"
done
```

**Solution:**
```bash
# Switch to minimal, security-focused base images
# Instead of ubuntu:latest, use:
FROM ubuntu:22.04-20240112  # Specific date-based tag
# or
FROM gcr.io/distroless/java17-debian12  # Distroless images
# or  
FROM alpine:3.19  # Minimal Alpine

# Multi-stage build to reduce attack surface
cat > Dockerfile.secure << 'EOF'
# Build stage
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

# Runtime stage - minimal image
FROM gcr.io/distroless/nodejs18-debian12
COPY --from=builder /app/node_modules /app/node_modules
COPY --from=builder /app .
EXPOSE 3000
CMD ["index.js"]
EOF

# Automate base image updates
cat > update-base-images.sh << 'EOF'
#!/bin/bash
# Check for base image updates weekly
echo "=== Checking for base image updates ==="

IMAGES=("node:18-alpine" "nginx:alpine" "python:3.11-slim")

for image in "${IMAGES[@]}"; do
    echo "Checking $image..."
    
    # Get current image digest
    LOCAL_DIGEST=$(docker image inspect $image --format '{{.RepoDigests}}' 2>/dev/null)
    
    # Pull latest
    docker pull $image > /dev/null 2>&1
    
    # Get new digest
    NEW_DIGEST=$(docker image inspect $image --format '{{.RepoDigests}}')
    
    if [ "$LOCAL_DIGEST" != "$NEW_DIGEST" ]; then
        echo "  Update available for $image"
        echo "   Old: $LOCAL_DIGEST"
        echo "   New: $NEW_DIGEST"
        
        # Trigger rebuild of dependent images
        echo "Triggering rebuild pipeline for $image..."
    else
        echo " $image is up to date"
    fi
done
EOF
```

### Dockerfile Security Issues

#### Issue: Running containers as root user

**Symptoms:**
- Containers running with UID 0
- Excessive privileges in container processes
- Failed security compliance scans

**Diagnosis:**
```bash
# Check what user processes run as in container
docker exec container_name id
docker exec container_name ps aux

# Check Dockerfile for USER directive
docker image inspect app:latest | jq '.[0].Config.User'

# Check if container can write to sensitive areas
docker exec container_name ls -la /etc/passwd
docker exec container_name touch /etc/test-file 2>&1
```

**Solution:**
```bash
# Create proper non-root user in Dockerfile
cat > Dockerfile.nonroot << 'EOF'
FROM node:18-alpine

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001 -G nodejs

# Set ownership of app directory  
WORKDIR /app
RUN chown -R nextjs:nodejs /app
USER nextjs

# Copy files as the non-root user
COPY --chown=nextjs:nodejs package*.json ./
COPY --chown=nextjs:nodejs . .

EXPOSE 3000
CMD ["node", "index.js"]
EOF

# For existing containers, run with user flag
docker run --user 1001:1001 app:latest

# Security scanning to verify non-root execution
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy:latest image --security-checks config app:latest
```

#### Issue: Excessive capabilities and privileges

**Diagnosis:**
```bash
# Check container capabilities
docker exec container_name capsh --print

# Check if running in privileged mode
docker inspect container_name | jq '.[0].HostConfig.Privileged'

# Check capability additions
docker inspect container_name | jq '.[0].HostConfig.CapAdd'
```

**Solution:**
```bash
# Drop all capabilities and add only necessary ones
docker run --cap-drop ALL --cap-add NET_BIND_SERVICE nginx:alpine

# Use security-opt to enable additional restrictions
docker run --security-opt no-new-privileges:true \
           --security-opt seccomp:unconfined \
           --read-only \
           --tmpfs /tmp \
           app:latest

# Dockerfile security best practices
cat > Dockerfile.hardened << 'EOF'
FROM alpine:3.19

# Install security updates
RUN apk update && apk upgrade && \
    apk add --no-cache ca-certificates && \
    rm -rf /var/cache/apk/*

# Create non-root user
RUN adduser -D -s /bin/sh appuser

# Set secure file permissions
COPY --chown=appuser:appuser app /app
RUN chmod 755 /app && \
    chmod +x /app/entrypoint.sh

USER appuser

# Health check for container monitoring
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

EXPOSE 8080
CMD ["/app/entrypoint.sh"]
EOF
```

## Runtime Security

### Container Escape Attempts

#### Issue: Detecting container escape attempts

**Symptoms:**
- Unusual process activity
- Attempts to access host filesystem
- Suspicious network connections

**Detection:**
```bash
# Monitor for container escape indicators
cat > monitor-container-escape.sh << 'EOF'
#!/bin/bash
echo "=== Container Escape Monitoring ==="

# Check for unusual mount points
echo "Checking for suspicious mounts..."
docker exec $CONTAINER_ID mount | grep -E "(proc|sys|dev)" | grep -v "ro"

# Look for attempts to access host namespace
echo "Checking process namespaces..."
docker exec $CONTAINER_ID ls -la /proc/1/ns/
docker exec $CONTAINER_ID readlink /proc/1/ns/pid

# Monitor for privilege escalation attempts
echo "Checking for setuid/setgid files..."
docker exec $CONTAINER_ID find / -perm -4000 -o -perm -2000 2>/dev/null

# Check for Docker socket access
echo "Checking for Docker socket access..."
docker exec $CONTAINER_ID ls -la /var/run/docker.sock 2>/dev/null && echo " Docker socket exposed!"

# Monitor process tree for anomalies
echo "Process tree analysis..."
docker exec $CONTAINER_ID ps axjf
EOF

# Real-time monitoring with Falco
cat > falco-container-rules.yml << 'EOF'
- rule: Container Escape Attempt
  desc: Detect attempts to escape from container
  condition: >
    spawned_process and container and
    (proc.name in (mount, umount, nsenter, unshare) or
     (proc.name = chroot and proc.args contains ".."))
  output: Container escape attempt (user=%user.name container=%container.name command=%proc.cmdline)
  priority: CRITICAL

- rule: Sensitive Mount in Container
  desc: Sensitive filesystem mounted in container
  condition: >
    container and
    fd.name pmatch (/proc/* or /sys/* or /dev/* or /var/run/docker.sock)
  output: Sensitive mount in container (container=%container.name file=%fd.name)
  priority: HIGH
EOF
```

**Response:**
```bash
# Immediate containment
docker pause suspicious_container
docker network disconnect bridge suspicious_container

# Evidence collection
docker logs suspicious_container > container-escape-logs.txt
docker exec suspicious_container ps aux > process-dump.txt
docker exec suspicious_container netstat -tulpn > network-connections.txt

# Forensic analysis
docker export suspicious_container > container-filesystem.tar
# Analyze the exported filesystem for indicators

# Remediation
docker stop suspicious_container
docker rm suspicious_container
# Review and harden container security policies
```

### Runtime Protection

#### Implementing runtime security monitoring

```bash
# Deploy Falco for runtime security
cat > falco-deployment.yml << 'EOF'
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: falco
spec:
  selector:
    matchLabels:
      app: falco
  template:
    metadata:
      labels:
        app: falco
    spec:
      serviceAccount: falco
      hostNetwork: true
      hostPID: true
      containers:
      - name: falco
        image: falcosecurity/falco:latest
        securityContext:
          privileged: true
        volumeMounts:
        - mountPath: /host/var/run/docker.sock
          name: docker-socket
        - mountPath: /host/proc
          name: proc-fs
          readOnly: true
        - mountPath: /host/boot
          name: boot-fs
          readOnly: true
        - mountPath: /host/lib/modules
          name: lib-modules
          readOnly: true
        - mountPath: /host/usr
          name: usr-fs
          readOnly: true
      volumes:
      - name: docker-socket
        hostPath:
          path: /var/run/docker.sock
      - name: proc-fs
        hostPath:
          path: /proc
      - name: boot-fs
        hostPath:
          path: /boot
      - name: lib-modules
        hostPath:
          path: /lib/modules
      - name: usr-fs
        hostPath:
          path: /usr
EOF

# Configure runtime security policies
cat > runtime-security-policy.json << 'EOF'
{
  "default_action": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": ["read", "write", "open", "close", "stat", "mmap"],
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "names": ["mount", "umount2", "ptrace", "setuid", "setgid"],
      "action": "SCMP_ACT_KILL"
    }
  ]
}
EOF

# Apply seccomp profile
docker run --security-opt seccomp:runtime-security-policy.json app:latest
```

## Secrets Management

### Secret Exposure in Containers

#### Issue: Secrets exposed in container environment or filesystem

**Symptoms:**
- API keys visible in environment variables
- Credentials stored in container images
- Secrets accessible via container inspection

**Diagnosis:**
```bash
# Check for secrets in environment variables
docker exec container_name env | grep -iE "(password|secret|key|token)"

# Inspect image layers for secrets
docker image history app:latest --format "table {{.CreatedBy}}" | grep -iE "(password|secret|key)"

# Check filesystem for credential files
docker exec container_name find / -name "*secret*" -o -name "*key*" -o -name "*password*" 2>/dev/null

# Scan container for common secret patterns
cat > scan-container-secrets.sh << 'EOF'
#!/bin/bash
CONTAINER_ID=$1

echo "=== Scanning $CONTAINER_ID for secrets ==="

# Environment variables
echo "Environment variables containing potential secrets:"
docker exec $CONTAINER_ID env | grep -iE "(api_key|password|secret|token|credential)" | head -10

# Process command lines  
echo "Process command lines with potential secrets:"
docker exec $CONTAINER_ID ps axww | grep -iE "(password|secret|key)" | head -5

# Files containing secrets
echo "Files potentially containing secrets:"
docker exec $CONTAINER_ID find /app /home -type f -name "*.conf" -o -name "*.cfg" -o -name "*.env" 2>/dev/null | \
  xargs docker exec $CONTAINER_ID grep -l -iE "(password|secret|api_key)" 2>/dev/null | head -5
EOF
```

**Solution:**
```bash
# Use Docker secrets (Swarm mode)
echo "mysecretpassword" | docker secret create db_password -
docker service create --secret db_password --name webapp nginx

# Use init containers for secret injection
cat > secret-injection.yml << 'EOF'
apiVersion: v1
kind: Pod
spec:
  initContainers:
  - name: secret-fetcher
    image: vault:latest
    command: ['sh', '-c']
    args:
    - |
      vault auth -method=aws
      vault kv get -field=password secret/db > /shared/db-password
    volumeMounts:
    - name: shared-secrets
      mountPath: /shared
  containers:
  - name: app
    image: myapp:latest
    volumeMounts:
    - name: shared-secrets
      mountPath: /secrets
      readOnly: true
  volumes:
  - name: shared-secrets
    emptyDir:
      medium: Memory  # Store in memory, not disk
EOF

# External secret management
cat > external-secrets.sh << 'EOF'
#!/bin/bash
# Retrieve secrets from external sources at runtime

# AWS Systems Manager Parameter Store
export DB_PASSWORD=$(aws ssm get-parameter --name "/app/db-password" --with-decryption --query Parameter.Value --output text)

# HashiCorp Vault
export API_KEY=$(vault kv get -field=api_key secret/app-credentials)

# Azure Key Vault  
export SECRET_VALUE=$(az keyvault secret show --vault-name mykeyvault --name mysecret --query value --output tsv)

# Start application with secrets from environment
exec "$@"
EOF

# Remove secrets from images
cat > Dockerfile.no-secrets << 'EOF'
FROM node:18-alpine

# Install packages in separate layer
COPY package*.json ./
RUN npm ci --only=production

# Copy application code (secrets injected at runtime)
COPY src/ src/
COPY public/ public/

# Create non-root user
RUN adduser -D appuser
USER appuser

# Secrets will be mounted or injected at runtime
EXPOSE 3000
CMD ["node", "src/index.js"]
EOF
```

## Network Security

### Container Network Isolation Issues

#### Issue: Containers can communicate without restrictions

**Symptoms:**
- Containers can reach unauthorized services
- No network segmentation between environments
- Lateral movement possibilities

**Diagnosis:**
```bash
# Check container network connectivity
docker exec container1 ping container2
docker exec container1 nc -zv database 5432
docker exec container1 curl -I http://internal-api:8080

# Check network configuration
docker network ls
docker network inspect bridge

# Analyze network traffic
docker exec container_name netstat -tulpn
docker exec container_name ss -tulpn
```

**Solution:**
```bash
# Create isolated networks for different tiers
docker network create --driver bridge frontend-network
docker network create --driver bridge backend-network  
docker network create --driver bridge database-network

# Run containers on appropriate networks
docker run -d --name web --network frontend-network nginx
docker run -d --name api --network backend-network myapi:latest
docker run -d --name db --network database-network postgres:13

# Connect only necessary containers
docker network connect backend-network web  # Allow web -> api
docker network connect database-network api  # Allow api -> db
# web cannot directly access db (no connection)

# Implement network policies with docker-compose
cat > docker-compose.secure.yml << 'EOF'
version: '3.8'

services:
  web:
    image: nginx
    networks:
      - frontend
    ports:
      - "80:80"
  
  api:
    image: myapi:latest  
    networks:
      - frontend
      - backend
    depends_on:
      - database
  
  database:
    image: postgres:13
    networks:
      - backend
    environment:
      POSTGRES_DB: myapp
      POSTGRES_USER: dbuser
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    secrets:
      - db_password

networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge
    internal: true  # No external access

secrets:
  db_password:
    external: true
EOF

# Network monitoring and logging
cat > monitor-container-network.sh << 'EOF'
#!/bin/bash
echo "=== Container Network Security Monitor ==="

# Monitor network connections
echo "Active container connections:"
for container in $(docker ps --format "{{.Names}}"); do
    echo "=== $container ==="
    docker exec $container netstat -tun 2>/dev/null | grep ESTABLISHED
done

# Check for unusual network activity  
echo "Checking for unusual network patterns..."
docker exec $1 ss -tuln | grep -E ":22|:23|:3389|:5432" && echo " Potential unauthorized access"

# Monitor DNS queries
echo "Recent DNS queries:"
docker logs $1 2>&1 | grep -E "nslookup|dig|host" | tail -5
EOF
```

## Vulnerability Scanning

### Comprehensive Image Scanning

#### Setting up multi-tool vulnerability scanning

```bash
# Create comprehensive scanning pipeline
cat > container-security-scan.sh << 'EOF'
#!/bin/bash
IMAGE=$1
REPORT_DIR="security-reports/$(date +%Y%m%d-%H%M%S)"
mkdir -p $REPORT_DIR

echo "=== Comprehensive Container Security Scan ==="
echo "Image: $IMAGE"
echo "Report Directory: $REPORT_DIR"

# 1. Trivy - Vulnerability and misconfiguration scanning
echo "Running Trivy scan..."
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v $PWD/$REPORT_DIR:/reports \
  aquasec/trivy:latest image \
  --format json \
  --output /reports/trivy-report.json \
  $IMAGE

# 2. Grype - Vulnerability scanning
echo "Running Grype scan..."
grype $IMAGE -o json > $REPORT_DIR/grype-report.json

# 3. Docker Bench Security (if available)
echo "Running Docker Bench Security..."
docker run --rm --net host --pid host --userns host --cap-add audit_control \
  -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
  -v /etc:/etc:ro \
  -v /var/lib:/var/lib:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /usr/lib/systemd:/usr/lib/systemd:ro \
  -v /etc/systemd:/etc/systemd:ro \
  --label docker_bench_security \
  docker/docker-bench-security > $REPORT_DIR/docker-bench.txt

# 4. Hadolint - Dockerfile linting
echo "Running Hadolint (Dockerfile analysis)..."
hadolint Dockerfile --format json > $REPORT_DIR/hadolint-report.json 2>/dev/null || echo "Hadolint failed or no Dockerfile found"

# 5. Generate summary report
echo "Generating summary report..."
python3 generate-security-summary.py $REPORT_DIR

echo "=== Scan Complete ==="
echo "Reports available in: $REPORT_DIR"
EOF

# Security report generation script
cat > generate-security-summary.py << 'EOF'
#!/usr/bin/env python3
import json
import sys
import os
from datetime import datetime

def parse_trivy_report(report_path):
    try:
        with open(report_path, 'r') as f:
            data = json.load(f)
        
        vulnerabilities = []
        if 'Results' in data:
            for result in data['Results']:
                if 'Vulnerabilities' in result:
                    vulnerabilities.extend(result['Vulnerabilities'])
        
        # Count by severity
        severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('Severity', 'UNKNOWN')
            if severity in severity_count:
                severity_count[severity] += 1
        
        return severity_count, len(vulnerabilities)
    except:
        return {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}, 0

def generate_summary(report_dir):
    print(f"=== Security Scan Summary ===")
    print(f"Generated: {datetime.now().isoformat()}")
    print(f"Report Directory: {report_dir}")
    
    # Trivy results
    trivy_path = os.path.join(report_dir, 'trivy-report.json')
    if os.path.exists(trivy_path):
        severity_count, total_vulns = parse_trivy_report(trivy_path)
        print(f"\nTrivy Vulnerability Scan:")
        print(f"  Total Vulnerabilities: {total_vulns}")
        print(f"  Critical: {severity_count['CRITICAL']}")
        print(f"  High: {severity_count['HIGH']}")
        print(f"  Medium: {severity_count['MEDIUM']}")
        print(f"  Low: {severity_count['LOW']}")
        
        if severity_count['CRITICAL'] > 0:
            print("   CRITICAL vulnerabilities found - immediate action required")
        elif severity_count['HIGH'] > 0:
            print("   HIGH severity vulnerabilities found - review recommended")
    
    # Check for other reports
    grype_path = os.path.join(report_dir, 'grype-report.json')
    if os.path.exists(grype_path):
        print(f"\n Grype scan completed - check {grype_path}")
    
    hadolint_path = os.path.join(report_dir, 'hadolint-report.json')
    if os.path.exists(hadolint_path):
        print(f" Dockerfile analysis completed - check {hadolint_path}")
    
    docker_bench_path = os.path.join(report_dir, 'docker-bench.txt')
    if os.path.exists(docker_bench_path):
        print(f" Docker Bench Security completed - check {docker_bench_path}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 generate-security-summary.py <report-directory>")
        sys.exit(1)
    
    generate_summary(sys.argv[1])
EOF
```

## Emergency Response

### Container Security Incident Response

#### Immediate response to security incidents

```bash
# Emergency container isolation script
cat > emergency-isolate.sh << 'EOF'
#!/bin/bash
CONTAINER_ID=$1

if [ -z "$CONTAINER_ID" ]; then
    echo "Usage: $0 <container_id>"
    exit 1
fi

echo "=== EMERGENCY CONTAINER ISOLATION ==="
echo "Container: $CONTAINER_ID"
echo "Time: $(date)"

# Step 1: Pause the container (stops execution but keeps state)
echo "Pausing container..."
docker pause $CONTAINER_ID

# Step 2: Collect forensic evidence
echo "Collecting evidence..."
mkdir -p incident-$(date +%Y%m%d-%H%M%S)
INCIDENT_DIR="incident-$(date +%Y%m%d-%H%M%S)"

# Container metadata
docker inspect $CONTAINER_ID > $INCIDENT_DIR/container-inspect.json

# Process list before isolation
docker exec $CONTAINER_ID ps aux > $INCIDENT_DIR/processes.txt 2>/dev/null || echo "Container paused - cannot collect processes"

# Network connections
docker exec $CONTAINER_ID netstat -tulpn > $INCIDENT_DIR/network-connections.txt 2>/dev/null || echo "Container paused - cannot collect network info"

# Container logs
docker logs $CONTAINER_ID > $INCIDENT_DIR/container-logs.txt

# Step 3: Network isolation
echo "Isolating network..."
NETWORKS=$(docker inspect $CONTAINER_ID | jq -r '.[0].NetworkSettings.Networks | keys[]')
for network in $NETWORKS; do
    if [ "$network" != "none" ]; then
        docker network disconnect $network $CONTAINER_ID 2>/dev/null || true
    fi
done

# Step 4: Memory dump (if possible)
echo "Attempting memory dump..."
PID=$(docker inspect $CONTAINER_ID | jq -r '.[0].State.Pid')
if [ "$PID" != "null" ] && [ "$PID" != "0" ]; then
    gcore -o $INCIDENT_DIR/memory-dump $PID 2>/dev/null || echo "Memory dump failed"
fi

# Step 5: Filesystem snapshot
echo "Creating filesystem snapshot..."
docker commit $CONTAINER_ID forensic-snapshot-$(date +%Y%m%d-%H%M%S)

echo "=== ISOLATION COMPLETE ==="
echo "Evidence collected in: $INCIDENT_DIR"
echo "Container is paused and network-isolated"
echo "Next steps:"
echo "1. Analyze evidence in $INCIDENT_DIR"
echo "2. Review container logs and inspect output"
echo "3. Determine if container can be safely unpaused or should be terminated"
echo "4. Update security policies based on findings"

# Create incident report template
cat > $INCIDENT_DIR/incident-report.md << 'REPORT'
# Container Security Incident Report

**Date:** $(date)
**Container ID:** $CONTAINER_ID
**Incident Handler:** $(whoami)

## Incident Summary
- [ ] Describe what triggered the incident
- [ ] Initial indicators observed
- [ ] Impact assessment

## Actions Taken
- [x] Container paused at $(date)
- [x] Network isolation completed
- [x] Forensic evidence collected
- [ ] Root cause analysis
- [ ] Remediation plan

## Evidence Location
- Container inspection: $INCIDENT_DIR/container-inspect.json
- Container logs: $INCIDENT_DIR/container-logs.txt
- Forensic snapshot: forensic-snapshot-$(date +%Y%m%d-%H%M%S)

## Next Steps
1. [ ] Analyze collected evidence
2. [ ] Determine attack vector
3. [ ] Check for lateral movement
4. [ ] Update security controls
5. [ ] Document lessons learned

REPORT

EOF

chmod +x emergency-isolate.sh
```

This Docker security guide provides troubleshooting for the most critical container security issues. Each section includes diagnosis commands, proven solutions, and examples that security engineers face daily. The emergency response procedures ensure you can quickly contain threats while preserving evidence for forensic analysis.