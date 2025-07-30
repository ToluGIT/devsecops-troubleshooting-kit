#!/bin/bash

# DevSecOps Security Baseline Assessment Tool
# This script performs a security posture assessment
# Author: DevSecOps Troubleshooting Kit
# Version: 1.0

set -e  # Exit on any error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables
REPORT_DIR="security-baseline-$(date +%Y%m%d-%H%M%S)"
SCORE=0
MAX_SCORE=0
CRITICAL_ISSUES=0
HIGH_ISSUES=0
MEDIUM_ISSUES=0
LOW_ISSUES=0

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    SCORE=$((SCORE + 1))
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    MEDIUM_ISSUES=$((MEDIUM_ISSUES + 1))
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
    HIGH_ISSUES=$((HIGH_ISSUES + 1))
}

log_critical() {
    echo -e "${RED}[CRIT]${NC} $1"
    CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
}

check_command() {
    if command -v "$1" &> /dev/null; then
        return 0
    else
        return 1
    fi
}

# Initialize report directory
init_report() {
    mkdir -p "$REPORT_DIR"/{system,network,containers,kubernetes,cloud,compliance}
    log_info "Security baseline assessment started"
    log_info "Report directory: $REPORT_DIR"
    
    # Create assessment metadata
    cat > "$REPORT_DIR/assessment-metadata.json" << EOF
{
    "assessment_time": "$(date -Iseconds)",
    "hostname": "$(hostname)",
    "os": "$(uname -a)",
    "user": "$(whoami)",
    "assessment_id": "baseline-$(date +%Y%m%d-%H%M%S)"
}
EOF
}

# System Security Assessment
assess_system_security() {
    log_info "=== System Security Assessment ==="
    MAX_SCORE=$((MAX_SCORE + 10))
    
    # Check for root privileges
    if [ "$(id -u)" = "0" ]; then
        log_warning "Running as root - consider using sudo for specific tasks only"
    else
        log_success "Running as non-root user"
    fi
    
    # Check system updates
    if check_command "apt-get"; then
        UPDATES=$(apt list --upgradable 2>/dev/null | wc -l)
        if [ "$UPDATES" -gt 1 ]; then
            log_warning "$((UPDATES - 1)) packages need updating"
            apt list --upgradable 2>/dev/null > "$REPORT_DIR/system/pending-updates.txt"
        else
            log_success "System packages are up to date"
        fi
    elif check_command "yum"; then
        UPDATES=$(yum check-update --quiet 2>/dev/null | wc -l)
        if [ "$UPDATES" -gt 0 ]; then
            log_warning "$UPDATES packages need updating"
            yum check-update > "$REPORT_DIR/system/pending-updates.txt" 2>/dev/null || true
        else
            log_success "System packages are up to date"
        fi
    fi
    
    # Check for security tools
    SECURITY_TOOLS=("fail2ban" "ufw" "iptables" "auditd" "rkhunter" "clamav")
    INSTALLED_TOOLS=0
    
    for tool in "${SECURITY_TOOLS[@]}"; do
        if check_command "$tool"; then
            INSTALLED_TOOLS=$((INSTALLED_TOOLS + 1))
        fi
    done
    
    if [ "$INSTALLED_TOOLS" -ge 3 ]; then
        log_success "$INSTALLED_TOOLS security tools installed"
    else
        log_warning "Only $INSTALLED_TOOLS security tools installed (recommended: 3+)"
    fi
    
    # Check file permissions
    SUSPICIOUS_FILES=$(find /tmp /var/tmp -type f -perm -002 2>/dev/null | wc -l)
    if [ "$SUSPICIOUS_FILES" -gt 0 ]; then
        log_warning "$SUSPICIOUS_FILES world-writable files in temp directories"
        find /tmp /var/tmp -type f -perm -002 2>/dev/null > "$REPORT_DIR/system/world-writable-files.txt"
    else
        log_success "No world-writable files in temp directories"
    fi
    
    # Check SUID/SGID files
    find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null > "$REPORT_DIR/system/suid-sgid-files.txt"
    SUID_COUNT=$(wc -l < "$REPORT_DIR/system/suid-sgid-files.txt")
    if [ "$SUID_COUNT" -gt 50 ]; then
        log_warning "$SUID_COUNT SUID/SGID files found (review for necessity)"
    else
        log_success "Reasonable number of SUID/SGID files ($SUID_COUNT)"
    fi
    
    # Check user accounts
    USERS_WITH_SHELL=$(awk -F: '$7 ~ /(bash|sh|zsh)$/ {print $1}' /etc/passwd | wc -l)
    if [ "$USERS_WITH_SHELL" -gt 5 ]; then
        log_warning "$USERS_WITH_SHELL users have shell access"
        awk -F: '$7 ~ /(bash|sh|zsh)$/ {print $1}' /etc/passwd > "$REPORT_DIR/system/shell-users.txt"
    else
        log_success "Limited shell access ($USERS_WITH_SHELL users)"
    fi
    
    # Check SSH configuration
    if [ -f "/etc/ssh/sshd_config" ]; then
        SSH_ISSUES=0
        
        if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config 2>/dev/null; then
            log_error "SSH root login is enabled"
            SSH_ISSUES=$((SSH_ISSUES + 1))
        fi
        
        if grep -q "^PasswordAuthentication yes" /etc/ssh/sshd_config 2>/dev/null; then
            log_warning "SSH password authentication is enabled"
            SSH_ISSUES=$((SSH_ISSUES + 1))
        fi
        
        if [ "$SSH_ISSUES" -eq 0 ]; then
            log_success "SSH configuration appears secure"
        fi
        
        cp /etc/ssh/sshd_config "$REPORT_DIR/system/sshd_config.txt"
    fi
    
    # Check for running services
    if check_command "systemctl"; then
        systemctl list-units --type=service --state=running > "$REPORT_DIR/system/running-services.txt"
        SERVICE_COUNT=$(systemctl list-units --type=service --state=running --no-pager | wc -l)
        if [ "$SERVICE_COUNT" -gt 50 ]; then
            log_warning "$SERVICE_COUNT services running (review for necessity)"
        else
            log_success "Reasonable number of services running ($SERVICE_COUNT)"
        fi
    fi
}

# Network Security Assessment  
assess_network_security() {
    log_info "=== Network Security Assessment ==="
    MAX_SCORE=$((MAX_SCORE + 8))
    
    # Check listening ports
    LISTENING_PORTS=$(netstat -tlnp 2>/dev/null | grep LISTEN | wc -l)
    netstat -tlnp 2>/dev/null > "$REPORT_DIR/network/listening-ports.txt"
    
    if [ "$LISTENING_PORTS" -lt 10 ]; then
        log_success "$LISTENING_PORTS listening ports (minimal exposure)"
    elif [ "$LISTENING_PORTS" -lt 20 ]; then
        log_warning "$LISTENING_PORTS listening ports (review necessity)"
    else
        log_error "$LISTENING_PORTS listening ports (high exposure risk)"
    fi
    
    # Check for dangerous services
    DANGEROUS_PORTS=("21" "23" "135" "139" "445" "1433" "3306" "5432")
    DANGEROUS_FOUND=0
    
    for port in "${DANGEROUS_PORTS[@]}"; do
        if netstat -tln 2>/dev/null | grep -q ":$port "; then
            log_warning "Potentially dangerous service on port $port"
            DANGEROUS_FOUND=$((DANGEROUS_FOUND + 1))
        fi
    done
    
    if [ "$DANGEROUS_FOUND" -eq 0 ]; then
        log_success "No obviously dangerous services exposed"
    fi
    
    # Check firewall status
    if check_command "ufw"; then
        if ufw status | grep -q "Status: active"; then
            log_success "UFW firewall is active"
        else
            log_error "UFW firewall is inactive"
        fi
    elif check_command "iptables"; then
        IPTABLES_RULES=$(iptables -L | wc -l)
        if [ "$IPTABLES_RULES" -gt 10 ]; then
            log_success "Iptables rules configured"
        else
            log_warning "Minimal or no iptables rules configured"
        fi
        iptables -L -n > "$REPORT_DIR/network/iptables-rules.txt"
    fi
    
    # Check network interfaces
    ip addr show > "$REPORT_DIR/network/network-interfaces.txt"
    
    # Check for promiscuous mode interfaces
    PROMISCUOUS=$(ip link show | grep PROMISC | wc -l)
    if [ "$PROMISCUOUS" -gt 0 ]; then
        log_warning "$PROMISCUOUS interfaces in promiscuous mode"
        ip link show | grep PROMISC > "$REPORT_DIR/network/promiscuous-interfaces.txt"
    else
        log_success "No interfaces in promiscuous mode"
    fi
    
    # Check DNS configuration
    if [ -f "/etc/resolv.conf" ]; then
        PUBLIC_DNS=$(grep -E "(8\.8\.8\.8|1\.1\.1\.1|208\.67\.222\.222)" /etc/resolv.conf | wc -l)
        if [ "$PUBLIC_DNS" -gt 0 ]; then
            log_warning "Using public DNS servers (potential privacy concern)"
        else
            log_success "Using private/corporate DNS servers"
        fi
        cp /etc/resolv.conf "$REPORT_DIR/network/resolv.conf"
    fi
}

# Container Security Assessment
assess_container_security() {
    log_info "=== Container Security Assessment ==="
    MAX_SCORE=$((MAX_SCORE + 8))
    
    if ! check_command "docker"; then
        log_info "Docker not installed - skipping container assessment"
        return
    fi
    
    # Check Docker daemon configuration
    if docker info > "$REPORT_DIR/containers/docker-info.txt" 2>&1; then
        log_success "Docker daemon accessible"
        
        # Check for privileged containers
        PRIVILEGED=$(docker ps --filter "label=security.privileged=true" -q | wc -l)
        if [ "$PRIVILEGED" -gt 0 ]; then
            log_error "$PRIVILEGED privileged containers running"
            docker ps --filter "label=security.privileged=true" > "$REPORT_DIR/containers/privileged-containers.txt"
        else
            log_success "No privileged containers detected"
        fi
        
        # Check container images
        docker images > "$REPORT_DIR/containers/docker-images.txt"
        UNTAGGED_IMAGES=$(docker images | grep "<none>" | wc -l)
        if [ "$UNTAGGED_IMAGES" -gt 5 ]; then
            log_warning "$UNTAGGED_IMAGES untagged/dangling images (cleanup recommended)"
        else
            log_success "Minimal dangling images ($UNTAGGED_IMAGES)"
        fi
        
        # Check running containers
        docker ps -a > "$REPORT_DIR/containers/all-containers.txt"
        RUNNING_CONTAINERS=$(docker ps -q | wc -l)
        
        if [ "$RUNNING_CONTAINERS" -gt 0 ]; then
            # Check for containers with host mounts
            HOST_MOUNTS=$(docker ps --format "{{.Names}}" | xargs -I {} docker inspect {} --format '{{.Name}}: {{range .Mounts}}{{if eq .Type "bind"}}{{.Source}}:{{.Destination}} {{end}}{{end}}' | grep -E '(/:|/etc|/var|/proc|/sys)' | wc -l)
            
            if [ "$HOST_MOUNTS" -gt 0 ]; then
                log_warning "$HOST_MOUNTS containers with sensitive host mounts"
            else
                log_success "No containers with sensitive host mounts"
            fi
        fi
        
        # Check Docker socket exposure
        DOCKER_SOCKET_EXPOSED=$(docker ps --format "{{.Names}}" | xargs -I {} docker inspect {} --format '{{.Name}}: {{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' 2>/dev/null | grep "/var/run/docker.sock" | wc -l)
        
        if [ "$DOCKER_SOCKET_EXPOSED" -gt 0 ]; then
            log_critical "$DOCKER_SOCKET_EXPOSED containers with Docker socket access (container escape risk)"
        else
            log_success "No containers with Docker socket access"
        fi
        
    else
        log_warning "Cannot access Docker daemon (permission or service issue)"
    fi
    
    # Check for container security tools
    CONTAINER_TOOLS=("trivy" "grype" "docker-bench-security")
    CONTAINER_TOOL_COUNT=0
    
    for tool in "${CONTAINER_TOOLS[@]}"; do
        if check_command "$tool"; then
            CONTAINER_TOOL_COUNT=$((CONTAINER_TOOL_COUNT + 1))
        fi
    done
    
    if [ "$CONTAINER_TOOL_COUNT" -gt 0 ]; then
        log_success "$CONTAINER_TOOL_COUNT container security tools available"
    else
        log_warning "No container security scanning tools found"
    fi
}

# Kubernetes Security Assessment
assess_kubernetes_security() {
    log_info "=== Kubernetes Security Assessment ==="
    MAX_SCORE=$((MAX_SCORE + 10))
    
    if ! check_command "kubectl"; then
        log_info "kubectl not found - skipping Kubernetes assessment"
        return
    fi
    
    # Check cluster access
    if kubectl cluster-info > "$REPORT_DIR/kubernetes/cluster-info.txt" 2>&1; then
        log_success "Kubernetes cluster accessible"
        
        # Check for pods running as root
        ROOT_PODS=$(kubectl get pods --all-namespaces -o jsonpath='{range .items[?(@.spec.securityContext.runAsUser==0)]}{.metadata.namespace}{" "}{.metadata.name}{"\n"}{end}' 2>/dev/null | wc -l)
        
        if [ "$ROOT_PODS" -gt 0 ]; then
            log_warning "$ROOT_PODS pods running as root"
            kubectl get pods --all-namespaces -o jsonpath='{range .items[?(@.spec.securityContext.runAsUser==0)]}{.metadata.namespace}{" "}{.metadata.name}{"\n"}{end}' > "$REPORT_DIR/kubernetes/root-pods.txt" 2>/dev/null
        else
            log_success "No pods explicitly running as root"
        fi
        
        # Check for privileged pods
        PRIVILEGED_PODS=$(kubectl get pods --all-namespaces -o json 2>/dev/null | jq -r '.items[] | select(.spec.containers[]?.securityContext?.privileged==true) | "\(.metadata.namespace)/\(.metadata.name)"' | wc -l)
        
        if [ "$PRIVILEGED_PODS" -gt 0 ]; then
            log_error "$PRIVILEGED_PODS privileged pods found"
        else
            log_success "No privileged pods found"
        fi
        
        # Check network policies
        NETWORK_POLICIES=$(kubectl get networkpolicies --all-namespaces 2>/dev/null | wc -l)
        if [ "$NETWORK_POLICIES" -gt 1 ]; then
            log_success "$NETWORK_POLICIES network policies configured"
        else
            log_warning "No network policies found (pods can communicate freely)"
        fi
        
        # Check RBAC
        kubectl get clusterrolebindings > "$REPORT_DIR/kubernetes/cluster-role-bindings.txt" 2>/dev/null
        CLUSTER_ADMIN_BINDINGS=$(kubectl get clusterrolebindings -o json 2>/dev/null | jq -r '.items[] | select(.roleRef.name=="cluster-admin") | .subjects[]?.name' | wc -l)
        
        if [ "$CLUSTER_ADMIN_BINDINGS" -lt 5 ]; then
            log_success "Limited cluster-admin access ($CLUSTER_ADMIN_BINDINGS users/accounts)"
        else
            log_warning "$CLUSTER_ADMIN_BINDINGS cluster-admin bindings (review necessity)"
        fi
        
        # Check pod security standards
        PSS_NAMESPACES=$(kubectl get namespaces -o json 2>/dev/null | jq -r '.items[] | select(.metadata.labels["pod-security.kubernetes.io/enforce"]) | .metadata.name' | wc -l)
        
        if [ "$PSS_NAMESPACES" -gt 0 ]; then
            log_success "Pod Security Standards enabled on $PSS_NAMESPACES namespaces"
        else
            log_warning "No Pod Security Standards detected"
        fi
        
        # Check for default service accounts
        DEFAULT_SA=$(kubectl get pods --all-namespaces -o json 2>/dev/null | jq -r '.items[] | select(.spec.serviceAccountName=="default") | "\(.metadata.namespace)/\(.metadata.name)"' | wc -l)
        
        if [ "$DEFAULT_SA" -gt 0 ]; then
            log_warning "$DEFAULT_SA pods using default service account"
        else
            log_success "No pods using default service account"
        fi
        
        # Check secrets
        kubectl get secrets --all-namespaces > "$REPORT_DIR/kubernetes/secrets.txt" 2>/dev/null
        SECRET_COUNT=$(kubectl get secrets --all-namespaces --no-headers 2>/dev/null | wc -l)
        log_info "$SECRET_COUNT secrets in cluster"
        
    else
        log_info "Kubernetes cluster not accessible or not configured"
    fi
}

# Cloud Security Assessment (basic checks)
assess_cloud_security() {
    log_info "=== Cloud Security Assessment ==="
    MAX_SCORE=$((MAX_SCORE + 6))
    
    # Check AWS CLI
    if check_command "aws"; then
        if aws sts get-caller-identity > "$REPORT_DIR/cloud/aws-identity.txt" 2>&1; then
            log_success "AWS CLI configured and accessible"
            
            # Check for root access keys
            if aws iam list-access-keys 2>/dev/null | grep -q "Root"; then
                log_critical "Root access keys detected (security risk)"
            else
                log_success "No root access keys found"
            fi
            
        else
            log_info "AWS CLI configured but not authenticated"
        fi
    fi
    
    # Check Azure CLI
    if check_command "az"; then
        if az account show > "$REPORT_DIR/cloud/azure-account.txt" 2>&1; then
            log_success "Azure CLI configured and accessible"
        else
            log_info "Azure CLI configured but not authenticated"
        fi
    fi
    
    # Check GCP CLI
    if check_command "gcloud"; then
        if gcloud auth list --filter=status:ACTIVE > "$REPORT_DIR/cloud/gcp-auth.txt" 2>&1; then
            log_success "GCP CLI configured and accessible"
        else
            log_info "GCP CLI configured but not authenticated"
        fi
    fi
    
    # Check for cloud security tools
    CLOUD_TOOLS=("aws" "az" "gcloud" "terraform" "terraformer")
    CLOUD_TOOL_COUNT=0
    
    for tool in "${CLOUD_TOOLS[@]}"; do
        if check_command "$tool"; then
            CLOUD_TOOL_COUNT=$((CLOUD_TOOL_COUNT + 1))
        fi
    done
    
    if [ "$CLOUD_TOOL_COUNT" -ge 2 ]; then
        log_success "$CLOUD_TOOL_COUNT cloud management tools available"
    else
        log_info "$CLOUD_TOOL_COUNT cloud management tools available"
    fi
}

# Compliance and Security Tooling Assessment
assess_compliance() {
    log_info "=== Compliance & Security Tools Assessment ==="
    MAX_SCORE=$((MAX_SCORE + 8))
    
    # Check security scanners
    SECURITY_SCANNERS=("nmap" "nikto" "sqlmap" "gobuster" "ffuf")
    SCANNER_COUNT=0
    
    for scanner in "${SECURITY_SCANNERS[@]}"; do
        if check_command "$scanner"; then
            SCANNER_COUNT=$((SCANNER_COUNT + 1))
        fi
    done
    
    if [ "$SCANNER_COUNT" -gt 0 ]; then
        log_info "$SCANNER_COUNT security scanning tools available"
    else
        log_warning "No security scanning tools found"
    fi
    
    # Check vulnerability scanners
    VULN_SCANNERS=("trivy" "grype" "clair" "anchore")
    VULN_SCANNER_COUNT=0
    
    for scanner in "${VULN_SCANNERS[@]}"; do
        if check_command "$scanner"; then
            VULN_SCANNER_COUNT=$((VULN_SCANNER_COUNT + 1))
        fi
    done
    
    if [ "$VULN_SCANNER_COUNT" -gt 0 ]; then
        log_success "$VULN_SCANNER_COUNT vulnerability scanners available"
    else
        log_warning "No vulnerability scanners found"
    fi
    
    # Check SAST tools
    SAST_TOOLS=("semgrep" "bandit" "eslint" "sonar-scanner")
    SAST_COUNT=0
    
    for tool in "${SAST_TOOLS[@]}"; do
        if check_command "$tool"; then
            SAST_COUNT=$((SAST_COUNT + 1))
        fi
    done
    
    if [ "$SAST_COUNT" -gt 0 ]; then
        log_success "$SAST_COUNT SAST tools available"
    else
        log_warning "No SAST tools found"
    fi
    
    # Check secrets scanners
    SECRET_SCANNERS=("gitleaks" "trufflehog" "detect-secrets")
    SECRET_SCANNER_COUNT=0
    
    for scanner in "${SECRET_SCANNERS[@]}"; do
        if check_command "$scanner"; then
            SECRET_SCANNER_COUNT=$((SECRET_SCANNER_COUNT + 1))
        fi
    done
    
    if [ "$SECRET_SCANNER_COUNT" -gt 0 ]; then
        log_success "$SECRET_SCANNER_COUNT secret scanners available"
    else
        log_error "No secret scanners found (critical for DevSecOps)"
    fi
    
    # Check infrastructure as code scanners
    IAC_SCANNERS=("checkov" "tfsec" "terrascan")
    IAC_COUNT=0
    
    for scanner in "${IAC_SCANNERS[@]}"; do
        if check_command "$scanner"; then
            IAC_COUNT=$((IAC_COUNT + 1))
        fi
    done
    
    if [ "$IAC_COUNT" -gt 0 ]; then
        log_success "$IAC_COUNT infrastructure scanning tools available"
    else
        log_warning "No infrastructure as code scanners found"
    fi
    
    # Check for logging and monitoring
    MONITORING_TOOLS=("journalctl" "rsyslog" "fail2ban" "auditd")
    MONITORING_COUNT=0
    
    for tool in "${MONITORING_TOOLS[@]}"; do
        if check_command "$tool"; then
            MONITORING_COUNT=$((MONITORING_COUNT + 1))
        fi
    done
    
    if [ "$MONITORING_COUNT" -ge 2 ]; then
        log_success "$MONITORING_COUNT monitoring/logging tools available"
    else
        log_warning "Limited monitoring/logging tools ($MONITORING_COUNT available)"
    fi
    
    # Check backup tools
    BACKUP_TOOLS=("rsync" "tar" "duplicity" "restic")
    BACKUP_COUNT=0
    
    for tool in "${BACKUP_TOOLS[@]}"; do
        if check_command "$tool"; then
            BACKUP_COUNT=$((BACKUP_COUNT + 1))
        fi
    done
    
    if [ "$BACKUP_COUNT" -ge 1 ]; then
        log_success "$BACKUP_COUNT backup tools available"
    else
        log_error "No backup tools found"
    fi
}

# Generate comprehensive report
generate_report() {
    log_info "=== Generating Security Baseline Report ==="
    
    PERCENTAGE=$((SCORE * 100 / MAX_SCORE))
    
    # Determine security posture
    if [ "$PERCENTAGE" -ge 80 ]; then
        POSTURE="STRONG"
        POSTURE_COLOR="${GREEN}"
    elif [ "$PERCENTAGE" -ge 60 ]; then
        POSTURE="GOOD"
        POSTURE_COLOR="${YELLOW}"
    elif [ "$PERCENTAGE" -ge 40 ]; then
        POSTURE="MODERATE"
        POSTURE_COLOR="${YELLOW}"
    else
        POSTURE="WEAK"
        POSTURE_COLOR="${RED}"
    fi
    
    # Create summary report
    cat > "$REPORT_DIR/security-baseline-report.md" << EOF
# Security Baseline Assessment Report

**Assessment Date:** $(date)
**System:** $(hostname)
**Assessed By:** $(whoami)

## Executive Summary

**Overall Security Posture:** ${POSTURE}
**Security Score:** ${SCORE}/${MAX_SCORE} (${PERCENTAGE}%)

### Issue Breakdown
- **Critical Issues:** ${CRITICAL_ISSUES}
- **High Issues:** ${HIGH_ISSUES}  
- **Medium Issues:** ${MEDIUM_ISSUES}
- **Low Issues:** ${LOW_ISSUES}

## Assessment Categories

### System Security
$([ -f "$REPORT_DIR/system/pending-updates.txt" ] && echo "- Pending Updates: $(wc -l < "$REPORT_DIR/system/pending-updates.txt")" || echo "- System appears up to date")
$([ -f "$REPORT_DIR/system/world-writable-files.txt" ] && echo "- World-writable files: $(wc -l < "$REPORT_DIR/system/world-writable-files.txt")" || echo "- No world-writable temp files found")
- SUID/SGID files: $([ -f "$REPORT_DIR/system/suid-sgid-files.txt" ] && wc -l < "$REPORT_DIR/system/suid-sgid-files.txt" || echo "0")

### Network Security
- Listening ports: $([ -f "$REPORT_DIR/network/listening-ports.txt" ] && grep -c LISTEN "$REPORT_DIR/network/listening-ports.txt" || echo "Unknown")
$([ -f "$REPORT_DIR/network/promiscuous-interfaces.txt" ] && echo "- Promiscuous interfaces: $(wc -l < "$REPORT_DIR/network/promiscuous-interfaces.txt")" || echo "- No promiscuous interfaces")

### Container Security
$([ -f "$REPORT_DIR/containers/docker-info.txt" ] && echo "- Docker available and accessible" || echo "- Docker not available")
$([ -f "$REPORT_DIR/containers/privileged-containers.txt" ] && echo "- Privileged containers: $(wc -l < "$REPORT_DIR/containers/privileged-containers.txt")" || echo "- No privileged containers detected")

### Kubernetes Security
$([ -f "$REPORT_DIR/kubernetes/cluster-info.txt" ] && echo "- Kubernetes cluster accessible" || echo "- Kubernetes not available")
$([ -f "$REPORT_DIR/kubernetes/root-pods.txt" ] && echo "- Pods running as root: $(wc -l < "$REPORT_DIR/kubernetes/root-pods.txt")" || echo "- No pods explicitly running as root")

## Recommendations

### Immediate Actions Required
EOF

    # Add specific recommendations based on findings
    if [ "$CRITICAL_ISSUES" -gt 0 ]; then
        cat >> "$REPORT_DIR/security-baseline-report.md" << EOF
**CRITICAL:** $CRITICAL_ISSUES critical security issues require immediate attention:
EOF
        if [ -f "$REPORT_DIR/containers/docker-socket-exposed.txt" ]; then
            echo "- Remove Docker socket access from containers immediately" >> "$REPORT_DIR/security-baseline-report.md"
        fi
    fi
    
    if [ "$HIGH_ISSUES" -gt 0 ]; then
        cat >> "$REPORT_DIR/security-baseline-report.md" << EOF

**HIGH:** $HIGH_ISSUES high-priority security issues should be addressed within 24 hours:
EOF
        if grep -q "SSH root login is enabled" "$REPORT_DIR"/*.log 2>/dev/null; then
            echo "- Disable SSH root login" >> "$REPORT_DIR/security-baseline-report.md"
        fi
    fi
    
    cat >> "$REPORT_DIR/security-baseline-report.md" << EOF

### Security Improvements
1. **Install missing security tools:**
   - Secret scanners (gitleaks, trufflehog)
   - Vulnerability scanners (trivy, grype)
   - Infrastructure scanners (checkov, tfsec)

2. **Implement security hardening:**
   - Regular system updates
   - Proper firewall configuration  
   - Service account management
   - Network segmentation

3. **Establish security monitoring:**
   - Log aggregation and analysis
   - Intrusion detection systems
   - Vulnerability scanning automation
   - Security incident response procedures

## Files Generated
$(find "$REPORT_DIR" -type f | sed 's|^|   - |')

## Next Steps
1. Address critical and high-priority issues immediately
2. Plan remediation for medium-priority issues
3. Schedule regular security assessments
4. Implement continuous security monitoring
5. Update security policies and procedures

---
*Generated by DevSecOps Troubleshooting Kit Security Baseline Tool*
EOF

    # Create JSON summary for automation
    cat > "$REPORT_DIR/security-baseline-summary.json" << EOF
{
  "assessment_time": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "security_score": {
    "score": $SCORE,
    "max_score": $MAX_SCORE,
    "percentage": $PERCENTAGE,
    "posture": "$POSTURE"
  },
  "issues": {
    "critical": $CRITICAL_ISSUES,
    "high": $HIGH_ISSUES,
    "medium": $MEDIUM_ISSUES,
    "low": $LOW_ISSUES
  },
  "categories_assessed": [
    "system_security",
    "network_security", 
    "container_security",
    "kubernetes_security",
    "cloud_security",
    "compliance_tools"
  ],
  "recommendations": {
    "immediate_action_required": $([ "$CRITICAL_ISSUES" -gt 0 ] && echo "true" || echo "false"),
    "high_priority_items": $HIGH_ISSUES,
    "security_tools_needed": $([ "$SECRET_SCANNER_COUNT" -eq 0 ] && echo "true" || echo "false")
  }
}
EOF

    # Display summary
    echo ""
    echo "=================================================="
    echo -e "         ${POSTURE_COLOR}SECURITY BASELINE ASSESSMENT${NC}"
    echo "=================================================="
    echo -e "Security Score: ${POSTURE_COLOR}${SCORE}/${MAX_SCORE} (${PERCENTAGE}%)${NC}"
    echo -e "Security Posture: ${POSTURE_COLOR}${POSTURE}${NC}"
    echo ""
    echo "Issue Summary:"
    echo -e "  Critical: ${RED}${CRITICAL_ISSUES}${NC}"
    echo -e "  High:     ${RED}${HIGH_ISSUES}${NC}"
    echo -e "  Medium:   ${YELLOW}${MEDIUM_ISSUES}${NC}"
    echo -e "  Low:      ${BLUE}${LOW_ISSUES}${NC}"
    echo ""
    echo "📋 Full Report: $REPORT_DIR/security-baseline-report.md"
    echo "📊 JSON Summary: $REPORT_DIR/security-baseline-summary.json"
    echo "📁 Evidence Files: $REPORT_DIR/"
    echo ""
    
    if [ "$CRITICAL_ISSUES" -gt 0 ] || [ "$HIGH_ISSUES" -gt 0 ]; then
        echo -e "${RED} IMMEDIATE ACTION REQUIRED${NC}"
        echo "Critical or high-priority security issues found."
        echo "Review the report and address issues immediately."
    elif [ "$PERCENTAGE" -lt 60 ]; then
        echo -e "${YELLOW} SECURITY IMPROVEMENTS NEEDED${NC}"
        echo "Security posture needs improvement."
        echo "Focus on installing missing security tools and hardening."
    else
        echo -e "${GREEN} GOOD SECURITY POSTURE${NC}"
        echo "Continue monitoring and maintain security practices."
    fi
}

# Main execution
main() {
    echo "DevSecOps Security Baseline Assessment Tool"
    echo "=========================================="
    
    init_report
    
    assess_system_security
    assess_network_security
    assess_container_security
    assess_kubernetes_security
    assess_cloud_security
    assess_compliance
    
    generate_report
    
    echo ""
    echo "Assessment completed successfully!"
    echo "Review the report and address any critical issues immediately."
}

# Execute main function
main "$@"