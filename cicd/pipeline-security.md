# CI/CD Pipeline Security Troubleshooting Guide

This guide helps you identify, troubleshoot, and resolve security issues in CI/CD pipelines across different platforms and tools.


## Pipeline Access Control

### Overprivileged Pipeline Permissions

#### Issue: CI/CD pipelines running with excessive privileges

**Symptoms:**
- Pipelines with admin access to production environments
- Service accounts with unnecessary permissions
- Ability to modify pipeline configurations without approval

**Diagnosis:**
```bash
# GitHub Actions permission audit
cat > audit-github-actions.sh << 'EOF'
#!/bin/bash
echo " GitHub Actions Security Audit "

# Check workflow permissions
echo "1. Analyzing workflow permissions..."
find .github/workflows -name "*.yml" -o -name "*.yaml" | while read workflow; do
    echo "Workflow: $workflow"
    
    # Check for admin permissions
    if grep -q "permissions:" "$workflow"; then
        echo "  Permissions configured:"
        grep -A 20 "permissions:" "$workflow" | head -20
    else
        echo "    No explicit permissions - defaults to GITHUB_TOKEN with read/write"
    fi
    
    # Check for dangerous actions
    dangerous_actions=$(grep -E "(actions/checkout@.*|actions/upload-artifact@.*)" "$workflow" | grep -v "@v[2-9]")
    if [ ! -z "$dangerous_actions" ]; then
        echo "    Using potentially outdated actions:"
        echo "$dangerous_actions"
    fi
    
    # Check for secret usage
    secrets=$(grep -oE "secrets\.[A-Z_]+" "$workflow" | sort | uniq)
    if [ ! -z "$secrets" ]; then
        echo "  Secrets used:"
        echo "$secrets"
    fi
    
    echo ""
done

# Check for self-hosted runners (security risk)
echo "2. Checking for self-hosted runners..."
if grep -r "runs-on.*self-hosted" .github/workflows/; then
    echo "  Self-hosted runners detected - review security implications"
fi

# Check for dangerous workflow triggers
echo "3. Checking for dangerous triggers..."
find .github/workflows -name "*.yml" -o -name "*.yaml" | while read workflow; do
    if grep -q "pull_request_target" "$workflow"; then
        echo "  $workflow uses pull_request_target - can execute malicious code from forks"
    fi
    
    if grep -q "workflow_dispatch" "$workflow"; then
        echo "  $workflow allows manual triggering"
    fi
done
EOF

# Jenkins pipeline security audit
cat > audit-jenkins-pipelines.sh << 'EOF'
#!/bin/bash
echo " Jenkins Pipeline Security Audit "

# Check Jenkinsfile permissions
find . -name "Jenkinsfile*" | while read pipeline; do
    echo "Pipeline: $pipeline"
    
    # Check for credential usage
    credentials=$(grep -oE "credentials\('[^']+'\)" "$pipeline" | sort | uniq)
    if [ ! -z "$credentials" ]; then
        echo "  Credentials used:"
        echo "$credentials"
    fi
    
    # Check for shell execution
    shell_commands=$(grep -n "sh\s*['\"]" "$pipeline" | head -5)
    if [ ! -z "$shell_commands" ]; then
        echo "  Shell commands (review for injection risks):"
        echo "$shell_commands" | head -3
    fi
    
    # Check for environment variables
    env_vars=$(grep -oE "env\.[A-Z_]+" "$pipeline" | sort | uniq)
    if [ ! -z "$env_vars" ]; then
        echo "  Environment variables used:"
        echo "$env_vars"
    fi
    
    echo ""
done
EOF

# Azure DevOps pipeline audit
cat > audit-azure-pipelines.sh << 'EOF'
#!/bin/bash
echo " Azure DevOps Pipeline Security Audit "

find . -name "*azure-pipelines*.yml" -o -name "*azure-pipelines*.yaml" | while read pipeline; do
    echo "Pipeline: $pipeline"
    
    # Check service connections
    service_connections=$(grep -oE "serviceConnection: [^\\s]+" "$pipeline")
    if [ ! -z "$service_connections" ]; then
        echo "  Service connections:"
        echo "$service_connections"
    fi
    
    # Check for inline scripts
    inline_scripts=$(grep -A 5 "script: |" "$pipeline" | head -10)
    if [ ! -z "$inline_scripts" ]; then
        echo "    Inline scripts detected (review for hardcoded secrets):"
        echo "$inline_scripts" | head -3
    fi
    
    # Check variable groups
    variable_groups=$(grep -oE "group: [^\\s]+" "$pipeline")
    if [ ! -z "$variable_groups" ]; then
        echo "  Variable groups:"
        echo "$variable_groups"
    fi
    
    echo ""
done
EOF

chmod +x audit-github-actions.sh audit-jenkins-pipelines.sh audit-azure-pipelines.sh
```

**Solution:**
```bash
# Create minimal privilege GitHub Actions workflow
cat > .github/workflows/secure-ci.yml << 'EOF'
name: Secure CI Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
    # Use pull_request (not pull_request_target) to prevent code execution from forks

# Minimal permissions - grant only what's needed
permissions:
  contents: read          # Read repository contents
  security-events: write  # Upload security scan results
  actions: read          # Download artifacts from other workflows
  pull-requests: write   # Comment on PRs with results

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4  # Use latest version
      with:
        # Don't persist credentials for security
        persist-credentials: false
        
    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '18'
        cache: 'npm'
        
    # Secrets are only accessible in steps that need them
    - name: Authenticate to registry
      env:
        NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
      run: |
        echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > ~/.npmrc
        
    - name: Install dependencies
      run: npm ci --audit-signatures  # Verify package signatures
      
    - name: Run security scan
      run: |
        npm audit --audit-level=high
        npx semgrep --config=r/security .
        
    - name: Upload security results
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: security-results.sarif
        
    # Clean up secrets from environment
    - name: Cleanup
      if: always()
      run: |
        rm -f ~/.npmrc
        unset NPM_TOKEN

  build:
    needs: security-scan  # Only build if security scan passes
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write  # Push to registry
      
    steps:
    - uses: actions/checkout@v4
      with:
        persist-credentials: false
        
    - name: Build application
      run: |
        docker build -t myapp:${{ github.sha }} .
        
    # Use OIDC for authentication instead of long-lived secrets
    - name: Configure AWS credentials
      uses: aws-actions/configure-aws-credentials@v4
      with:
        role-to-assume: arn:aws:iam::ACCOUNT:role/github-actions-role
        aws-region: us-east-1
        
    - name: Push to registry
      run: |
        aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin ACCOUNT.dkr.ecr.us-east-1.amazonaws.com
        docker tag myapp:${{ github.sha }} ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/myapp:${{ github.sha }}
        docker push ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/myapp:${{ github.sha }}
EOF

# Secure Jenkins pipeline
cat > Jenkinsfile.secure << 'EOF'
pipeline {
    agent {
        // Use specific agent labels for security
        label 'secure-build-agents'
    }
    
    // Minimal required tools
    tools {
        nodejs '18.0.0'
        dockerTool '20.10.0'
    }
    
    options {
        // Security hardening options
        timeout(time: 30, unit: 'MINUTES')
        timestamps()
        buildDiscarder(logRotator(numToKeepStr: '10'))
        disableConcurrentBuilds()
    }
    
    environment {
        // Avoid exposing sensitive data in logs
        DOCKER_BUILDKIT = '1'
        BUILDX_NO_DEFAULT_ATTESTATIONS = '1'
    }
    
    stages {
        stage('Security Scan') {
            steps {
                script {
                    // Use credentials() wrapper for secure access
                    withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                        sh '''
                            # Security scanning
                            npm audit --audit-level=high
                            
                            # SAST scanning
                            sonar-scanner -Dsonar.login=${SONAR_TOKEN}
                        '''
                    }
                }
            }
            
            post {
                always {
                    // Publish security scan results
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: 'security-reports',
                        reportFiles: 'security-report.html',
                        reportName: 'Security Scan Report'
                    ])
                }
            }
        }
        
        stage('Build') {
            when {
                // Only build if security scans pass
                expression { currentBuild.result == null }
            }
            
            steps {
                script {
                    withCredentials([usernamePassword(credentialsId: 'registry-creds', 
                                                   usernameVariable: 'REGISTRY_USER', 
                                                   passwordVariable: 'REGISTRY_PASS')]) {
                        sh '''
                            # Secure docker build
                            docker build --no-cache --security-opt=no-new-privileges -t myapp:${BUILD_NUMBER} .
                            
                            # Login and push
                            echo "${REGISTRY_PASS}" | docker login -u "${REGISTRY_USER}" --password-stdin registry.company.com
                            docker tag myapp:${BUILD_NUMBER} registry.company.com/myapp:${BUILD_NUMBER}
                            docker push registry.company.com/myapp:${BUILD_NUMBER}
                        '''
                    }
                }
            }
            
            post {
                always {
                    // Clean up sensitive data
                    sh '''
                        docker logout registry.company.com
                        docker system prune -f
                    '''
                }
            }
        }
        
        stage('Deploy to Staging') {
            when {
                branch 'main'
            }
            
            steps {
                script {
                    // Use role-based authentication for deployment
                    withCredentials([kubeconfigFile(credentialsId: 'k8s-staging-config', variable: 'KUBECONFIG')]) {
                        sh '''
                            # Deploy with security context
                            kubectl apply -f k8s/staging/
                            kubectl rollout status deployment/myapp -n staging --timeout=300s
                        '''
                    }
                }
            }
        }
    }
    
    post {
        always {
            // Clean up workspace for security
            cleanWs deleteDirs: true
        }
        
        failure {
            // Send security alerts on failure
            script {
                if (env.BRANCH_NAME == 'main') {
                    slackSend(
                        channel: '#security-alerts',
                        color: 'danger',
                        message: " Security pipeline failed for ${env.JOB_NAME} - ${env.BUILD_URL}"
                    )
                }
            }
        }
    }
}
EOF
```

## Secrets Management in Pipelines

### Hardcoded Secrets in Pipeline Definitions

#### Issue: Secrets exposed in pipeline configuration files

**Symptoms:**
- API keys visible in YAML files
- Database passwords in environment variables
- Credentials committed to version control

**Diagnosis:**
```bash
# Scan for hardcoded secrets in pipeline files
cat > scan-pipeline-secrets.sh << 'EOF'
#!/bin/bash
echo "Pipeline Secrets Security Scan "

# Define patterns for common secrets
PATTERNS=(
    "api[_-]?key['\"]?\s*[:=]\s*['\"][a-zA-Z0-9]{20,}"
    "secret['\"]?\s*[:=]\s*['\"][a-zA-Z0-9+/]{20,}"
    "password['\"]?\s*[:=]\s*['\"][^'\"]{8,}"
    "token['\"]?\s*[:=]\s*['\"][a-zA-Z0-9._-]{20,}"
    "aws_access_key_id['\"]?\s*[:=]\s*['\"]AKIA[0-9A-Z]{16}"
    "-----BEGIN [A-Z ]+-----"
    "mysql://[^:]+:[^@]+@"
    "postgres://[^:]+:[^@]+@"
)

# Files to scan
FILES_TO_SCAN=(
    ".github/workflows/*.yml"
    ".github/workflows/*.yaml" 
    "Jenkinsfile*"
    "*azure-pipelines*.yml"
    "*azure-pipelines*.yaml"
    ".gitlab-ci.yml"
    "bitbucket-pipelines.yml"
    "Dockerfile"
    "docker-compose*.yml"
    "*.env"
    "*.properties"
)

echo "1. Scanning pipeline files for hardcoded secrets..."
for file_pattern in "${FILES_TO_SCAN[@]}"; do
    if ls $file_pattern 1> /dev/null 2>&1; then
        for file in $file_pattern; do
            echo "Scanning: $file"
            
            for pattern in "${PATTERNS[@]}"; do
                matches=$(grep -n -E "$pattern" "$file" 2>/dev/null || true)
                if [ ! -z "$matches" ]; then
                    echo "  Potential secret found:"
                    echo "$matches" | head -3
                fi
            done
        done
    fi
done

# Check for environment variables that might contain secrets
echo -e "\n2. Checking for suspicious environment variables..."
find . -name "*.yml" -o -name "*.yaml" -o -name "Jenkinsfile*" | xargs grep -l "env:" | while read file; do
    suspicious_envs=$(grep -A 20 "env:" "$file" | grep -iE "(key|secret|password|token)" | head -5)
    if [ ! -z "$suspicious_envs" ]; then
        echo "File: $file"
        echo "$suspicious_envs"
        echo ""
    fi
done

# Check git history for secrets
echo "3. Checking git history for leaked secrets..."
git log --oneline -n 50 | cut -d' ' -f1 | while read commit; do
    secret_files=$(git show --name-only "$commit" | grep -E "\.(yml|yaml|env|properties)$" | head -3)
    if [ ! -z "$secret_files" ]; then
        for file in $secret_files; do
            for pattern in "${PATTERNS[@]}"; do
                if git show "$commit:$file" 2>/dev/null | grep -q -E "$pattern"; then
                    echo "  Potential secret in commit $commit:$file"
                fi
            done
        done
    fi
done
EOF

chmod +x scan-pipeline-secrets.sh
./scan-pipeline-secrets.sh
```

**Solution:**
```bash
# Implement secure secrets management
cat > setup-secure-secrets.sh << 'EOF'
#!/bin/bash
echo " Setting up Secure Secrets Management "

# GitHub Actions with OIDC
cat > .github/workflows/secure-secrets.yml << 'GHA_SECRETS'
name: Secure Secrets Example

on:
  push:
    branches: [main]

permissions:
  id-token: write  # Required for OIDC
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    
    # Use OIDC instead of long-lived credentials
    - name: Configure AWS Credentials
      uses: aws-actions/configure-aws-credentials@v4
      with:
        role-to-assume: arn:aws:iam::ACCOUNT:role/github-actions-role
        aws-region: us-east-1
        
    # Retrieve secrets from AWS Secrets Manager
    - name: Get secrets from AWS
      run: |
        DB_PASSWORD=$(aws secretsmanager get-secret-value --secret-id prod/db/password --query SecretString --output text)
        API_KEY=$(aws secretsmanager get-secret-value --secret-id prod/api/key --query SecretString --output text)
        
        # Use secrets in environment (not visible in logs)
        echo "DB_PASSWORD=$DB_PASSWORD" >> $GITHUB_ENV
        echo "API_KEY=$API_KEY" >> $GITHUB_ENV
        
    - name: Deploy application
      env:
        # Secrets are available as environment variables
        DATABASE_URL: "postgresql://user:${{ env.DB_PASSWORD }}@host/db"
      run: |
        # Deploy without exposing secrets in command line
        kubectl create secret generic app-secrets \
          --from-literal=database-url="$DATABASE_URL" \
          --from-literal=api-key="$API_KEY" \
          --dry-run=client -o yaml | kubectl apply -f -
GHA_SECRETS

# Jenkins with HashiCorp Vault
cat > Jenkinsfile.vault << 'JENKINS_VAULT'
pipeline {
    agent any
    
    stages {
        stage('Deploy') {
            steps {
                script {
                    // Use Vault to retrieve secrets
                    def secrets = [
                        [
                            path: 'secret/myapp/prod',
                            engineVersion: 2,
                            secretValues: [
                                [envVar: 'DB_PASSWORD', vaultKey: 'database_password'],
                                [envVar: 'API_KEY', vaultKey: 'api_key']
                            ]
                        ]
                    ]
                    
                    withVault([vaultSecrets: secrets]) {
                        sh '''
                            # Secrets are available as environment variables
                            # Deploy without logging sensitive values
                            kubectl create secret generic app-secrets \
                              --from-literal=database-url="postgresql://user:${DB_PASSWORD}@host/db" \
                              --from-literal=api-key="${API_KEY}" \
                              --dry-run=client -o yaml | kubectl apply -f -
                        '''
                    }
                }
            }
        }
    }
    
    post {
        always {
            // Clean up any temporary secret files
            sh 'find . -name "*secret*" -type f -delete || true'
        }
    }
}
JENKINS_VAULT

# Azure DevOps with Key Vault
cat > azure-pipelines-keyvault.yml << 'AZURE_VAULT'
trigger:
- main

pool:
  vmImage: 'ubuntu-latest'

variables:
- group: 'prod-secrets'  # Variable group linked to Key Vault

steps:
- task: AzureKeyVault@2
  inputs:
    azureSubscription: 'production-service-connection'
    keyVaultName: 'prod-key-vault'
    secretsFilter: 'database-password,api-key'
    runAsPreJob: true

- script: |
    # Secrets are available as pipeline variables
    echo "##vso[task.setvariable variable=DATABASE_URL;issecret=true]postgresql://user:$(database-password)@host/db"
  displayName: 'Set database URL'

- task: Kubernetes@1
  inputs:
    command: 'apply'
    arguments: '-f k8s/secrets.yaml'
  env:
    DB_PASSWORD: $(database-password)
    API_KEY: $(api-key)
AZURE_VAULT

# External Secrets Operator for Kubernetes
cat > external-secrets.yaml << 'EXT_SECRETS'
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: vault-backend
spec:
  provider:
    vault:
      server: "https://vault.company.com"
      path: "secret"
      version: "v2"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "external-secrets"

---
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: app-secrets
spec:
  refreshInterval: 300s  # Refresh every 5 minutes
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: app-secrets
    creationPolicy: Owner
  data:
  - secretKey: database-password
    remoteRef:
      key: secret/myapp/prod
      property: database_password
  - secretKey: api-key
    remoteRef:
      key: secret/myapp/prod
      property: api_key
EXT_SECRETS

echo " Secure secrets management examples created"
echo "Choose the appropriate method for your platform:"
echo "- GitHub Actions: .github/workflows/secure-secrets.yml"
echo "- Jenkins: Jenkinsfile.vault"
echo "- Azure DevOps: azure-pipelines-keyvault.yml"
echo "- Kubernetes: external-secrets.yaml"
EOF

chmod +x setup-secure-secrets.sh
```

## Build Environment Security

### Compromised Build Agents

#### Issue: Build agents infected with malware or compromised

**Symptoms:**
- Unexpected network connections during builds
- Modified build artifacts
- Suspicious process activity on build agents

**Diagnosis:**
```bash
# Build agent security monitoring
cat > monitor-build-agents.sh << 'EOF'
#!/bin/bash
echo " Build Agent Security Monitoring "

# Check for unusual processes
echo "1. Checking for suspicious processes..."
ps aux | grep -E "(wget|curl|nc|ncat|socat|python|perl|bash|sh).*http" | grep -v grep || echo "No suspicious network processes found"

# Monitor network connections
echo "2. Monitoring network connections..."
netstat -tun | grep ESTABLISHED | while read line; do
    remote_ip=$(echo $line | awk '{print $5}' | cut -d: -f1)
    # Check if IP is internal
    if [[ ! $remote_ip =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.) ]]; then
        echo "  External connection: $line"
    fi
done

# Check for cryptocurrency mining
echo "3. Checking for cryptocurrency mining..."
ps aux | grep -iE "(xmrig|cpuminer|ccminer|ethminer)" | grep -v grep && echo " Cryptocurrency mining detected" || echo "No mining processes found"

# Monitor file system changes
echo "4. Checking for unauthorized file modifications..."
# Check common attack locations
for path in "/tmp" "/var/tmp" "/dev/shm" "/home"; do
    if [ -d "$path" ]; then
        recent_files=$(find "$path" -type f -mtime -1 -executable 2>/dev/null | head -10)
        if [ ! -z "$recent_files" ]; then
            echo "Recent executable files in $path:"
            echo "$recent_files"
        fi
    fi
done

# Check system integrity
echo "5. System integrity check..."
# Check for modified system binaries
which debsums &>/dev/null && debsums -c | head -10
which rpm &>/dev/null && rpm -Va | grep "^..5" | head -10

# Monitor Docker daemon if present
if command -v docker &>/dev/null; then
    echo "6. Docker security check..."
    # Check for privileged containers
    privileged=$(docker ps --filter "label=security.docker.privileged=true" -q)
    if [ ! -z "$privileged" ]; then
        echo "  Privileged containers running: $privileged"
    fi
    
    # Check for containers with host mounts
    docker ps --format "table {{.Names}}\t{{.Mounts}}" | grep -E "(\/:|\/proc|\/sys)" && echo "  Containers with sensitive host mounts"
fi

# Check for rootkits
if command -v rkhunter &>/dev/null; then
    echo "7. Rootkit scan..."
    rkhunter --check --sk --rwo 2>/dev/null | tail -20
fi
EOF

# Automated build agent hardening
cat > harden-build-agent.sh << 'EOF'
#!/bin/bash
echo " Build Agent Hardening "

# Update system
echo "1. Updating system packages..."
if command -v apt-get &>/dev/null; then
    apt-get update && apt-get upgrade -y
    apt-get install -y fail2ban rkhunter chkrootkit auditd
elif command -v yum &>/dev/null; then
    yum update -y
    yum install -y fail2ban rkhunter chkrootkit audit
fi

# Configure fail2ban
echo "2. Configuring fail2ban..."
cat > /etc/fail2ban/jail.local << F2B_CONFIG
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
ignoreip = 127.0.0.1/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3
F2B_CONFIG

systemctl enable fail2ban
systemctl start fail2ban

# Disable unnecessary services
echo "3. Disabling unnecessary services..."
UNNECESSARY_SERVICES=("telnet" "rsh" "rcp" "rlogin" "ypbind" "ypserv" "tftp" "finger")
for service in "${UNNECESSARY_SERVICES[@]}"; do
    systemctl disable "$service" 2>/dev/null || true
    systemctl stop "$service" 2>/dev/null || true
done

# Configure SSH hardening
echo "4. Hardening SSH..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
cat >> /etc/ssh/sshd_config << SSH_CONFIG
Protocol 2
PermitRootLogin no
MaxAuthTries 3
MaxSessions 2
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
PasswordAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication yes
X11Forwarding no
UsePAM yes
SSH_CONFIG

systemctl restart ssh

# Configure file system permissions
echo "5. Setting secure file permissions..."
chmod 700 /root
chmod 644 /etc/passwd
chmod 644 /etc/group
chmod 000 /etc/shadow
chmod 000 /etc/gshadow

# Install and configure auditd
echo "6. Configuring system auditing..."
cat >> /etc/audit/rules.d/audit.rules << AUDIT_RULES
# Monitor authentication events
-w /var/log/auth.log -p wa -k authentication
-w /etc/passwd -p wa -k passwd_changes
-w /etc/group -p wa -k group_changes
-w /etc/shadow -p wa -k shadow_changes

# Monitor system calls
-a always,exit -F arch=b64 -S execve -k process_execution
-a always,exit -F arch=b32 -S execve -k process_execution

# Monitor file access
-w /etc/sudoers -p wa -k sudoers_changes
-w /var/log/sudo.log -p wa -k sudo_log

# Monitor network configuration
-w /etc/hosts -p wa -k network_config
-w /etc/network/ -p wa -k network_config
AUDIT_RULES

systemctl enable auditd
systemctl start auditd

# Set up intrusion detection
echo "7. Setting up intrusion detection..."
rkhunter --update
rkhunter --propupd

# Create daily security check cron job
cat > /etc/cron.daily/security-check << SECURITY_CHECK
#!/bin/bash
# Daily security check for build agents

LOG_FILE="/var/log/security-check.log"
echo "$(date): Starting daily security check" >> $LOG_FILE

# Run rootkit check
rkhunter --check --sk --rwo >> $LOG_FILE 2>&1

# Check for new listening services
netstat -tulpn | grep LISTEN > /tmp/listening_ports
if [ -f /var/log/last_listening_ports ]; then
    diff /var/log/last_listening_ports /tmp/listening_ports > /tmp/port_changes
    if [ -s /tmp/port_changes ]; then
        echo "$(date): WARNING - Listening ports changed:" >> $LOG_FILE
        cat /tmp/port_changes >> $LOG_FILE
    fi
fi
mv /tmp/listening_ports /var/log/last_listening_ports

# Check for new users
getent passwd | cut -d: -f1 | sort > /tmp/current_users
if [ -f /var/log/last_users ]; then
    diff /var/log/last_users /tmp/current_users > /tmp/user_changes
    if [ -s /tmp/user_changes ]; then
        echo "$(date): WARNING - User accounts changed:" >> $LOG_FILE
        cat /tmp/user_changes >> $LOG_FILE
    fi
fi
mv /tmp/current_users /var/log/last_users

echo "$(date): Security check completed" >> $LOG_FILE
SECURITY_CHECK

chmod +x /etc/cron.daily/security-check

echo " Build agent hardening completed"
echo " Daily security checks configured"
echo " Check /var/log/security-check.log for ongoing monitoring"
EOF

chmod +x monitor-build-agents.sh harden-build-agent.sh
```

## Incident Response

### Pipeline Security Breach Response

#### Emergency response to compromised CI/CD pipeline

```bash
# Emergency pipeline security response
cat > pipeline-emergency-response.sh << 'EOF'
#!/bin/bash
PIPELINE_NAME=${1}
PLATFORM=${2:-"github"}  # github, jenkins, azure, gitlab
INCIDENT_ID=${3:-"incident-$(date +%Y%m%d-%H%M%S)"}

if [ -z "$PIPELINE_NAME" ]; then
    echo "Usage: $0 <pipeline-name> [platform] [incident-id]"
    echo "Platforms: github, jenkins, azure, gitlab"
    exit 1
fi

echo " CI/CD PIPELINE SECURITY INCIDENT RESPONSE "
echo "Pipeline: $PIPELINE_NAME"
echo "Platform: $PLATFORM"
echo "Incident ID: $INCIDENT_ID"
echo "Time: $(date)"

# Create incident directory
INCIDENT_DIR="incidents/$INCIDENT_ID"
mkdir -p $INCIDENT_DIR

# Step 1: Immediate containment
echo "Step 1: Immediate containment..."
case $PLATFORM in
    "github")
        echo "1a. Disabling GitHub Actions workflow..."
        # This would need GitHub CLI or API calls
        echo "Run: gh workflow disable \"$PIPELINE_NAME\""
        
        echo "1b. Checking recent workflow runs..."
        echo "Run: gh run list --workflow=\"$PIPELINE_NAME\" --limit=10"
        ;;
        
    "jenkins")
        echo "1a. Disabling Jenkins job..."
        curl -X POST "http://jenkins:8080/job/$PIPELINE_NAME/disable" --user admin:token
        
        echo "1b. Stopping running builds..."
        curl -X POST "http://jenkins:8080/job/$PIPELINE_NAME/lastBuild/stop" --user admin:token
        ;;
        
    "azure")
        echo "1a. Disabling Azure DevOps pipeline..."
        echo "Run: az pipelines update --name \"$PIPELINE_NAME\" --status disabled"
        ;;
        
    "gitlab")
        echo "1a. Disabling GitLab pipeline..."
        # GitLab API call would go here
        echo "Manual: Disable pipeline in GitLab UI"
        ;;
esac

# Step 2: Evidence collection
echo "Step 2: Collecting evidence..."

# Pipeline configuration
echo "2a. Backing up pipeline configuration..."
case $PLATFORM in
    "github")
        cp .github/workflows/* $INCIDENT_DIR/ 2>/dev/null || true
        ;;
    "jenkins")
        curl -s "http://jenkins:8080/job/$PIPELINE_NAME/config.xml" --user admin:token > $INCIDENT_DIR/pipeline-config.xml
        ;;
    *)
        echo "Manual: Export pipeline configuration to $INCIDENT_DIR/"
        ;;
esac

# Recent builds/runs
echo "2b. Collecting recent build history..."
case $PLATFORM in
    "github")
        gh run list --workflow="$PIPELINE_NAME" --limit=50 --json status,conclusion,createdAt,headSha > $INCIDENT_DIR/recent-runs.json
        ;;
    "jenkins")
        curl -s "http://jenkins:8080/job/$PIPELINE_NAME/api/json?tree=builds[number,result,timestamp,url]" --user admin:token > $INCIDENT_DIR/recent-builds.json
        ;;
esac

# Build logs for suspicious runs
echo "2c. Collecting suspicious build logs..."
echo "Manual: Download logs for recent failed or suspicious builds to $INCIDENT_DIR/logs/"

# Step 3: Analysis
echo "Step 3: Analyzing potential compromise indicators..."

# Check for suspicious changes in git history
echo "3a. Checking git history for suspicious changes..."
git log --oneline -n 50 --grep="password\|secret\|key" > $INCIDENT_DIR/suspicious-commits.txt
git log --oneline -n 50 --author=".*@.*\..*" | grep -vE "@(company\.com|github\.com)" > $INCIDENT_DIR/external-authors.txt

# Check for unusual file modifications
echo "3b. Checking for unusual file modifications..."
find . -name "*.yml" -o -name "*.yaml" -o -name "Jenkinsfile*" -o -name "*.sh" | xargs ls -la > $INCIDENT_DIR/pipeline-files.txt

# Look for indicators of compromise in pipeline files
echo "3c. Scanning for IoCs in pipeline configurations..."
MALICIOUS_PATTERNS=(
    "curl.*http://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"
    "wget.*http://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"
    "base64.*decode"
    "eval.*\$\("
    "python.*-c.*import"
    "powershell.*-enc"
    "certutil.*-decode"
)

for pattern in "${MALICIOUS_PATTERNS[@]}"; do
    echo "Checking for pattern: $pattern"
    find . -name "*.yml" -o -name "*.yaml" -o -name "Jenkinsfile*" | xargs grep -l "$pattern" >> $INCIDENT_DIR/suspicious-patterns.txt 2>/dev/null || true
done

# Step 4: Check for lateral movement
echo "Step 4: Checking for lateral movement..."

# Check deployed applications
echo "4a. Checking deployed applications for compromise..."
if command -v kubectl &>/dev/null; then
    kubectl get pods --all-namespaces -o json > $INCIDENT_DIR/kubernetes-pods.json
fi

if command -v docker &>/dev/null; then
    docker images --format "table {{.Repository}}:{{.Tag}}\t{{.CreatedAt}}\t{{.Size}}" > $INCIDENT_DIR/docker-images.txt
fi

# Check cloud resources if applicable
echo "4b. Checking cloud resources..."
if command -v aws &>/dev/null; then
    aws ec2 describe-instances --query 'Reservations[].Instances[?State.Name==`running`].[InstanceId,LaunchTime,InstanceType]' --output table > $INCIDENT_DIR/aws-instances.txt 2>/dev/null || true
fi

# Step 5: Secure the environment
echo "Step 5: Securing the environment..."

# Rotate credentials
echo "5a. Rotating potentially compromised credentials..."
cat > $INCIDENT_DIR/credentials-to-rotate.md << CREDS
# Credentials to Rotate Immediately

## Pipeline Secrets
- [ ] Registry credentials
- [ ] Cloud provider access keys  
- [ ] Database passwords
- [ ] API keys
- [ ] SSH keys used by pipeline

## Service Accounts
- [ ] Pipeline service accounts
- [ ] Deployment service accounts
- [ ] Registry service accounts

## Access Tokens
- [ ] GitHub/GitLab tokens
- [ ] Jenkins API tokens
- [ ] Cloud provider tokens

## Next Steps
1. Generate new credentials
2. Update secret stores
3. Update pipeline configurations
4. Test pipeline functionality
5. Monitor for further compromise
CREDS

# Check for backdoors
echo "5b. Checking for potential backdoors..."
cat > $INCIDENT_DIR/backdoor-check.sh << 'BACKDOOR_CHECK'
#!/bin/bash
echo "=== Backdoor Detection ==="

# Check for scheduled tasks/cron jobs
echo "Checking cron jobs..."
crontab -l 2>/dev/null && echo "User cron jobs found" || echo "No user cron jobs"
ls -la /etc/cron* 2>/dev/null

# Check for unusual startup scripts
echo "Checking startup scripts..."
find /etc/init.d /etc/systemd/system -name "*" -type f -mtime -30 2>/dev/null

# Check for SSH authorized keys
echo "Checking SSH authorized keys..."
find /home /root -name authorized_keys -type f -exec ls -la {} \; 2>/dev/null

# Check for suspicious network listeners
echo "Checking network listeners..."
netstat -tlnp | grep -vE ":(22|80|443|8080|9000)\\s"

# Check for unusual sudo rules
echo "Checking sudo rules..."
ls -la /etc/sudoers.d/ 2>/dev/null
BACKDOOR_CHECK

chmod +x $INCIDENT_DIR/backdoor-check.sh

# Step 6: Generate incident report
echo "Step 6: Generating incident report..."
cat > $INCIDENT_DIR/incident-report.md << REPORT
# CI/CD Pipeline Security Incident Report

**Incident ID:** $INCIDENT_ID
**Date:** $(date)
**Pipeline:** $PIPELINE_NAME
**Platform:** $PLATFORM
**Handler:** $(whoami)

## Incident Summary
- CI/CD pipeline security incident detected
- Pipeline disabled and contained
- Evidence collection in progress

## Timeline
- $(date): Incident detected and response initiated
- $(date): Pipeline disabled and evidence collection started

## Actions Taken
- [x] Pipeline disabled immediately
- [x] Configuration backed up
- [x] Recent build history collected
- [x] Git history analyzed for suspicious changes
- [x] Compromise indicators searched
- [x] Lateral movement assessment initiated

## Evidence Collected
- Pipeline configuration: stored in incident directory
- Recent builds: $(ls $INCIDENT_DIR/*builds* $INCIDENT_DIR/*runs* 2>/dev/null | wc -l) files
- Git analysis: suspicious-commits.txt, external-authors.txt
- IoC scanning: suspicious-patterns.txt
- System snapshots: various system state files

## Initial Findings
- Suspicious commits: $(cat $INCIDENT_DIR/suspicious-commits.txt 2>/dev/null | wc -l) found
- External authors: $(cat $INCIDENT_DIR/external-authors.txt 2>/dev/null | wc -l) found
- Suspicious patterns: $(cat $INCIDENT_DIR/suspicious-patterns.txt 2>/dev/null | wc -l) found

## Immediate Actions Required
1. [ ] Rotate all credentials used by the pipeline
2. [ ] Review and approve all recent pipeline changes
3. [ ] Scan deployed applications for compromise
4. [ ] Update pipeline security policies
5. [ ] Implement additional monitoring

## Evidence Location
All evidence stored in: $INCIDENT_DIR/

## Next Steps
1. Complete credential rotation
2. Forensic analysis of collected evidence
3. Determine attack vector and scope
4. Update security controls and monitoring
5. Communication plan for stakeholders

REPORT

echo " INCIDENT RESPONSE COMPLETE "
echo " Evidence directory: $INCIDENT_DIR"
echo " Incident report: $INCIDENT_DIR/incident-report.md"
echo " Next: Complete credential rotation and forensic analysis"
echo "  Pipeline remains disabled until investigation complete"

# Optional: Send notification
if command -v slack &>/dev/null; then
    slack send " CI/CD Security Incident $INCIDENT_ID - Pipeline '$PIPELINE_NAME' disabled and under investigation. Evidence: $INCIDENT_DIR/"
fi
EOF

chmod +x pipeline-emergency-response.sh
```

This CI/CD pipeline security guide provides troubleshooting for the most critical pipeline security issues that can lead to supply chain compromises, credential theft, and production system breaches. The emergency response procedures ensure quick containment while preserving forensic evidence for investigation.