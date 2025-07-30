# Container Registry Security Troubleshooting Guide

This guide helps you secure container registries, implement image signing and scanning, and troubleshoot registry-related security issues.

## Registry Access Control

### Issue: Unauthorized access to container registry

**Symptoms:**
- Unexpected image pushes or pulls
- Images being modified or deleted
- Unknown users accessing registry
- Privilege escalation through registry access

**Diagnosis:**
```bash
# Registry access control audit
cat > audit-registry-access.sh << 'EOF'
#!/bin/bash
echo " Container Registry Access Control Audit "

REGISTRY_TYPE=${1:-docker-hub}  # docker-hub, ecr, gcr, acr, harbor

case $REGISTRY_TYPE in
    "docker-hub")
        echo "1. Docker Hub Access Analysis:"
        echo "  Current Docker login status:"
        docker info | grep -A 5 "Registry:"
        
        # Check for stored credentials
        if [ -f ~/.docker/config.json ]; then
            echo "  Stored credentials found:"
            jq -r '.auths | keys[]' ~/.docker/config.json 2>/dev/null || echo "  No credentials stored"
        fi
        ;;
        
    "ecr")
        echo "1. AWS ECR Access Analysis:"
        echo "  Current AWS credentials:"
        aws sts get-caller-identity 2>/dev/null || echo "  No AWS credentials configured"
        
        echo "  ECR repositories:"
        aws ecr describe-repositories --query 'repositories[].repositoryName' --output table 2>/dev/null || echo "  Cannot access ECR repositories"
        
        # Check repository policies
        echo "  Repository policies:"
        aws ecr describe-repositories --query 'repositories[].repositoryName' --output text 2>/dev/null | while read repo; do
            if [ -n "$repo" ]; then
                echo "    Repository: $repo"
                aws ecr get-repository-policy --repository-name "$repo" --query 'policyText' --output text 2>/dev/null | jq . 2>/dev/null || echo "      No custom policy"
            fi
        done
        ;;
        
    "gcr")
        echo "1. Google Container Registry Access Analysis:"
        echo "  Current GCP credentials:"
        gcloud auth list 2>/dev/null | head -5 || echo "  No GCP credentials configured"
        
        echo "  GCR repositories:"
        gcloud container images list --limit=10 2>/dev/null || echo "  Cannot access GCR repositories"
        ;;
        
    "harbor")
        echo "1. Harbor Registry Access Analysis:"
        echo "  Harbor configuration check needed manually"
        echo "  Check: Harbor UI > Administration > Users & Projects"
        ;;
        
    *)
        echo "Unknown registry type: $REGISTRY_TYPE"
        exit 1
        ;;
esac

# Generic registry security checks
echo "2. Generic Registry Security Checks:"

# Check for insecure registries
echo "  Docker daemon insecure registries:"
docker info 2>/dev/null | grep -A 5 "Insecure Registries" || echo "  No insecure registries configured"

# Check for registry mirrors
echo "  Registry mirrors:"
docker info 2>/dev/null | grep -A 5 "Registry Mirrors" || echo "  No registry mirrors configured"

# Check running containers for registry sources
echo "3. Container Image Source Analysis:"
docker ps --format "table {{.Names}}\t{{.Image}}" | while read name image; do
    if [ "$name" != "NAMES" ]; then
        # Extract registry from image name
        registry=$(echo "$image" | cut -d'/' -f1)
        if [[ "$registry" == *"."* ]]; then
            echo "  Container $name uses registry: $registry"
        fi
    fi
done

# Check for credential helpers
echo "4. Docker Credential Helpers:"
docker-credential-helpers 2>/dev/null || echo "  No credential helpers installed"

if [ -f ~/.docker/config.json ]; then
    echo "  Configured credential helpers:"
    jq -r '.credHelpers // {} | keys[]' ~/.docker/config.json 2>/dev/null || echo "  None configured"
fi

echo "Registry access audit complete"
EOF

chmod +x audit-registry-access.sh
./audit-registry-access.sh ecr
```

**Solution:**
```bash
# Secure registry access configuration
cat > secure-registry-access.sh << 'EOF'
#!/bin/bash
echo "=== Securing Container Registry Access ==="

REGISTRY_TYPE=${1:-ecr}
ACTION=${2:-configure}

case $REGISTRY_TYPE in
    "ecr")
        echo "Securing AWS ECR access..."
        
        if [ "$ACTION" = "configure" ]; then
            # Create ECR repository with secure settings
            REPO_NAME=${3:-secure-app}
            
            echo "1. Creating secure ECR repository: $REPO_NAME"
            aws ecr create-repository --repository-name "$REPO_NAME" --image-scanning-configuration scanOnPush=true
            
            # Set lifecycle policy
            echo "2. Setting lifecycle policy..."
            cat > lifecycle-policy.json << LIFECYCLE
{
    "rules": [
        {
            "rulePriority": 1,
            "selection": {
                "tagStatus": "untagged",
                "countType": "sinceImagePushed",
                "countUnit": "days",
                "countNumber": 7
            },
            "action": {
                "type": "expire"
            }
        },
        {
            "rulePriority": 2,
            "selection": {
                "tagStatus": "tagged",
                "countType": "imageCountMoreThan",
                "countNumber": 10
            },
            "action": {
                "type": "expire"
            }
        }
    ]
}
LIFECYCLE

            aws ecr put-lifecycle-policy --repository-name "$REPO_NAME" --lifecycle-policy-text file://lifecycle-policy.json
            
            # Set repository policy for least privilege
            echo "3. Setting repository access policy..."
            ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
            
            cat > repository-policy.json << REPO_POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowPull",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::${ACCOUNT_ID}:role/EKS-*"
            },
            "Action": [
                "ecr:BatchGetImage",
                "ecr:GetDownloadUrlForLayer"
            ]
        },
        {
            "Sid": "AllowPushFromCI",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::${ACCOUNT_ID}:role/CI-ECR-Role"
            },
            "Action": [
                "ecr:BatchCheckLayerAvailability",
                "ecr:PutImage",
                "ecr:InitiateLayerUpload",
                "ecr:UploadLayerPart",
                "ecr:CompleteLayerUpload"
            ]
        }
    ]
}
REPO_POLICY

            aws ecr set-repository-policy --repository-name "$REPO_NAME" --policy-text file://repository-policy.json
            
            # Clean up temp files
            rm lifecycle-policy.json repository-policy.json
            
            echo " ECR repository $REPO_NAME configured securely"
        fi
        ;;
        
    "docker-registry")
        echo "Configuring secure Docker Registry..."
        
        # Create registry with TLS and authentication
        echo "1. Creating secure Docker Registry configuration..."
        mkdir -p registry/{auth,certs,data}
        
        # Generate TLS certificates
        echo "2. Generating TLS certificates..."
        openssl req -newkey rsa:4096 -nodes -sha256 -keyout registry/certs/domain.key -x509 -days 365 -out registry/certs/domain.crt -subj "/CN=registry.local"
        
        # Create htpasswd authentication
        echo "3. Setting up authentication..."
        docker run --rm --entrypoint htpasswd httpd:2 -Bbn registry $(openssl rand -base64 12) > registry/auth/htpasswd
        
        # Create secure registry configuration
        cat > registry/config.yml << REGISTRY_CONFIG
version: 0.1
log:
  fields:
    service: registry
  level: info
storage:
  filesystem:
    rootdirectory: /var/lib/registry
  delete:
    enabled: false
http:
  addr: :5000
  headers:
    X-Content-Type-Options: [nosniff]
    X-Frame-Options: [deny]
    X-Content-Type-Options: [nosniff]
  tls:
    certificate: /certs/domain.crt
    key: /certs/domain.key
auth:
  htpasswd:
    realm: basic-realm
    path: /auth/htpasswd
health:
  storagedriver:
    enabled: true
    interval: 10s
    threshold: 3
REGISTRY_CONFIG

        # Create Docker Compose for secure registry
        cat > docker-compose.yml << COMPOSE
version: '3.8'
services:
  registry:
    image: registry:2.8
    container_name: secure-registry
    restart: unless-stopped
    ports:
      - "5000:5000"
    volumes:
      - ./registry/data:/var/lib/registry
      - ./registry/certs:/certs
      - ./registry/auth:/auth
      - ./registry/config.yml:/etc/docker/registry/config.yml
    environment:
      - REGISTRY_HTTP_TLS_CERTIFICATE=/certs/domain.crt
      - REGISTRY_HTTP_TLS_KEY=/certs/domain.key
      - REGISTRY_AUTH_HTPASSWD_REALM=Registry Realm
      - REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd
    networks:
      - registry-network
      
networks:
  registry-network:
    driver: bridge
COMPOSE

        echo " Secure Docker Registry configured"
        echo "Start with: docker-compose up -d"
        ;;
        
    "harbor")
        echo "Configuring Harbor Registry security..."
        echo "1. Download Harbor installer"
        echo "2. Edit harbor.yml configuration"
        echo "3. Enable HTTPS and authentication"
        echo "4. Configure RBAC policies"
        echo "5. Enable vulnerability scanning"
        
        # Harbor configuration template
        cat > harbor-security-config.yml << HARBOR_CONFIG
# Harbor Security Configuration Template
hostname: registry.yourdomain.com

# HTTPS configuration
https:
  port: 443
  certificate: /your/certificate/path/server.crt
  private_key: /your/private/key/path/server.key

# Harbor admin password (change this!)
harbor_admin_password: ChangeMePlease123!

# Database settings
database:
  password: ChangeMePlease123!
  max_idle_conns: 100
  max_open_conns: 900

# Data volume
data_volume: /data

# Trivy configuration for vulnerability scanning
trivy:
  ignore_unfixed: false
  skip_update: false
  insecure: false

# Jobservice configuration
jobservice:
  max_job_workers: 10

# Notification settings
notification:
  webhook_job_max_retry: 10

# Log settings
log:
  level: info
  local:
    rotate_count: 50
    rotate_size: 200M
    location: /var/log/harbor

# Proxy settings for corporate environments
# proxy:
#   http_proxy:
#   https_proxy:
#   no_proxy:
#   components:
#     - core
#     - jobservice
#     - trivy

HARBOR_CONFIG

        echo " Harbor security configuration template created"
        echo "Edit harbor-security-config.yml and install Harbor"
        ;;
esac

echo "Registry access security configuration complete"
EOF

chmod +x secure-registry-access.sh
```

## Image Vulnerability Scanning

### Issue: Vulnerable container images in registry

**Symptoms:**
- Images with known CVEs being deployed
- No visibility into image vulnerabilities
- Security scanners reporting issues
- Compliance violations

**Diagnosis:**
```bash
# Container image vulnerability scanning
cat > scan-container-vulnerabilities.sh << 'EOF'
#!/bin/bash
echo "=== Container Image Vulnerability Scanning ==="

SCAN_TYPE=${1:-registry}  # registry, local, running
TARGET=${2:-}

# Install scanning tools if not present
install_scanning_tools() {
    echo "1. Installing scanning tools..."
    
    # Install Trivy
    if ! command -v trivy &> /dev/null; then
        echo "Installing Trivy..."
        curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
    fi
    
    # Install Grype
    if ! command -v grype &> /dev/null; then
        echo "Installing Grype..."
        curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
    fi
    
    echo " Scanning tools installed"
}

scan_local_images() {
    echo "2. Scanning local Docker images..."
    
    # Get all local images
    docker images --format "table {{.Repository}}:{{.Tag}}" | grep -v REPOSITORY | while read image; do
        if [ "$image" != "<none>:<none>" ]; then
            echo "Scanning image: $image"
            
            # Trivy scan
            trivy image --format json --output "trivy-${image//[\/:]/_}.json" "$image" 2>/dev/null
            
            # Grype scan
            grype "$image" -o json --file "grype-${image//[\/:]/_}.json" 2>/dev/null
            
            # Quick summary
            echo "  Trivy results:"
            trivy image --format table --severity HIGH,CRITICAL "$image" 2>/dev/null | grep -E "CRITICAL|HIGH" | wc -l | awk '{print "    Critical/High vulnerabilities: " $1}'
            
            echo "  Grype results:"
            grype "$image" -o table 2>/dev/null | grep -E "Critical|High" | wc -l | awk '{print "    Critical/High vulnerabilities: " $1}'
            echo ""
        fi
    done
}

scan_running_containers() {
    echo "3. Scanning running containers..."
    
    docker ps --format "{{.Names}} {{.Image}}" | while read container image; do
        echo "Scanning running container: $container ($image)"
        
        # Scan the container filesystem
        trivy image --format table --severity HIGH,CRITICAL "$image" 2>/dev/null | head -20
        
        # Check for running processes with vulnerabilities
        docker exec "$container" ps aux 2>/dev/null | head -10 || echo "Cannot access container processes"
        echo ""
    done
}

scan_registry_images() {
    echo "4. Scanning registry images..."
    
    # AWS ECR example
    if command -v aws &> /dev/null; then
        echo "Scanning AWS ECR repositories..."
        
        aws ecr describe-repositories --query 'repositories[].repositoryName' --output text | while read repo; do
            if [ -n "$repo" ]; then
                echo "Repository: $repo"
                
                # Get image scan results
                aws ecr describe-image-scan-findings --repository-name "$repo" --query 'imageScanFindings.findings[?severity==`HIGH` || severity==`CRITICAL`].[name,severity,description]' --output table 2>/dev/null || echo "No scan results available"
                
                # Start scan if not already scanning
                aws ecr start-image-scan --repository-name "$repo" --image-id imageTag=latest 2>/dev/null || true
            fi
        done
    fi
    
    # Docker Hub scanning (using local pull and scan)
    if [ -n "$TARGET" ]; then
        echo "Scanning Docker Hub image: $TARGET"
        docker pull "$TARGET" 2>/dev/null
        trivy image --format table --severity HIGH,CRITICAL "$TARGET" 2>/dev/null
    fi
}

generate_vulnerability_report() {
    echo "5. Generating vulnerability report..."
    
    cat > vulnerability-report.html << HTML_REPORT
<!DOCTYPE html>
<html>
<head>
    <title>Container Vulnerability Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .critical { color: #d32f2f; font-weight: bold; }
        .high { color: #f57c00; font-weight: bold; }
        .medium { color: #1976d2; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Container Vulnerability Report</h1>
    <p>Generated on: $(date)</p>
    
    <h2>Summary</h2>
    <table>
        <tr><th>Severity</th><th>Count</th></tr>
HTML_REPORT

    # Count vulnerabilities from Trivy results
    CRITICAL_COUNT=$(find . -name "trivy-*.json" -exec jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL") | .VulnerabilityID' {} \; 2>/dev/null | wc -l)
    HIGH_COUNT=$(find . -name "trivy-*.json" -exec jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH") | .VulnerabilityID' {} \; 2>/dev/null | wc -l)
    
    cat >> vulnerability-report.html << HTML_REPORT2
        <tr><td class="critical">Critical</td><td>$CRITICAL_COUNT</td></tr>
        <tr><td class="high">High</td><td>$HIGH_COUNT</td></tr>
    </table>
    
    <h2>Detailed Findings</h2>
    <p>Detailed vulnerability data available in JSON files: trivy-*.json, grype-*.json</p>
    
    <h2>Recommendations</h2>
    <ul>
        <li>Update base images to latest versions</li>
        <li>Remove unnecessary packages from images</li>
        <li>Implement automated vulnerability scanning in CI/CD</li>
        <li>Set up vulnerability monitoring and alerting</li>
        <li>Use distroless or minimal base images when possible</li>
    </ul>
</body>
</html>
HTML_REPORT2

    echo " Vulnerability report generated: vulnerability-report.html"
}

# Main execution
install_scanning_tools

case $SCAN_TYPE in
    "local")
        scan_local_images
        ;;
    "running")
        scan_running_containers
        ;;
    "registry")
        scan_registry_images
        ;;
    "all")
        scan_local_images
        scan_running_containers
        scan_registry_images
        ;;
    *)
        echo "Usage: $0 {local|running|registry|all} [target-image]"
        exit 1
        ;;
esac

generate_vulnerability_report

echo "Container vulnerability scanning complete"
echo "Review JSON files for detailed results"
EOF

chmod +x scan-container-vulnerabilities.sh
```

## Image Signing and Verification

### Issue: Unsigned or tampered container images

**Symptoms:**
- No cryptographic verification of images
- Images potentially modified in transit
- Supply chain attack concerns
- Compliance requirements not met

**Solution:**
```bash
# Container image signing and verification
cat > setup-image-signing.sh << 'EOF'
#!/bin/bash
echo "=== Container Image Signing and Verification Setup ==="

SIGNING_METHOD=${1:-cosign}  # cosign, notary
REGISTRY=${2:-}

setup_cosign() {
    echo "1. Setting up Cosign for image signing..."
    
    # Install Cosign
    if ! command -v cosign &> /dev/null; then
        echo "Installing Cosign..."
        COSIGN_VERSION=$(curl -s https://api.github.com/repos/sigstore/cosign/releases/latest | jq -r '.tag_name')
        curl -O -L "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64"
        mv cosign-linux-amd64 /usr/local/bin/cosign
        chmod +x /usr/local/bin/cosign
    fi
    
    # Generate key pair
    echo "2. Generating Cosign key pair..."
    if [ ! -f cosign.key ]; then
        cosign generate-key-pair
        echo " Cosign key pair generated"
        echo " Private key: cosign.key (keep secure!)"
        echo " Public key: cosign.pub (distribute for verification)"
    fi
    
    # Create signing script
    cat > sign-image.sh << SIGN_SCRIPT
#!/bin/bash
IMAGE=\$1
if [ -z "\$IMAGE" ]; then
    echo "Usage: \$0 <image-name:tag>"
    exit 1
fi

echo "Signing image: \$IMAGE"

# Sign the image
cosign sign --key cosign.key "\$IMAGE"

echo "Image signed successfully"
echo "Verification command: cosign verify --key cosign.pub \$IMAGE"
SIGN_SCRIPT

    chmod +x sign-image.sh
    
    # Create verification script
    cat > verify-image.sh << VERIFY_SCRIPT
#!/bin/bash
IMAGE=\$1
if [ -z "\$IMAGE" ]; then
    echo "Usage: \$0 <image-name:tag>"
    exit 1
fi

echo "Verifying image: \$IMAGE"

# Verify the image signature
if cosign verify --key cosign.pub "\$IMAGE"; then
    echo " Image signature is valid"
else
    echo " Image signature verification failed"
    exit 1
fi
VERIFY_SCRIPT

    chmod +x verify-image.sh
    
    echo " Cosign setup complete"
    echo "Usage:"
    echo "  Sign image: ./sign-image.sh your-registry/image:tag"
    echo "  Verify image: ./verify-image.sh your-registry/image:tag"
}

setup_notary() {
    echo "1. Setting up Docker Content Trust (Notary)..."
    
    # Enable Docker Content Trust
    export DOCKER_CONTENT_TRUST=1
    echo "export DOCKER_CONTENT_TRUST=1" >> ~/.bashrc
    
    # Create directory for trust metadata
    mkdir -p ~/.docker/trust
    
    # Generate root key (do this once)
    echo "2. Generating root key for Docker Content Trust..."
    if [ ! -f ~/.docker/trust/private/root_keys ]; then
        # This will be generated on first push with DCT enabled
        echo "Root key will be generated on first signed push"
    fi
    
    # Create script to push signed images
    cat > push-signed-image.sh << PUSH_SCRIPT
#!/bin/bash
IMAGE=\$1
if [ -z "\$IMAGE" ]; then
    echo "Usage: \$0 <image-name:tag>"
    exit 1
fi

echo "Pushing signed image: \$IMAGE"

# Enable Docker Content Trust
export DOCKER_CONTENT_TRUST=1

# Push the image (will automatically sign)
docker push "\$IMAGE"

echo "Image pushed and signed successfully"
PUSH_SCRIPT

    chmod +x push-signed-image.sh
    
    # Create verification script
    cat > pull-verify-image.sh << PULL_SCRIPT
#!/bin/bash
IMAGE=\$1
if [ -z "\$IMAGE" ]; then
    echo "Usage: \$0 <image-name:tag>"
    exit 1
fi

echo "Pulling and verifying image: \$IMAGE"

# Enable Docker Content Trust for verification
export DOCKER_CONTENT_TRUST=1

# Pull the image (will automatically verify)
if docker pull "\$IMAGE"; then
    echo " Image signature verified and image pulled"
else
    echo " Image signature verification failed or pull failed"
    exit 1
fi
PULL_SCRIPT

    chmod +x pull-verify-image.sh
    
    echo " Docker Content Trust setup complete"
    echo "Usage:"
    echo "  Push signed image: ./push-signed-image.sh your-registry/image:tag"
    echo "  Pull and verify: ./pull-verify-image.sh your-registry/image:tag"
}

setup_admission_controller() {
    echo "3. Setting up Kubernetes admission controller for signature verification..."
    
    # Create policy for signature verification
    cat > image-signature-policy.yaml << POLICY
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signatures
spec:
  validationFailureAction: enforce
  background: false
  rules:
  - name: verify-cosign-signature
    match:
      any:
      - resources:
          kinds:
          - Pod
    verifyImages:
    - image: "*"
      key: |-
        $(cat cosign.pub)
      annotations:
        dev.cosignproject.cosign/signature: cosign
POLICY

    echo "Kubernetes admission controller policy created: image-signature-policy.yaml"
    echo "Apply with: kubectl apply -f image-signature-policy.yaml"
    echo "(Requires Kyverno admission controller)"
}

create_ci_cd_integration() {
    echo "4. Creating CI/CD integration examples..."
    
    # GitHub Actions workflow
    cat > .github/workflows/sign-and-push.yml << GITHUB_WORKFLOW
name: Build, Sign, and Push Container Image

on:
  push:
    branches: [ main ]

jobs:
  build-and-sign:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@v2
    
    - name: Login to Registry
      uses: docker/login-action@v2
      with:
        registry: \${{ secrets.REGISTRY_URL }}
        username: \${{ secrets.REGISTRY_USERNAME }}
        password: \${{ secrets.REGISTRY_PASSWORD }}
    
    - name: Build and push
      uses: docker/build-push-action@v4
      with:
        context: .
        push: true
        tags: \${{ secrets.REGISTRY_URL }}/\${{ github.repository }}:\${{ github.sha }}
    
    - name: Install Cosign
      uses: sigstore/cosign-installer@v3
    
    - name: Sign container image
      env:
        COSIGN_PRIVATE_KEY: \${{ secrets.COSIGN_PRIVATE_KEY }}
        COSIGN_PASSWORD: \${{ secrets.COSIGN_PASSWORD }}
      run: |
        cosign sign --key env://COSIGN_PRIVATE_KEY \${{ secrets.REGISTRY_URL }}/\${{ github.repository }}:\${{ github.sha }}
GITHUB_WORKFLOW

    # Jenkins pipeline
    cat > Jenkinsfile << JENKINS_PIPELINE
pipeline {
    agent any
    
    environment {
        REGISTRY = credentials('registry-url')
        REGISTRY_CREDS = credentials('registry-credentials')
        COSIGN_KEY = credentials('cosign-private-key')
        COSIGN_PASSWORD = credentials('cosign-password')
    }
    
    stages {
        stage('Build') {
            steps {
                script {
                    docker.build("\${REGISTRY}/\${env.JOB_NAME}:\${env.BUILD_NUMBER}")
                }
            }
        }
        
        stage('Push') {
            steps {
                script {
                    docker.withRegistry("https://\${REGISTRY}", 'registry-credentials') {
                        def image = docker.image("\${REGISTRY}/\${env.JOB_NAME}:\${env.BUILD_NUMBER}")
                        image.push()
                    }
                }
            }
        }
        
        stage('Sign') {
            steps {
                script {
                    sh """
                        echo "\${COSIGN_KEY}" > cosign.key
                        cosign sign --key cosign.key "\${REGISTRY}/\${env.JOB_NAME}:\${env.BUILD_NUMBER}"
                        rm cosign.key
                    """
                }
            }
        }
    }
}
JENKINS_PIPELINE

    echo " CI/CD integration examples created"
    echo "GitHub Actions: .github/workflows/sign-and-push.yml"
    echo "Jenkins Pipeline: Jenkinsfile"
}

# Main execution
case $SIGNING_METHOD in
    "cosign")
        setup_cosign
        ;;
    "notary"|"dct")
        setup_notary
        ;;
    "both")
        setup_cosign
        setup_notary
        ;;
    *)
        echo "Usage: $0 {cosign|notary|both} [registry-url]"
        exit 1
        ;;
esac

setup_admission_controller
create_ci_cd_integration

echo ""
echo " Container image signing setup complete"
echo ""
echo "Next steps:"
echo "1. Distribute public keys to teams for verification"
echo "2. Integrate signing into CI/CD pipelines"
echo "3. Configure admission controllers in Kubernetes"
echo "4. Train teams on signature verification processes"
echo "5. Monitor for unsigned images in production"
EOF

chmod +x setup-image-signing.sh
```

## Registry Monitoring and Auditing

### Registry security monitoring and audit logging

**Solution:**
```bash
# Registry monitoring and auditing setup
cat > setup-registry-monitoring.sh << 'EOF'
#!/bin/bash
echo "=== Container Registry Monitoring and Auditing Setup ==="

REGISTRY_TYPE=${1:-harbor}  # harbor, ecr, gcr, acr

setup_harbor_monitoring() {
    echo "1. Setting up Harbor registry monitoring..."
    
    # Create Harbor audit log analysis script
    cat > analyze-harbor-logs.sh << HARBOR_AUDIT
#!/bin/bash
echo "Harbor Registry Audit Analysis"

HARBOR_LOG_DIR="/var/log/harbor"
AUDIT_OUTPUT="harbor-audit-$(date +%Y%m%d).txt"

echo "Harbor Registry Security Audit - $(date)" > \$AUDIT_OUTPUT
echo "==========================================" >> \$AUDIT_OUTPUT

# Analyze core service logs
if [ -d "\$HARBOR_LOG_DIR" ]; then
    echo "Analyzing Harbor logs in \$HARBOR_LOG_DIR..."
    
    # Failed login attempts
    echo "Failed Login Attempts:" >> \$AUDIT_OUTPUT
    grep -h "authentication failed" \$HARBOR_LOG_DIR/core.log* 2>/dev/null | tail -20 >> \$AUDIT_OUTPUT || echo "No failed login attempts found" >> \$AUDIT_OUTPUT
    
    # Image push/pull activities
    echo "" >> \$AUDIT_OUTPUT
    echo "Image Operations:" >> \$AUDIT_OUTPUT
    grep -h -E "(push|pull).*artifact" \$HARBOR_LOG_DIR/core.log* 2>/dev/null | tail -20 >> \$AUDIT_OUTPUT || echo "No image operations found" >> \$AUDIT_OUTPUT
    
    # User management activities
    echo "" >> \$AUDIT_OUTPUT
    echo "User Management:" >> \$AUDIT_OUTPUT
    grep -h -E "(user.*create|user.*delete|user.*update)" \$HARBOR_LOG_DIR/core.log* 2>/dev/null | tail -10 >> \$AUDIT_OUTPUT || echo "No user management activities found" >> \$AUDIT_OUTPUT
    
    # Project activities
    echo "" >> \$AUDIT_OUTPUT
    echo "Project Management:" >> \$AUDIT_OUTPUT
    grep -h -E "(project.*create|project.*delete)" \$HARBOR_LOG_DIR/core.log* 2>/dev/null | tail -10 >> \$AUDIT_OUTPUT || echo "No project activities found" >> \$AUDIT_OUTPUT
    
    # Vulnerability scan results
    echo "" >> \$AUDIT_OUTPUT
    echo "Vulnerability Scans:" >> \$AUDIT_OUTPUT
    grep -h "scan.*complete" \$HARBOR_LOG_DIR/core.log* 2>/dev/null | tail -10 >> \$AUDIT_OUTPUT || echo "No vulnerability scans found" >> \$AUDIT_OUTPUT
    
else
    echo "Harbor log directory not found: \$HARBOR_LOG_DIR" >> \$AUDIT_OUTPUT
fi

echo "Audit analysis complete: \$AUDIT_OUTPUT"
HARBOR_AUDIT

    chmod +x analyze-harbor-logs.sh
    
    # Create Harbor metrics collection script
    cat > collect-harbor-metrics.sh << HARBOR_METRICS
#!/bin/bash
echo "Collecting Harbor Registry Metrics"

HARBOR_URL=\${1:-"https://harbor.local"}
HARBOR_USER=\${2:-"admin"}
HARBOR_PASS=\${3:-"Harbor12345"}

# Function to call Harbor API
harbor_api() {
    local endpoint=\$1
    curl -s -u "\$HARBOR_USER:\$HARBOR_PASS" "\$HARBOR_URL/api/v2.0\$endpoint" -H "Accept: application/json"
}

echo "Harbor Registry Metrics - $(date)"
echo "================================="

# System info
echo "1. System Information:"
harbor_api "/systeminfo" | jq -r '.storage[] | "Storage: \(.total / 1024 / 1024 / 1024 | round)GB total, \(.free / 1024 / 1024 / 1024 | round)GB free"' 2>/dev/null || echo "Could not retrieve system info"

# Project statistics
echo "2. Project Statistics:"
PROJECT_COUNT=\$(harbor_api "/projects" | jq '. | length' 2>/dev/null || echo "0")
echo "Total projects: \$PROJECT_COUNT"

# User statistics
echo "3. User Statistics:"
USER_COUNT=\$(harbor_api "/users" | jq '. | length' 2>/dev/null || echo "0")
echo "Total users: \$USER_COUNT"

# Repository statistics
echo "4. Repository Statistics:"
harbor_api "/projects" | jq -r '.[].name' 2>/dev/null | while read project; do
    if [ -n "\$project" ]; then
        REPO_COUNT=\$(harbor_api "/projects/\$project/repositories" | jq '. | length' 2>/dev/null || echo "0")
        echo "Project \$project: \$REPO_COUNT repositories"
    fi
done

# Recent activities
echo "5. Recent Activities (audit logs):"
harbor_api "/audit-logs?page=1&page_size=5" | jq -r '.[] | "\(.operation) by \(.username) at \(.op_time)"' 2>/dev/null || echo "Could not retrieve audit logs"

echo "Metrics collection complete"
HARBOR_METRICS

    chmod +x collect-harbor-metrics.sh
    
    echo " Harbor monitoring scripts created"
    echo "Usage: ./analyze-harbor-logs.sh"
    echo "Usage: ./collect-harbor-metrics.sh https://your-harbor.com admin password"
}

setup_ecr_monitoring() {
    echo "2. Setting up AWS ECR monitoring..."
    
    # ECR audit script
    cat > audit-ecr-usage.sh << ECR_AUDIT
#!/bin/bash
echo "AWS ECR Usage Audit"

AUDIT_OUTPUT="ecr-audit-$(date +%Y%m%d).txt"

echo "AWS ECR Security Audit - $(date)" > \$AUDIT_OUTPUT
echo "=================================" >> \$AUDIT_OUTPUT

# List all repositories
echo "ECR Repositories:" >> \$AUDIT_OUTPUT
aws ecr describe-repositories --query 'repositories[].[repositoryName,createdAt,imageScanningConfiguration.scanOnPush]' --output table >> \$AUDIT_OUTPUT 2>/dev/null

# Check image scan results
echo "" >> \$AUDIT_OUTPUT
echo "Image Vulnerability Scan Summary:" >> \$AUDIT_OUTPUT
aws ecr describe-repositories --query 'repositories[].repositoryName' --output text | while read repo; do
    if [ -n "\$repo" ]; then
        echo "Repository: \$repo" >> \$AUDIT_OUTPUT
        aws ecr describe-image-scan-findings --repository-name "\$repo" --query 'imageScanFindings.findingCounts' --output table >> \$AUDIT_OUTPUT 2>/dev/null || echo "No scan results available" >> \$AUDIT_OUTPUT
        echo "" >> \$AUDIT_OUTPUT
    fi
done

# Check repository policies
echo "Repository Policies:" >> \$AUDIT_OUTPUT
aws ecr describe-repositories --query 'repositories[].repositoryName' --output text | while read repo; do
    if [ -n "\$repo" ]; then
        echo "Repository: \$repo" >> \$AUDIT_OUTPUT
        aws ecr get-repository-policy --repository-name "\$repo" --query 'policyText' --output text 2>/dev/null | jq . >> \$AUDIT_OUTPUT 2>/dev/null || echo "No custom policy" >> \$AUDIT_OUTPUT
        echo "" >> \$AUDIT_OUTPUT
    fi
done

# CloudTrail events for ECR
echo "Recent ECR API Calls (last 24 hours):" >> \$AUDIT_OUTPUT
aws logs filter-log-events \
    --log-group-name CloudTrail-ECR \
    --start-time \$(date -d '24 hours ago' +%s)000 \
    --filter-pattern '{ \$.eventSource = "ecr.amazonaws.com" }' \
    --query 'events[].{Time:eventTime,User:userIdentity.type,Event:eventName,Source:sourceIPAddress}' \
    --output table >> \$AUDIT_OUTPUT 2>/dev/null || echo "CloudTrail logs not available or not configured" >> \$AUDIT_OUTPUT

echo "ECR audit complete: \$AUDIT_OUTPUT"
ECR_AUDIT

    chmod +x audit-ecr-usage.sh
    
    # ECR monitoring with CloudWatch
    cat > setup-ecr-cloudwatch.sh << ECR_CW
#!/bin/bash
echo "Setting up ECR CloudWatch monitoring"

# Create CloudWatch log group for ECR events
aws logs create-log-group --log-group-name /aws/ecr/events 2>/dev/null || echo "Log group already exists"

# Create EventBridge rule for ECR events
cat > ecr-event-rule.json << 'RULE'
{
    "Rules": [
        {
            "Name": "ECRImagePushEvents",
            "EventPattern": {
                "source": ["aws.ecr"],
                "detail-type": ["ECR Image Action"],
                "detail": {
                    "action-type": ["PUSH"],
                    "result": ["SUCCESS"]
                }
            },
            "State": "ENABLED",
            "Targets": [
                {
                    "Id": "1",
                    "Arn": "arn:aws:logs:us-east-1:\$(aws sts get-caller-identity --query Account --output text):log-group:/aws/ecr/events"
                }
            ]
        }
    ]
}
RULE

aws events put-rule --name ECRImagePushEvents --event-pattern file://ecr-event-rule.json --description "Monitor ECR image push events" 2>/dev/null

# Create CloudWatch alarm for unauthorized access
aws cloudwatch put-metric-alarm \
    --alarm-name "ECR-UnauthorizedAccess" \
    --alarm-description "Alarm for ECR unauthorized access attempts" \
    --metric-name "ErrorCount" \
    --namespace "AWS/ECR" \
    --statistic "Sum" \
    --period 300 \
    --threshold 5 \
    --comparison-operator "GreaterThanThreshold" \
    --evaluation-periods 1 2>/dev/null

echo " ECR CloudWatch monitoring configured"
ECR_CW

    chmod +x setup-ecr-cloudwatch.sh
    
    echo " ECR monitoring scripts created"
    echo "Usage: ./audit-ecr-usage.sh"
    echo "Usage: ./setup-ecr-cloudwatch.sh"
}

setup_registry_alerting() {
    echo "3. Setting up registry security alerting..."
    
    # Create alerting configuration
    cat > registry-alerting-config.yaml << ALERTING_CONFIG
# Registry Security Alerting Configuration
alerts:
  - name: "Vulnerable Image Pushed"
    condition: "vulnerability_scan.critical_count > 0"
    action: "block_deployment"
    notification:
      - slack: "#security-alerts"
      - email: "security-team@company.com"
    
  - name: "Unsigned Image Pushed"
    condition: "image_signature.verified == false"
    action: "quarantine"
    notification:
      - slack: "#security-alerts"
    
  - name: "Unusual Push Activity"
    condition: "push_rate > baseline * 3"
    action: "investigate"
    notification:
      - slack: "#devops-alerts"
    
  - name: "Failed Authentication Attempts"
    condition: "auth_failures > 10 in 5min"
    action: "alert"
    notification:
      - slack: "#security-alerts"
      - pagerduty: "security-escalation"

# Webhook configuration for external integrations
webhooks:
  security_webhook:
    url: "https://security-tools.company.com/webhook"
    auth:
      type: "bearer"
      token: "\${SECURITY_WEBHOOK_TOKEN}"
    events:
      - "vulnerability_found"
      - "unsigned_image"
      - "policy_violation"

# Integration with external security tools
integrations:
  siem:
    type: "splunk"
    endpoint: "https://splunk.company.com:8088/services/collector"
    token: "\${SPLUNK_TOKEN}"
    
  ticketing:
    type: "jira"
    url: "https://company.atlassian.net"
    project: "SEC"
    credentials:
      username: "\${JIRA_USER}"
      token: "\${JIRA_TOKEN}"
ALERTING_CONFIG

    echo " Registry alerting configuration created: registry-alerting-config.yaml"
    echo "Configure environment variables for tokens and credentials"
}

create_monitoring_dashboard() {
    echo "4. Creating monitoring dashboard..."
    
    # Grafana dashboard JSON
    cat > registry-security-dashboard.json << DASHBOARD
{
  "dashboard": {
    "title": "Container Registry Security Dashboard",
    "panels": [
      {
        "title": "Image Vulnerability Trends",
        "type": "graph",
        "targets": [
          {
            "query": "sum(rate(registry_vulnerability_scans_total[5m])) by (severity)"
          }
        ]
      },
      {
        "title": "Authentication Failures",
        "type": "stat",
        "targets": [
          {
            "query": "sum(rate(registry_auth_failures_total[5m]))"
          }
        ]
      },
      {
        "title": "Push/Pull Activities",
        "type": "graph",
        "targets": [
          {
            "query": "sum(rate(registry_operations_total[5m])) by (operation)"
          }
        ]
      },
      {
        "title": "Unsigned Images",
        "type": "table",
        "targets": [
          {
            "query": "registry_unsigned_images"
          }
        ]
      }
    ]
  }
}
DASHBOARD

    echo " Grafana dashboard configuration created: registry-security-dashboard.json"
    echo "Import this dashboard into your Grafana instance"
}

# Main execution
case $REGISTRY_TYPE in
    "harbor")
        setup_harbor_monitoring
        ;;
    "ecr")
        setup_ecr_monitoring
        ;;
    "all")
        setup_harbor_monitoring
        setup_ecr_monitoring
        ;;
    *)
        echo "Usage: $0 {harbor|ecr|all}"
        exit 1
        ;;
esac

setup_registry_alerting
create_monitoring_dashboard

echo ""
echo " Registry monitoring and auditing setup complete"
echo ""
echo "Created files:"
echo "  - analyze-*-logs.sh - Log analysis scripts"
echo "  - collect-*-metrics.sh - Metrics collection scripts"
echo "  - registry-alerting-config.yaml - Alerting configuration"
echo "  - registry-security-dashboard.json - Grafana dashboard"
echo ""
echo "Next steps:"
echo "1. Configure log aggregation and SIEM integration"
echo "2. Set up automated alerting for security events"
echo "3. Create regular audit and compliance reports"
echo "4. Implement automated response to security incidents"
echo "5. Train teams on security monitoring procedures"
EOF

chmod +x setup-registry-monitoring.sh
```

This container registry security guide provides tools for securing access control, implementing vulnerability scanning, setting up image signing and verification, and monitoring registry activities. The scripts help organizations maintain secure container registries while ensuring compliance with security policies and detecting potential threats.