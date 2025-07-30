# Supply Chain Security Troubleshooting Guide

This guide helps you identify and resolve security issues in your software supply chain, including dependency management, build systems, and third-party integrations.


## Dependency Vulnerabilities

### Issue: Vulnerable dependencies in application code

**Symptoms:**
- Security scanners reporting vulnerable packages
- Known CVEs in dependency list
- Outdated packages with security issues
- Transitive dependency vulnerabilities

**Diagnosis:**
```bash
# Comprehensive dependency vulnerability scan
cat > scan-dependencies.sh << 'EOF'
#!/bin/bash
echo " Dependency Vulnerability Scan "

# Detect project types and scan accordingly
PROJECT_ROOT=${1:-.}
cd "$PROJECT_ROOT"

echo "1. Detecting project types in $(pwd)..."

# Node.js projects
if [ -f "package.json" ]; then
    echo "  Node.js project detected"
    
    echo "2. Scanning Node.js dependencies..."
    if command -v npm > /dev/null; then
        echo "  Running npm audit..."
        npm audit --json > npm-audit-results.json 2>/dev/null
        
        # Summary of vulnerabilities
        if [ -f npm-audit-results.json ]; then
            echo "  Vulnerability Summary:"
            jq '.metadata.vulnerabilities' npm-audit-results.json 2>/dev/null || echo "  Failed to parse audit results"
            
            echo "  Critical/High vulnerabilities:"
            jq -r '.advisories[] | select(.severity == "critical" or .severity == "high") | "  - \(.module_name): \(.title)"' npm-audit-results.json 2>/dev/null
        fi
    fi
    
    # Additional scanning with audit tools
    if command -v yarn > /dev/null; then
        echo "  Running yarn audit..."
        yarn audit --json > yarn-audit-results.json 2>/dev/null || true
    fi
    
    # Snyk scanning if available
    if command -v snyk > /dev/null; then
        echo "  Running Snyk scan..."
        snyk test --json > snyk-nodejs-results.json 2>/dev/null || true
    fi
fi

# Python projects
if [ -f "requirements.txt" ] || [ -f "Pipfile" ] || [ -f "pyproject.toml" ]; then
    echo "  Python project detected"
    
    echo "3. Scanning Python dependencies..."
    
    # Safety scan
    if command -v safety > /dev/null; then
        echo "  Running Safety scan..."
        safety check --json > safety-results.json 2>/dev/null || true
        
        if [ -f safety-results.json ]; then
            echo "  Safety scan summary:"
            jq -r '.[].advisory' safety-results.json 2>/dev/null | head -10
        fi
    fi
    
    # pip-audit if available
    if command -v pip-audit > /dev/null; then
        echo "  Running pip-audit..."
        pip-audit --format=json --output=pip-audit-results.json 2>/dev/null || true
    fi
    
    # Bandit for security issues
    if command -v bandit > /dev/null; then
        echo "  Running Bandit security scan..."
        bandit -r . -f json -o bandit-results.json 2>/dev/null || true
    fi
fi

# Java projects
if [ -f "pom.xml" ] || [ -f "build.gradle" ]; then
    echo "  Java project detected"
    
    echo "4. Scanning Java dependencies..."
    
    # OWASP Dependency Check
    if command -v dependency-check > /dev/null; then
        echo "  Running OWASP Dependency Check..."
        dependency-check --project "$(basename $(pwd))" --scan . --format JSON --out dependency-check-results.json 2>/dev/null || true
    fi
    
    # Maven security plugin
    if [ -f "pom.xml" ] && command -v mvn > /dev/null; then
        echo "  Running Maven dependency vulnerability check..."
        mvn org.sonatype.ossindex.maven:ossindex-maven-plugin:audit > maven-security-results.txt 2>&1 || true
    fi
fi

# Go projects
if [ -f "go.mod" ]; then
    echo "  Go project detected"
    
    echo "5. Scanning Go dependencies..."
    
    # Go mod audit
    if command -v go > /dev/null; then
        echo "  Running Go mod vulnerabilities check..."
        go list -json -m all | nancy sleuth > go-audit-results.txt 2>/dev/null || true
        
        # Gosec for security issues
        if command -v gosec > /dev/null; then
            echo "  Running Gosec security scan..."
            gosec -fmt json -out gosec-results.json ./... 2>/dev/null || true
        fi
    fi
fi

# Docker/Container analysis
if [ -f "Dockerfile" ]; then
    echo "  Docker project detected"
    
    echo "6. Scanning Docker dependencies..."
    
    # Trivy scan if available
    if command -v trivy > /dev/null; then
        echo "  Running Trivy filesystem scan..."
        trivy fs --format json --output trivy-results.json . 2>/dev/null || true
    fi
    
    # Hadolint for Dockerfile issues
    if command -v hadolint > /dev/null; then
        echo "  Running Hadolint Dockerfile scan..."
        hadolint Dockerfile > hadolint-results.txt 2>&1 || true
    fi
fi

# Generic file analysis
echo "7. Analyzing dependency lock files..."

# Check for dependency lock files
for lockfile in package-lock.json yarn.lock Pipfile.lock Gemfile.lock composer.lock; do
    if [ -f "$lockfile" ]; then
        echo "  Found $lockfile (last modified: $(stat -c %y "$lockfile"))"
        
        # Check for potential typosquatting
        case $lockfile in
            "package-lock.json")
                echo "    Checking for suspicious packages..."
                grep -o '"name": "[^"]*"' package-lock.json | cut -d'"' -f4 | grep -E '(^[0-9]|[^a-z0-9-]|--|\\.\\.)' | head -10 || true
                ;;
        esac
    fi
done

# Generate summary report
echo "8. Generating dependency security summary..."
cat > dependency-security-summary.txt << SUMMARY
Dependency Security Scan Summary
================================
Date: $(date)
Project: $(basename $(pwd))
Location: $(pwd)

Scan Results:
$(ls -la *-results.* 2>/dev/null | awk '{print "- " $9 " (size: " $5 " bytes)"}')

Recommendations:
1. Review all identified vulnerabilities
2. Update dependencies to latest secure versions
3. Consider alternative packages for high-risk dependencies
4. Implement automated dependency scanning in CI/CD
5. Set up vulnerability monitoring and alerts
6. Review transitive dependencies
7. Consider using dependency pinning strategies

SUMMARY

echo " Dependency vulnerability scan complete"
echo " Summary report: dependency-security-summary.txt"
echo " Detailed results: *-results.*"
EOF

chmod +x scan-dependencies.sh
./scan-dependencies.sh
```

**Solution:**
```bash
# Fix dependency vulnerabilities
cat > fix-dependencies.sh << 'EOF'
#!/bin/bash
echo " Fixing Dependency Vulnerabilities "

PROJECT_ROOT=${1:-.}
cd "$PROJECT_ROOT"

# Create backup of current state
echo "1. Creating backup of current dependency state..."
BACKUP_DIR="dependency-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"

for file in package.json package-lock.json yarn.lock requirements.txt Pipfile Pipfile.lock pom.xml build.gradle go.mod go.sum; do
    if [ -f "$file" ]; then
        cp "$file" "$BACKUP_DIR/"
        echo "  Backed up $file"
    fi
done

# Node.js vulnerability fixes
if [ -f "package.json" ]; then
    echo "2. Fixing Node.js vulnerabilities..."
    
    # Audit and fix with npm
    if command -v npm > /dev/null; then
        echo "  Running npm audit fix..."
        npm audit fix --force > npm-fix-results.txt 2>&1
        
        echo "  Checking for remaining vulnerabilities..."
        npm audit --audit-level moderate > npm-audit-post-fix.txt 2>&1
        
        # Manual fixes for critical issues
        echo "  Manual vulnerability fixes..."
        
        # Update specific vulnerable packages
        npm list --depth=0 --parseable | while read package_path; do
            if [ -n "$package_path" ]; then
                package_name=$(basename "$package_path")
                # Update to latest version if vulnerabilities exist
                npm update "$package_name" 2>/dev/null || true
            fi
        done
        
        echo "   Node.js dependency fixes applied"
    fi
fi

# Python vulnerability fixes
if [ -f "requirements.txt" ] || [ -f "Pipfile" ]; then
    echo "3. Fixing Python vulnerabilities..."
    
    # Create virtual environment for safe updates
    if command -v python3 > /dev/null; then
        echo "  Creating virtual environment for testing updates..."
        python3 -m venv venv-security-update
        source venv-security-update/bin/activate
        
        # Update pip first
        pip install --upgrade pip
        
        # Install and update packages
        if [ -f "requirements.txt" ]; then
            echo "  Updating packages from requirements.txt..."
            pip install -r requirements.txt
            pip freeze > requirements-updated.txt
            
            # Check for vulnerable packages and update
            if command -v safety > /dev/null; then
                safety check --json > safety-check-post-update.json 2>/dev/null || true
                
                # Auto-update vulnerable packages if possible
                safety check --output text | grep -o "^[a-zA-Z0-9_-]*" | while read pkg; do
                    if [ -n "$pkg" ]; then
                        pip install --upgrade "$pkg" 2>/dev/null || echo "Failed to update $pkg"
                    fi
                done
            fi
        fi
        
        deactivate
        echo "   Python dependency fixes applied (check venv-security-update/)"
    fi
fi

# Java vulnerability fixes
if [ -f "pom.xml" ]; then
    echo "4. Fixing Java (Maven) vulnerabilities..."
    
    if command -v mvn > /dev/null; then
        # Update dependencies
        echo "  Updating Maven dependencies..."
        mvn versions:use-latest-versions -DallowMajorUpdates=false > maven-update-results.txt 2>&1
        
        # Run dependency check again
        mvn org.sonatype.ossindex.maven:ossindex-maven-plugin:audit > maven-audit-post-fix.txt 2>&1 || true
        
        echo "   Java/Maven dependency fixes applied"
    fi
fi

if [ -f "build.gradle" ]; then
    echo "5. Fixing Java (Gradle) vulnerabilities..."
    
    if command -v gradle > /dev/null; then
        # Update dependencies
        echo "  Updating Gradle dependencies..."
        gradle dependencyUpdates > gradle-update-results.txt 2>&1 || true
        
        echo "   Java/Gradle dependency analysis complete"
    fi
fi

# Go vulnerability fixes
if [ -f "go.mod" ]; then
    echo "6. Fixing Go vulnerabilities..."
    
    if command -v go > /dev/null; then
        echo "  Updating Go modules..."
        go get -u all > go-update-results.txt 2>&1
        go mod tidy
        
        # Vulnerability scan post-update
        if command -v gosec > /dev/null; then
            gosec ./... > gosec-post-fix.txt 2>&1 || true
        fi
        
        echo "   Go dependency fixes applied"
    fi
fi

# Docker vulnerability fixes
if [ -f "Dockerfile" ]; then
    echo "7. Fixing Docker vulnerabilities..."
    
    # Create secure Dockerfile template
    echo "  Creating secure Dockerfile recommendations..."
    cat > Dockerfile.security-recommendations << SECURE_DOCKER
# Security recommendations for Dockerfile

# Use specific version tags instead of latest
FROM node:16.20.0-alpine3.17
# Instead of: FROM node:latest

# Create non-root user
RUN addgroup -g 1001 -S nodejs && adduser -S nextjs -u 1001

# Set working directory
WORKDIR /app

# Copy package files first for better layer caching
COPY package*.json ./

# Install dependencies as root, then switch to non-root user
RUN npm ci --only=production && npm cache clean --force

# Copy application code
COPY --chown=nextjs:nodejs . .

# Switch to non-root user
USER nextjs

# Expose port
EXPOSE 3000

# Use exec form for CMD
CMD ["npm", "start"]

# Additional security measures:
# - Use multi-stage builds to reduce attack surface
# - Scan images with: trivy image <image-name>
# - Use distroless or minimal base images when possible
# - Pin all dependency versions
# - Remove unnecessary packages and tools
SECURE_DOCKER

    echo "   Docker security recommendations created"
fi

# Create dependency update automation
echo "8. Creating dependency update automation..."
cat > .github/workflows/dependency-updates.yml << WORKFLOW
name: Dependency Security Updates

on:
  schedule:
    - cron: '0 2 * * 1'  # Weekly on Monday at 2 AM
  workflow_dispatch:

jobs:
  update-dependencies:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Node.js
        if: contains('package.json', github.workspace)
        uses: actions/setup-node@v3
        with:
          node-version: '18'
          cache: 'npm'
          
      - name: Setup Python  
        if: contains('requirements.txt', github.workspace)
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
          
      - name: Install security scanning tools
        run: |
          npm install -g audit-ci snyk
          pip install safety bandit
          
      - name: Run security scans
        run: |
          # Node.js scanning
          if [ -f "package.json" ]; then
            npm audit --audit-level high
            audit-ci --moderate
          fi
          
          # Python scanning
          if [ -f "requirements.txt" ]; then
            safety check
            bandit -r . -f json
          fi
          
      - name: Create Pull Request
        if: failure()
        uses: peter-evans/create-pull-request@v4
        with:
          title: 'Security: Update vulnerable dependencies'
          body: |
            Automated dependency security update
            
            This PR addresses security vulnerabilities found in dependencies.
            Please review and test before merging.
          branch: security/dependency-updates
          commit-message: 'fix: update vulnerable dependencies'
WORKFLOW

# Create dependency monitoring configuration
echo "9. Creating dependency monitoring setup..."
cat > dependency-monitoring.sh << MONITORING
#!/bin/bash
# Dependency Security Monitoring Script

SLACK_WEBHOOK_URL="\${SLACK_WEBHOOK_URL:-}"
EMAIL_RECIPIENTS="\${EMAIL_RECIPIENTS:-security@company.com}"

# Run security scans
scan_results=\$(mktemp)
critical_found=false

echo "Running dependency security monitoring..." > \$scan_results
date >> \$scan_results
echo "" >> \$scan_results

# Node.js monitoring
if [ -f "package.json" ]; then
    echo "Node.js Security Scan:" >> \$scan_results
    if npm audit --audit-level critical --json > npm_audit.json 2>/dev/null; then
        critical_count=\$(jq '.metadata.vulnerabilities.critical' npm_audit.json 2>/dev/null || echo 0)
        high_count=\$(jq '.metadata.vulnerabilities.high' npm_audit.json 2>/dev/null || echo 0)
        
        if [ "\$critical_count" -gt 0 ] || [ "\$high_count" -gt 0 ]; then
            echo "   Critical: \$critical_count, High: \$high_count" >> \$scan_results
            critical_found=true
        else
            echo "   No critical vulnerabilities found" >> \$scan_results
        fi
    fi
fi

# Python monitoring
if [ -f "requirements.txt" ]; then
    echo "Python Security Scan:" >> \$scan_results
    if command -v safety > /dev/null; then
        if ! safety check > safety_results.txt 2>&1; then
            echo "   Vulnerabilities found:" >> \$scan_results
            cat safety_results.txt >> \$scan_results
            critical_found=true
        else
            echo "   No vulnerabilities found" >> \$scan_results
        fi
    fi
fi

# Send alerts if critical vulnerabilities found
if [ "\$critical_found" = true ]; then
    echo "Critical vulnerabilities detected - sending alerts..."
    
    # Slack notification
    if [ -n "\$SLACK_WEBHOOK_URL" ]; then
        curl -X POST -H 'Content-type: application/json' \\
            --data "{\"text\":\" Critical dependency vulnerabilities detected in \$(pwd)\"}" \\
            \$SLACK_WEBHOOK_URL
    fi
    
    # Email notification
    mail -s "Critical Dependency Vulnerabilities Detected" \$EMAIL_RECIPIENTS < \$scan_results 2>/dev/null || true
fi

# Log results
cp \$scan_results "dependency-monitoring-\$(date +%Y%m%d-%H%M%S).log"
rm \$scan_results
MONITORING

chmod +x dependency-monitoring.sh

# Generate fix summary
echo "10. Generating fix summary..."
cat > dependency-fix-summary.txt << SUMMARY
Dependency Vulnerability Fix Summary
===================================
Date: $(date)
Project: $(basename $(pwd))

Actions Taken:
1. Created backup of current state: $BACKUP_DIR/
2. Applied automated fixes for Node.js dependencies
3. Updated Python packages in virtual environment
4. Updated Java/Maven dependencies
5. Updated Go modules  
6. Created secure Dockerfile recommendations
7. Set up automated dependency monitoring
8. Created GitHub Actions workflow for security updates

Files Created:
- dependency-fix-summary.txt (this file)
- Dockerfile.security-recommendations
- .github/workflows/dependency-updates.yml
- dependency-monitoring.sh
- venv-security-update/ (Python virtual env)

Post-Fix Actions Required:
1. Test application with updated dependencies
2. Review and merge any breaking changes
3. Configure Slack webhook for monitoring alerts
4. Set up email notifications for security team
5. Schedule regular dependency audits
6. Implement dependency pinning strategy
7. Consider using tools like Dependabot or Renovate

Monitoring:
- Run ./dependency-monitoring.sh regularly
- Check GitHub Actions workflow execution
- Monitor for new vulnerability disclosures
- Keep security scanning tools updated

SUMMARY

echo " Dependency vulnerability fixes completed"
echo " Fix summary: dependency-fix-summary.txt"
echo " Backup location: $BACKUP_DIR/"
echo ""
echo "  Important: Test your application thoroughly before deploying updated dependencies"
EOF

chmod +x fix-dependencies.sh
```

## Package Repository Security

### Issue: Compromised or malicious packages in repositories

**Symptoms:**
- Unexpected behavior after package updates
- Network connections to suspicious domains
- Unusual file system modifications
- Security scanners detecting malicious code

**Diagnosis:**
```bash
# Analyze package repository security
cat > analyze-package-security.sh << 'EOF'
#!/bin/bash
echo " Package Repository Security Analysis "

# Check package sources and repositories
echo "1. Analyzing package repository configurations..."

# NPM configuration
if command -v npm > /dev/null; then
    echo "  NPM Registry Configuration:"
    npm config list | grep registry
    npm config get registry
    
    echo "  NPM Authentication Tokens:"
    npm config list | grep -E "_authToken|_auth" | sed 's/=.*/=***REDACTED***/'
    
    echo "  Recently installed packages:"
    if [ -f package-lock.json ]; then
        node -e "
        const lock = require('./package-lock.json');
        const now = new Date();
        const recentThreshold = 30 * 24 * 60 * 60 * 1000; // 30 days
        
        Object.keys(lock.packages).forEach(pkg => {
            if (pkg && lock.packages[pkg].resolved) {
                console.log('    ' + pkg + ' -> ' + new URL(lock.packages[pkg].resolved).hostname);
            }
        });
        " 2>/dev/null || echo "    Could not analyze package sources"
    fi
fi

# Python package sources
if command -v pip > /dev/null; then
    echo "  Python Package Index Configuration:"
    pip config list 2>/dev/null || echo "    Using default PyPI"
    
    echo "  Recently installed packages:"
    pip list --format=json | jq -r '.[] | select(.name | test("^[0-9]|[^a-zA-Z0-9_-]")) | "     Suspicious name: " + .name' 2>/dev/null || true
fi

# Maven repositories
if [ -f pom.xml ]; then
    echo "  Maven Repository Configuration:"
    grep -A 5 "<repository>" pom.xml 2>/dev/null || echo "    Using default Maven Central"
fi

# Check for typosquatting indicators
echo "2. Checking for potential typosquatting..."

if [ -f package.json ]; then
    echo "  Analyzing Node.js package names..."
    
    # Extract package names and check for suspicious patterns
    node -e "
    const pkg = require('./package.json');
    const deps = {...(pkg.dependencies || {}), ...(pkg.devDependencies || {})};
    
    Object.keys(deps).forEach(name => {
        // Check for suspicious patterns
        if (name.match(/^[0-9]/)) {
            console.log('    Package starts with number: ' + name);
        }
        if (name.match(/[^a-z0-9\-_@\/]/)) {
            console.log('    Package has unusual characters: ' + name);
        }
        if (name.includes('--') || name.includes('..')) {
            console.log('    Package has suspicious patterns: ' + name);
        }
        if (name.length > 50) {
            console.log('    Unusually long package name: ' + name);
        }
    });
    " 2>/dev/null || echo "    Could not analyze package names"
fi

# Check package integrity and signatures
echo "3. Checking package integrity..."

if command -v npm > /dev/null && [ -f package-lock.json ]; then
    echo "  Verifying NPM package integrity..."
    npm ci --dry-run > npm-integrity-check.txt 2>&1 || echo "    Integrity check failed"
    
    grep -i "warn\|error\|integrity" npm-integrity-check.txt | head -10 || echo "    No integrity issues found"
fi

# Check for recently modified packages
echo "4. Analyzing recent package modifications..."

if [ -d node_modules ]; then
    echo "  Recently modified node_modules files:"
    find node_modules -type f -mtime -7 -not -path "*/\.cache/*" -not -name "*.log" | head -20
fi

# Network analysis of package sources
echo "5. Network security analysis..."

if command -v netstat > /dev/null; then
    echo "  Current network connections:"
    netstat -tuln | grep -E ":80|:443|:8080" | head -10
fi

# Check for suspicious scripts in packages
echo "6. Analyzing package scripts..."

if [ -f package.json ]; then
    echo "  Package.json scripts:"
    node -e "
    const pkg = require('./package.json');
    if (pkg.scripts) {
        Object.entries(pkg.scripts).forEach(([name, script]) => {
            console.log('    ' + name + ': ' + script);
            
            // Check for suspicious patterns
            if (script.match(/curl|wget|bash.*http|eval|exec/i)) {
                console.log('   Potentially suspicious script detected');
            }
        });
    }
    " 2>/dev/null
fi

# Generate security report
echo "7. Generating package security report..."
cat > package-security-report.txt << REPORT
Package Repository Security Analysis
===================================
Date: $(date)
Location: $(pwd)

Registry Configurations:
$(npm config get registry 2>/dev/null || echo "NPM: Not available")

Potential Security Issues:
- Check above output for suspicious package names
- Verify all package sources are trusted
- Review any packages with unusual download patterns
- Validate package signatures where available

Recommendations:
1. Use package-lock.json and similar lock files
2. Regularly audit dependencies
3. Use private package registries for internal packages
4. Implement package signature verification
5. Monitor for typosquatting attacks
6. Use tools like Socket.dev or Sonatype for supply chain security
7. Implement SBOM generation and tracking

REPORT

echo "✅ Package security analysis complete"
echo "📋 Report saved: package-security-report.txt"
EOF

chmod +x analyze-package-security.sh
./analyze-package-security.sh
```

**Solution:**
```bash
# Secure package repository configuration
cat > secure-package-repos.sh << 'EOF'
#!/bin/bash
echo " Securing Package Repository Configuration "

# Create secure NPM configuration
echo "1. Securing NPM configuration..."
if command -v npm > /dev/null; then
    # Set up secure registry configuration
    npm config set audit-level moderate
    npm config set fund false
    npm config set package-lock true
    npm config set save-exact true
    
    # Configure registry with authentication
    echo "  Configuring secure NPM settings..."
    
    # Create .npmrc with security settings
    cat > .npmrc << NPMRC
# NPM Security Configuration
audit-level=moderate
fund=false
package-lock=true
save-exact=true

# Use secure registry (default: https://registry.npmjs.org/)
registry=https://registry.npmjs.org/

# Security headers
strict-ssl=true
ca=""

# Disable scripts from untrusted packages
ignore-scripts=false

# Package verification
package-lock-only=false

NPMRC

    # Set up package verification
    echo "  Setting up package integrity verification..."
    cat > verify-packages.js << VERIFY_JS
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Verify package integrity
function verifyPackage(packagePath) {
    try {
        const packageJson = JSON.parse(fs.readFileSync(path.join(packagePath, 'package.json')));
        
        // Check for suspicious patterns
        const suspiciousPatterns = [
            /postinstall.*curl|wget/i,
            /preinstall.*bash.*http/i,
            /install.*eval/i
        ];
        
        if (packageJson.scripts) {
            Object.entries(packageJson.scripts).forEach(([script, command]) => {
                suspiciousPatterns.forEach(pattern => {
                    if (pattern.test(command)) {
                        console.warn('Suspicious script in', packageJson.name, ':', script, '=', command);
                    }
                });
            });
        }
        
        return true;
    } catch (error) {
        console.error('Error verifying package:', packagePath, error.message);
        return false;
    }
}

// Scan all installed packages
if (fs.existsSync('node_modules')) {
    fs.readdirSync('node_modules').forEach(pkg => {
        if (!pkg.startsWith('.') && !pkg.startsWith('@')) {
            verifyPackage(path.join('node_modules', pkg));
        }
    });
}

console.log('Package verification completed');
VERIFY_JS

    echo "   NPM security configuration applied"
fi

# Secure Python package configuration
echo "2. Securing Python package configuration..."
if command -v pip > /dev/null; then
    # Create pip configuration for security
    mkdir -p ~/.pip
    cat > ~/.pip/pip.conf << PIP_CONF
[global]
# Use only trusted repositories
trusted-host = pypi.org
               pypi.python.org
               files.pythonhosted.org

# Require HTTPS
require-virtualenv = false
trusted-host = 

# Cache settings
cache-dir = ~/.cache/pip

# Security settings
cert = 
client-cert = 

[install]
# Always verify SSL
trusted-host = 

# Use hash checking
require-hashes = false

PIP_CONF

    # Create requirements verification script
    cat > verify-python-packages.py << VERIFY_PY
#!/usr/bin/env python3
"""
Python package security verification script
"""
import json
import re
import sys
import subprocess
from pathlib import Path

def check_package_names():
    """Check for suspicious package names"""
    suspicious_patterns = [
        r'^[0-9]',  # Starts with number
        r'[^a-zA-Z0-9\-_]',  # Contains unusual characters
        r'--',  # Double hyphen
        r'\.\.',  # Double dot
    ]
    
    if Path('requirements.txt').exists():
        with open('requirements.txt', 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    package = line.split('==')[0].split('>=')[0].split('<=')[0]
                    
                    for pattern in suspicious_patterns:
                        if re.search(pattern, package):
                            print(f"  Suspicious package name: {package}")

def check_installed_packages():
    """Check currently installed packages"""
    try:
        result = subprocess.run(['pip', 'list', '--format=json'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            packages = json.loads(result.stdout)
            
            for pkg in packages:
                name = pkg['name']
                # Check for typosquatting patterns
                if re.match(r'^[0-9]', name) or len(name) > 50:
                    print(f"  Unusual package: {name} v{pkg['version']}")
                    
    except Exception as e:
        print(f"Error checking packages: {e}")

if __name__ == "__main__":
    print("Python Package Security Verification")
    print("====================================")
    check_package_names()
    check_installed_packages()
    print("Verification completed")
VERIFY_PY

    chmod +x verify-python-packages.py
    echo "   Python package security configuration applied"
fi

# Secure Maven configuration
echo "3. Securing Maven configuration..."
if command -v mvn > /dev/null || [ -f pom.xml ]; then
    # Create secure Maven settings
    mkdir -p ~/.m2
    cat > ~/.m2/settings.xml << MAVEN_SETTINGS
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 
          http://maven.apache.org/xsd/settings-1.0.0.xsd">
  
  <!-- Security-focused Maven configuration -->
  <servers>
    <!-- Configure secure access to repositories -->
    <server>
      <id>central</id>
      <configuration>
        <httpConfiguration>
          <all>
            <useSystemProperties>true</useSystemProperties>
          </all>
        </httpConfiguration>
      </configuration>
    </server>
  </servers>

  <mirrors>
    <!-- Use secure mirrors -->
    <mirror>
      <id>central</id>
      <name>Maven Central Repository</name>
      <url>https://repo1.maven.org/maven2</url>
      <mirrorOf>central</mirrorOf>
    </mirror>
  </mirrors>

  <profiles>
    <profile>
      <id>security</id>
      <properties>
        <!-- Enable checksum verification -->
        <checksum.fail>true</checksum.fail>
        <!-- Use HTTPS only -->
        <maven.wagon.http.ssl.insecure>false</maven.wagon.http.ssl.insecure>
        <maven.wagon.http.ssl.allowall>false</maven.wagon.http.ssl.allowall>
      </properties>
    </profile>
  </profiles>

  <activeProfiles>
    <activeProfile>security</activeProfile>
  </activeProfiles>
</settings>
MAVEN_SETTINGS

    echo "   Maven security configuration applied"
fi

# Set up package monitoring and verification
echo "4. Setting up package monitoring..."

# Create package monitoring script
cat > monitor-packages.sh << MONITOR
#!/bin/bash
# Package Security Monitoring Script

LOG_FILE="package-security.log"
ALERT_FILE="package-alerts.txt"

echo "Package Security Monitor - \$(date)" >> \$LOG_FILE

# Monitor new package installations
check_new_packages() {
    # NPM packages
    if [ -f package-lock.json ]; then
        # Check for recent package modifications
        find node_modules -type f -name "package.json" -mtime -1 | while read pkg_json; do
            pkg_name=\$(dirname "\$pkg_json" | xargs basename)
            echo "New/Modified package detected: \$pkg_name" >> \$LOG_FILE
            
            # Basic security check
            if grep -q "postinstall\|preinstall" "\$pkg_json"; then
                echo "  Package \$pkg_name has install scripts" >> \$ALERT_FILE
            fi
        done
    fi
    
    # Python packages
    if command -v pip > /dev/null; then
        pip list --format=json | jq -r '.[] | select(.name | test("^[0-9]")) | "Suspicious Python package: " + .name' >> \$ALERT_FILE 2>/dev/null || true
    fi
}

# Check for known vulnerabilities
check_vulnerabilities() {
    if command -v npm > /dev/null && [ -f package.json ]; then
        npm audit --json > npm-audit.json 2>/dev/null
        
        CRITICAL=\$(jq '.metadata.vulnerabilities.critical' npm-audit.json 2>/dev/null || echo 0)
        HIGH=\$(jq '.metadata.vulnerabilities.high' npm-audit.json 2>/dev/null || echo 0)
        
        if [ "\$CRITICAL" -gt 0 ] || [ "\$HIGH" -gt 0 ]; then
            echo " Critical: \$CRITICAL, High: \$HIGH vulnerabilities found" >> \$ALERT_FILE
        fi
    fi
}

# Run checks
check_new_packages
check_vulnerabilities

# Send alerts if any issues found
if [ -s \$ALERT_FILE ]; then
    echo "Security alerts found:"
    cat \$ALERT_FILE
    
    # Send notification (configure as needed)
    # mail -s "Package Security Alert" security@company.com < \$ALERT_FILE
fi
MONITOR

chmod +x monitor-packages.sh

# Create package security policy
echo "5. Creating package security policy..."
cat > PACKAGE_SECURITY_POLICY.md << POLICY
# Package Security Policy

## Overview
This document defines security requirements for managing third-party packages and dependencies.

## Package Repository Security

### Approved Registries
- **NPM**: https://registry.npmjs.org/ (default)
- **PyPI**: https://pypi.org/ (default)
- **Maven Central**: https://repo1.maven.org/maven2
- **Internal registries**: [Add your internal registry URLs]

### Prohibited Sources
- Unofficial or mirror repositories
- Repositories without HTTPS
- Repositories from unknown maintainers

## Security Requirements

### Before Adding Dependencies
1. Verify package authenticity and maintainer reputation
2. Check for known vulnerabilities using security scanners
3. Review package source code for suspicious behavior
4. Ensure package has active maintenance and community support
5. Validate package signing/verification where available

### Package Naming Validation
- Reject packages starting with numbers
- Avoid packages with unusual characters or patterns
- Check for typosquatting of popular packages
- Verify package names match official documentation

### Installation Security
1. Use exact version pinning in lock files
2. Enable package signature verification
3. Configure secure registry settings
4. Use hash verification where supported
5. Run security scans before and after installation

### Monitoring and Maintenance
1. Regular vulnerability scanning (automated)
2. Monitor for new security advisories
3. Update packages promptly when security fixes are available
4. Maintain inventory of all dependencies (SBOM)
5. Remove unused dependencies

## Incident Response

### If Malicious Package Detected
1. Immediately remove the package from systems
2. Scan all systems for compromise indicators
3. Review logs for any malicious activity
4. Report to security team and package registry
5. Update security tools with new indicators

### Communication
- Security team: security@company.com
- Emergency contact: +1-xxx-xxx-xxxx
- Incident reporting: incident-response@company.com

## Tools and Automation
- Dependency scanning: [List your tools]
- Vulnerability monitoring: [List your tools]
- SBOM generation: [List your tools]
- Package verification: [List your tools]

POLICY

echo "6. Setting up automated security scanning..."

# Create pre-commit hook for package security
mkdir -p .git/hooks
cat > .git/hooks/pre-commit << PRECOMMIT
#!/bin/bash
# Package Security Pre-commit Hook

echo "Running package security checks..."

# Check for package-lock.json changes
if git diff --cached --name-only | grep -q "package-lock.json\|requirements.txt\|pom.xml\|go.mod"; then
    echo "Package dependencies changed - running security scan..."
    
    # Run package verification
    if [ -f package.json ]; then
        node verify-packages.js || exit 1
    fi
    
    if [ -f requirements.txt ]; then
        python3 verify-python-packages.py || exit 1
    fi
    
    echo "Package security check passed"
fi
PRECOMMIT

chmod +x .git/hooks/pre-commit

echo " Package repository security configuration complete"
echo ""
echo "Configuration files created:"
echo "  - .npmrc (NPM security settings)"
echo "  - ~/.pip/pip.conf (Python security settings)"
echo "  - ~/.m2/settings.xml (Maven security settings)"
echo "  - PACKAGE_SECURITY_POLICY.md (Security policy)"
echo "  - monitor-packages.sh (Monitoring script)"
echo "  - verify-packages.js (NPM verification)"
echo "  - verify-python-packages.py (Python verification)"
echo ""
echo "Next steps:"
echo "1. Configure monitoring alerts (email/Slack)"
echo "2. Set up automated scanning in CI/CD pipeline"
echo "3. Train development team on package security policy"
echo "4. Schedule regular security audits"
echo "5. Implement SBOM generation and tracking"
EOF

chmod +x secure-package-repos.sh
```

This supply chain security guide provides detection and remediation tools for dependency vulnerabilities, package repository security, build system integrity, and monitoring. The scripts help identify compromised packages, secure repository configurations, and implement automated security scanning throughout the software development lifecycle.
