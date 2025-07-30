# Code Scanning & Static Analysis Security Guide

This guide provides  troubleshooting for static application security testing (SAST), secrets detection, and dependency vulnerability management in your codebase.


## Overview

Code scanning is your first line of defense against security vulnerabilities. This guide helps you troubleshoot common issues with:

- **SAST Tools**: SonarQube, CodeQL, Semgrep, Checkmarx, Veracode
- **Secret Scanners**: GitLeaks, TruffleHog, detect-secrets
- **Dependency Scanners**: Snyk, OWASP Dependency-Check, npm audit
- **License Compliance**: FOSSA, WhiteSource, Black Duck

## Static Application Security Testing (SAST)

### Common SAST Issues

#### Issue: High False Positive Rate

**Symptoms:**
- Hundreds of low-priority findings
- Developers ignoring SAST reports
- Security team overwhelmed with noise

**Diagnosis:**
```bash
# Analyze SAST results by severity and confidence
cat sast-results.json | jq '.findings[] | {severity: .severity, confidence: .confidence, rule: .rule_id}' | sort | uniq -c

# Check rule configuration
grep -r "severity.*LOW" sonar-project.properties
grep -r "confidence.*LOW" checkmarx-config.xml

# Review historical false positive rate
awk '/false_positive/ {fp++} /total_findings/ {total++} END {print "False Positive Rate:", fp/total*100"%"}' sast-audit.log
```

**Solution:**
```bash
# Tune SAST rules - disable noisy low-value rules
# SonarQube example
curl -X POST "http://sonarqube:9000/api/qualityprofiles/deactivate_rule" \
  -H "Authorization: Basic $(echo -n admin:admin | base64)" \
  -d "key=java-security-way-12345" \
  -d "rule=javascript:S1481"

# Semgrep - create custom rule exclusions
cat > .semgrepignore << EOF
# Ignore test files for certain rules
tests/
*_test.go
*.test.js
EOF

# CodeQL - customize query suite
cat > .github/codeql/codeql-config.yml << EOF
name: "Custom CodeQL Config"
queries:
  - uses: security-extended
  - uses: security-and-quality
packs:
  - codeql/javascript-queries
  - codeql/python-queries
EOF
```

#### Issue: SAST Tool Not Detecting Known Vulnerabilities

**Symptoms:**
- Manual code review finds issues SAST missed
- Penetration testing reveals missed vulnerabilities
- Inconsistent results across different tools

**Diagnosis:**
```bash
# Test with known vulnerable patterns
echo 'eval($_GET["cmd"])' > test-sqli.php
echo 'SELECT * FROM users WHERE id = ' + userId > test-sqli.js

# Run SAST tool against test cases
semgrep --config=r/security test-sqli.php test-sqli.js
sonar-scanner -Dsonar.sources=. -Dsonar.projectKey=test-vuln

# Check tool version and rule updates
semgrep --version
sonar-scanner --version
```

**Solution:**
```bash
# Update SAST tools and rules
# Semgrep
semgrep --update

# SonarQube
docker pull sonarqube:latest
# Update quality profiles with latest security rules

# CodeQL
codeql database update /path/to/database

# Add custom security rules for your tech stack
cat > custom-security.yml << EOF
rules:
  - id: hardcoded-secret
    pattern: |
      password = "$PASSWORD"
    message: Hardcoded password detected
    severity: ERROR
    languages: [python, javascript]
EOF
```

### Language-Specific SAST Configuration

#### JavaScript/TypeScript
```bash
# ESLint security plugin setup
npm install --save-dev eslint-plugin-security

cat > .eslintrc.js << EOF
module.exports = {
  plugins: ['security'],
  extends: ['plugin:security/recommended'],
  rules: {
    'security/detect-eval-with-expression': 'error',
    'security/detect-non-literal-fs-filename': 'error',
    'security/detect-unsafe-regex': 'error'
  }
};
EOF

# Run security-focused linting
eslint --ext .js,.ts --rule "security/detect-eval-with-expression: error" src/
```

#### Python
```bash
# Bandit for Python security scanning
pip install bandit[toml]

cat > pyproject.toml << EOF
[tool.bandit]
exclude_dirs = ["tests", "venv"]
skips = ["B101", "B601"]  # Skip assert and shell usage in tests
EOF

# Run with confidence levels
bandit -r . -f json -o bandit-report.json --confidence-level medium
```

#### Java
```bash
# SpotBugs with security rules
mvn spotbugs:spotbugs -Dspotbugs.includeFilterFile=security-rules.xml

cat > security-rules.xml << EOF
<FindBugsFilter>
  <Match>
    <Bug category="SECURITY"/>
  </Match>
</FindBugsFilter>
EOF
```

## Secrets Detection

### Common Secret Scanner Issues

#### Issue: Secrets Scanner Missing Actual Secrets

**Symptoms:**
- Manual review finds API keys, passwords
- Scanner reports no findings
- False sense of security

**Diagnosis:**
```bash
# Test scanner with known patterns
echo "api_key = 'sk-1234567890abcdef'" > test-secret.py
echo "password = 'P@ssw0rd123'" >> test-secret.py

# Run different scanners
gitleaks detect --source . --verbose
trufflehog filesystem --only-verified .
detect-secrets scan test-secret.py

# Check scanner configuration
cat .gitleaksignore
cat .secrets.baseline
```

**Solution:**
```bash
# Configure comprehensive secret patterns
cat > .gitleaks.toml << EOF
[[rules]]
description = "AWS Access Key"
regex = '''AKIA[0-9A-Z]{16}'''
tags = ["aws", "credentials"]

[[rules]]
description = "Private Key"
regex = '''-----BEGIN PRIVATE KEY-----'''
tags = ["private-key"]

[[rules]]
description = "JWT Token"
regex = '''eyJ[A-Za-z0-9+/=]+\.eyJ[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+'''
tags = ["jwt"]

[[rules]]
description = "Database Connection String"
regex = '''(mysql|postgres|mongodb)://[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@'''
tags = ["database"]
EOF

# Create comprehensive secret hunting script
cat > scripts/hunt-secrets.sh << 'EOF'
#!/bin/bash
echo "=== Comprehensive Secret Hunt ==="

# Multiple tools for better coverage
echo "Running GitLeaks..."
gitleaks detect --source . --report-format json --report-path gitleaks-report.json

echo "Running TruffleHog..."
trufflehog filesystem --only-verified --json . > trufflehog-report.json

echo "Running custom regex patterns..."
# Custom patterns for your organization
grep -r -E "api[_-]?key['\"]?\s*[:=]\s*['\"][a-zA-Z0-9]{20,}" . --exclude-dir=.git
grep -r -E "secret['\"]?\s*[:=]\s*['\"][a-zA-Z0-9+/]{20,}" . --exclude-dir=.git

echo "=== Results Summary ==="
echo "GitLeaks findings: $(cat gitleaks-report.json | jq length)"
echo "TruffleHog findings: $(cat trufflehog-report.json | wc -l)"
EOF
```

#### Issue: Too Many False Positives in Secret Scanning

**Symptoms:**
- Scanner flagging test data, documentation
- Variables named "password" without actual secrets
- Overwhelming number of findings

**Diagnosis:**
```bash
# Analyze false positive patterns
jq '.[] | select(.RuleID == "generic-api-key") | .File' gitleaks-report.json | sort | uniq -c

# Check what's being flagged
jq -r '.[] | "\(.File):\(.StartLine) - \(.Match)"' gitleaks-report.json | head -20

# Review current ignore rules
cat .gitleaksignore
```

**Solution:**
```bash
# Create sophisticated ignore patterns
cat > .gitleaksignore << EOF
# Test files and fixtures
**/test/**
**/tests/**
**/*test*
**/*_test.go
**/fixtures/**
**/mock/**

# Documentation
README.md
CHANGELOG.md
docs/**
*.md

# Configuration templates
config.template.yml
*.example
*.sample

# Build artifacts
dist/**
build/**
node_modules/**
EOF

# Use entropy analysis to reduce false positives
cat > high-entropy-secrets.py << 'EOF'
import math
import re
import sys

def calculate_entropy(s):
    if not s:
        return 0
    entropy = 0
    for char in set(s):
        p = s.count(char) / len(s)
        entropy -= p * math.log2(p)
    return entropy

def is_likely_secret(value):
    # High entropy strings are more likely to be secrets
    return len(value) > 15 and calculate_entropy(value) > 4.0

# Scan for high-entropy strings that look like secrets
with open(sys.argv[1], 'r') as f:
    content = f.read()
    
patterns = [
    r"['\"]([A-Za-z0-9+/]{20,})['\"]",  # Base64-like
    r"['\"]([A-Fa-f0-9]{20,})['\"]",    # Hex strings
    r"['\"]([A-Za-z0-9._-]{20,})['\"]"  # Mixed strings
]

for pattern in patterns:
    matches = re.findall(pattern, content)
    for match in matches:
        if is_likely_secret(match):
            print(f"Potential secret: {match[:10]}... (entropy: {calculate_entropy(match):.2f})")
EOF
```

## Dependency Vulnerability Scanning

### Common Dependency Scanner Issues

#### Issue: Overwhelming Number of Vulnerability Findings

**Symptoms:**
- Hundreds of medium/low severity CVEs
- Many findings in transitive dependencies
- Difficult to prioritize remediation efforts

**Diagnosis:**
```bash
# Analyze vulnerability breakdown
npm audit --json | jq '.vulnerabilities | to_entries[] | {name: .key, severity: .value.severity}' | sort | uniq -c

# Check direct vs transitive dependencies
npm audit --json | jq '.vulnerabilities | to_entries[] | select(.value.via | type == "array") | .key'

# Analyze by severity and exploitability
snyk test --json | jq '.vulnerabilities[] | {id: .id, severity: .severity, cvssScore: .cvssScore, exploit: .exploit}' | sort
```

**Solution:**
```bash
# Focus on high-severity, directly exploitable vulnerabilities
cat > vulnerability-filter.sh << 'EOF'
#!/bin/bash
echo "=== Critical & High Severity Vulnerabilities ==="

# npm audit - focus on fixable issues
npm audit --audit-level=high --json | jq -r '.vulnerabilities[] | select(.severity == "critical" or .severity == "high") | "\(.title): \(.via[0].name) - \(.via[0].url)"'

# Snyk - filter by exploitability
snyk test --severity-threshold=high --json | jq -r '.vulnerabilities[] | select(.exploit == "Mature" or .exploit == "High") | "\(.id): \(.title) (CVSS: \(.cvssScore))"'

# OWASP Dependency Check - focus on high confidence findings
grep -E "(Critical|High)" dependency-check-report.xml | grep -E "confidence=\"(HIGHEST|HIGH)\""

echo "=== Prioritization Recommendations ==="
echo "1. Fix Critical/High vulnerabilities in direct dependencies"
echo "2. Update dependencies with available patches"  
echo "3. Consider alternatives for unmaintained packages"
EOF

# Create dependency update strategy
cat > update-dependencies.sh << 'EOF'
#!/bin/bash
# Safe dependency update approach

echo "=== Checking for security updates ==="
npm audit fix --only=prod  # Only production dependencies
# or
yarn audit --level high

echo "=== Updating to latest secure versions ==="
# Update to latest minor/patch versions (safer)
npm update

# For major version updates, check breaking changes first
npm outdated | grep -E "(major|red)"
EOF
```

#### Issue: False Positive Vulnerabilities

**Symptoms:**
- Vulnerabilities in unused code paths
- Development-only dependencies flagged in production scans
- Vulnerabilities that don't apply to your use case

**Diagnosis:**
```bash
# Check if vulnerability affects used code paths
# For npm packages
npm audit --json | jq '.vulnerabilities[].via[] | select(.source != null) | .source'

# Check dependency tree
npm ls affected-package
yarn why affected-package

# Analyze if dev dependency affects production
jq '.devDependencies' package.json
```

**Solution:**
```bash
# Configure scanner to ignore dev dependencies in production builds
cat > .snyk << EOF
# Ignore vulnerabilities in dev dependencies for production
ignore:
  SNYK-JS-LODASH-567746:
    - '*':
        reason: Used only in development environment
        expires: 2024-12-31T23:59:59.999Z
EOF

# Use different scanning approaches for different environments
cat > security-scan.sh << 'EOF'
#!/bin/bash
if [ "$NODE_ENV" = "production" ]; then
    # Production: scan only production dependencies
    npm audit --only=prod --audit-level=moderate
else
    # Development: scan all dependencies but with different thresholds
    npm audit --audit-level=high
fi

# Custom script to check if vulnerability is actually exploitable
python3 check_exploitability.py --package lodash --version 4.17.15 --usage-pattern "_.merge(object, source)"
EOF
```

## Code Quality Security Gates

### Setting Up Security Quality Gates

#### CI/CD Pipeline Integration
```bash
# GitHub Actions security workflow
cat > .github/workflows/security-scan.yml << EOF
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run SAST
        uses: github/codeql-action/analyze@v2
        with:
          languages: javascript,python
          
      - name: Secret Scanning
        run: |
          docker run --rm -v "\$PWD:/code" zricethezav/gitleaks:latest detect --source /code --verbose
          
      - name: Dependency Scanning  
        run: |
          npm audit --audit-level=high
          pip-audit
          
      - name: Security Gate
        run: |
          # Fail build if critical vulnerabilities found
          CRITICAL_COUNT=\$(npm audit --json | jq '.metadata.vulnerabilities.critical // 0')
          if [ "\$CRITICAL_COUNT" -gt 0 ]; then
            echo "CRITICAL: \$CRITICAL_COUNT critical vulnerabilities found"
            exit 1
          fi
EOF

# Jenkins pipeline security stage
cat > Jenkinsfile.security << EOF
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            parallel {
                stage('SAST') {
                    steps {
                        script {
                            sh 'sonar-scanner -Dsonar.projectKey=myproject'
                            def qualityGate = waitForQualityGate()
                            if (qualityGate.status != 'OK') {
                                error "Security quality gate failed: \${qualityGate.status}"
                            }
                        }
                    }
                }
                stage('Secret Scan') {
                    steps {
                        sh 'gitleaks detect --source . --report-format json --report-path gitleaks-report.json'
                        script {
                            def report = readJSON file: 'gitleaks-report.json'
                            if (report.size() > 0) {
                                error "Secrets detected in code"
                            }
                        }
                    }
                }
            }
        }
    }
}
EOF
```

## Integration Troubleshooting

### Common CI/CD Integration Issues

#### Issue: Security Scans Timing Out

**Symptoms:**
- CI/CD pipeline fails due to scanner timeouts
- Large codebases taking too long to scan
- Resource constraints in build environment

**Solution:**
```bash
# Optimize SAST scanning
cat > optimize-scan.sh << 'EOF'
#!/bin/bash
# Incremental scanning - only scan changed files
if [ "$GITHUB_EVENT_NAME" = "pull_request" ]; then
    # Get changed files
    CHANGED_FILES=$(git diff --name-only $GITHUB_BASE_REF..HEAD)
    
    # Run SAST only on changed files
    echo "$CHANGED_FILES" | xargs semgrep --config=r/security
else
    # Full scan on main branch
    semgrep --config=r/security .
fi

# Parallel scanning for large codebases
CORES=$(nproc)
find . -name "*.py" -print0 | xargs -0 -n 1 -P $CORES bandit

# Use caching to speed up subsequent runs
- uses: actions/cache@v3
  with:
    path: ~/.cache/semgrep
    key: ${{ runner.os }}-semgrep-${{ hashFiles('**/*.py', '**/*.js') }}
EOF
```

#### Issue: Scanner Authentication Failures

**Symptoms:**
- "Authentication failed" errors
- Unable to access private dependencies
- License validation failures

**Solution:**
```bash
# Secure authentication setup
# Environment variables for CI/CD
export SNYK_TOKEN="your-snyk-token"
export SONAR_TOKEN="your-sonar-token" 
export GITHUB_TOKEN="your-github-token"

# Docker registry authentication for private base images
echo $DOCKER_REGISTRY_PASSWORD | docker login -u $DOCKER_REGISTRY_USER --password-stdin registry.company.com

# Private npm registry authentication  
npm config set registry https://npm.company.com/
npm config set //npm.company.com/:_authToken $NPM_TOKEN

# Troubleshoot authentication issues
curl -H "Authorization: Bearer $SNYK_TOKEN" https://snyk.io/api/v1/user/me
curl -H "Authorization: Bearer $SONAR_TOKEN" http://sonarqube.company.com/api/authentication/validate
```

## False Positive Management

### Systematic False Positive Reduction

```bash
# Create false positive analysis script
cat > analyze-false-positives.sh << 'EOF'
#!/bin/bash
echo "=== False Positive Analysis ==="

# Analyze SAST findings by rule and frequency
echo "Most frequent SAST findings:"
jq -r '.findings[] | .rule_id' sast-results.json | sort | uniq -c | sort -nr | head -10

# Check patterns that are likely false positives
echo "Checking common false positive patterns:"
grep -E "(test|mock|example)" sast-results.json
grep -E "(TODO|FIXME|XXX)" sast-results.json

# Create suppression rules for validated false positives
cat > suppressions.json << SUPP
{
  "suppress": [
    {
      "rule_id": "hardcoded-password",
      "file_pattern": "**/test/**",
      "reason": "Test files contain dummy credentials"
    },
    {
      "rule_id": "sql-injection", 
      "line_pattern": ".*-- This is safe because.*",
      "reason": "Manually reviewed and marked as safe"
    }
  ]
}
SUPP

echo "=== Suppression rules created ==="
EOF

# Implement smart filtering
cat > smart-filter.py << 'EOF'
import json
import re

def filter_findings(findings_file, config_file):
    with open(findings_file) as f:
        findings = json.load(f)
    
    with open(config_file) as f:
        config = json.load(f)
    
    filtered = []
    for finding in findings:
        should_suppress = False
        
        for suppression in config.get('suppress', []):
            # Check if suppression rule applies
            if finding.get('rule_id') == suppression.get('rule_id'):
                file_pattern = suppression.get('file_pattern', '.*')
                if re.match(file_pattern.replace('*', '.*'), finding.get('file', '')):
                    should_suppress = True
                    break
        
        if not should_suppress:
            filtered.append(finding)
    
    return filtered

# Usage
filtered = filter_findings('sast-results.json', 'suppressions.json')
print(f"Original findings: {len(findings)}, After filtering: {len(filtered)}")
EOF
```

## Real-World Scenarios

### Scenario 1: Critical Vulnerability in Production Dependency

**Situation:** Your dependency scanner flags a critical vulnerability in a widely-used library that's in production.

**Response:**
```bash
# 1. Assess the impact immediately
npm audit --json | jq '.vulnerabilities[] | select(.severity == "critical") | {title: .title, package: .via[0].name, vulnerable_versions: .via[0].range}'

# 2. Check if the vulnerable code path is actually used
# Create a script to trace usage
cat > trace-usage.sh << 'EOF'
#!/bin/bash
PACKAGE_NAME=$1
echo "Tracing usage of $PACKAGE_NAME..."

# Find direct imports/requires
grep -r "import.*$PACKAGE_NAME" src/
grep -r "require.*$PACKAGE_NAME" src/

# Check which functions are being called
grep -r "$PACKAGE_NAME\." src/ | head -20

# Check if vulnerability affects used functions
echo "Review vulnerability details to see if used functions are affected"
EOF

# 3. Implement immediate mitigation if patch not available
# Option A: Vendor the library and patch it yourself
npm pack vulnerable-library
tar -xzf vulnerable-library-1.0.0.tgz
# Apply security patch to package/
npm install ./package

# Option B: Use npm override/resolutions to force secure version
cat > package.json.patch << 'EOF'
{
  "overrides": {
    "vulnerable-library": "1.0.1-security-patch"
  }
}
EOF

# 4. Test thoroughly
npm test
# Run security scan again to confirm fix
npm audit --audit-level=critical
```

### Scenario 2: Secret Accidentally Committed to Repository

**Situation:** GitLeaks detects an AWS access key was committed to your main branch.

**Immediate Response:**
```bash
# 1. IMMEDIATELY revoke the exposed credential
aws iam delete-access-key --access-key-id AKIA1234567890ABCDEF --user-name service-account

# 2. Check if the key was used maliciously
aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA1234567890ABCDEF --start-time 2024-01-01 --end-time $(date -I)

# 3. Remove from git history (if recent commit)
git filter-branch --force --index-filter 'git rm --cached --ignore-unmatch config/secrets.yml' --prune-empty --tag-name-filter cat -- --all

# 4. Force push to remove from remote (coordinate with team)
git push origin --force --all

# 5. Implement secret scanning pre-commit hook
cat > .pre-commit-config.yaml << EOF
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
EOF
pre-commit install

# 6. Set up proper secrets management
# Move to environment variables or secret manager
export AWS_ACCESS_KEY_ID=$(aws ssm get-parameter --name "/app/aws-access-key" --with-decryption --query Parameter.Value --output text)
```

### Scenario 3: SAST Tool Blocking Critical Deployment

**Situation:** Your SAST tool is flagging a "vulnerability" that's blocking a critical production deployment, but you believe it's a false positive.

**Response:**
```bash
# 1. Quick validation of the finding
# Get exact details of the finding
jq '.findings[] | select(.id == "FINDING_ID") | {file: .file, line: .line, code: .snippet, rule: .rule_id}' sast-results.json

# 2. Manual code review
# Check the flagged code in context
sed -n '150,170p' src/auth/login.js  # Around the flagged line

# 3. Create emergency bypass with documentation
cat > emergency-bypass.md << EOF
# Emergency Security Bypass - $(date)

**Finding ID:** SAST-2024-001
**Rule:** hardcoded-password
**File:** src/auth/login.js:155
**Reviewer:** $(whoami)
**Business Justification:** Critical customer-facing bug fix needed for production

**Security Analysis:**
- The flagged line is a constant used for test environment detection
- No actual credentials are hardcoded
- Risk assessed as FALSE POSITIVE

**Mitigation:** 
- Added suppression rule
- Scheduled for proper fix in next sprint
- Security team notified

**Approval:** @security-team-lead
EOF

# 4. Add targeted suppression
cat >> sonar-project.properties << EOF
# Emergency suppression for deployment - remove after proper fix
sonar.issue.ignore.multicriteria=e1
sonar.issue.ignore.multicriteria.e1.ruleKey=javascript:S2068
sonar.issue.ignore.multicriteria.e1.resourceKey=src/auth/login.js
EOF

# 5. Deploy with monitoring
# Add extra logging around the bypassed finding
echo "SECURITY_BYPASS_ACTIVE=true" >> deployment-flags.env

# 6. Schedule immediate follow-up
echo "TODO: Fix hardcoded constant in auth/login.js - Security bypass active until $(date -d '+7 days')" >> tech-debt.md
```

These scenarios demonstrate the balance between security rigor and operational necessity, always with proper documentation and follow-up actions.