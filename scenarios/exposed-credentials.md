# Scenario: AWS Credentials Exposed in GitHub Repository

## Incident Overview

**Incident Type:** Credential Exposure  
**Severity:** Critical  
**Business Impact:** High  
**Discovery Method:** GitHub Secret Scanning Alert  

### What Happened

A developer accidentally committed AWS access keys to a public GitHub repository. The credentials were discovered by GitHub's secret scanning feature and flagged as exposed. The keys have administrative access to the company's production AWS environment.

### Timeline of Events

- **09:15 AM**: Developer commits code to public repository including `.env` file
- **09:17 AM**: GitHub secret scanning detects AWS credentials  
- **09:18 AM**: Automated alert sent to security team
- **09:22 AM**: Security analyst confirms credential exposure
- **09:25 AM**: Incident response initiated

## Initial Assessment

### Immediate Indicators

**Exposed Credentials:**
```bash
# Found in public repository: company/web-app/.env
AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF
AWS_SECRET_ACCESS_KEY=abcd1234567890abcdef1234567890abcdef12
AWS_DEFAULT_REGION=us-east-1
```

**Repository Details:**
- Repository: `company/web-app`
- File: `.env` 
- Commit: `a1b2c3d4e5f6789012345678901234567890abcd`
- Public visibility: Yes

**Credential Permissions:**
- Policy: `AdministratorAccess`
- MFA Required: No
- Last Used: 2 hours ago

## Investigation Phase

### Step 1: Assess Credential Usage

```bash
# Check recent AWS API activity for the exposed credentials
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA1234567890ABCDEF \
    --start-time 2024-01-15T09:00:00Z \
    --end-time 2024-01-15T12:00:00Z \
    --output table

# Result shows suspicious activity:
# - 15 EC2 instances launched in us-west-1 (unusual region)
# - S3 bucket created: "crypto-mining-temp-bucket"
# - IAM user created: "backup-service-user"
# - Multiple API calls from IP: 185.220.xxx.xxx (TOR exit node)
```

### Step 2: Identify Malicious Activity

**Suspicious API Calls Detected:**
```bash
# EC2 instances launched for cryptocurrency mining
aws ec2 describe-instances \
    --filters "Name=instance-state-name,Values=running" \
    --query 'Reservations[].Instances[?LaunchTime>`2024-01-15T09:00:00Z`].[InstanceId,InstanceType,LaunchTime,PublicIpAddress]' \
    --output table

# Results:
# |  i-0abcd1234567890ef |  m5.24xlarge  |  2024-01-15T09:35:24Z  |  18.144.xxx.xxx |
# |  i-0abcd1234567890fg |  m5.24xlarge  |  2024-01-15T09:36:45Z  |  54.183.xxx.xxx |
# (13 more similar instances...)

# S3 bucket analysis
aws s3 ls s3://crypto-mining-temp-bucket --recursive
# Contains cryptocurrency mining software and configuration files

# New IAM user investigation
aws iam get-user --user-name backup-service-user
aws iam list-attached-user-policies --user-name backup-service-user
# Result: User has PowerUserAccess policy attached
```

### Step 3: Calculate Financial Impact

```bash
# Calculate cost of unauthorized instances
aws ce get-cost-and-usage \
    --time-period Start=2024-01-15,End=2024-01-16 \
    --granularity DAILY \
    --metrics BlendedCost \
    --group-by Type=DIMENSION,Key=SERVICE

# Estimated impact: $2,847 in 3 hours (m5.24xlarge instances)
# Projected daily cost if not stopped: $22,776
```

## Response Actions

### Phase 1: Immediate Containment (0-15 minutes)

#### 1.1 Disable Compromised Credentials
```bash
# CRITICAL: Immediately disable the exposed access key
aws iam update-access-key \
    --access-key-id AKIA1234567890ABCDEF \
    --status Inactive \
    --user-name production-deploy-user

echo "Compromised access key disabled at $(date)"
```

#### 1.2 Stop Unauthorized Resources
```bash
# Terminate all instances launched by the compromised key
MALICIOUS_INSTANCES=$(aws ec2 describe-instances \
    --filters "Name=instance-state-name,Values=running" \
    --query 'Reservations[].Instances[?LaunchTime>`2024-01-15T09:00:00Z`].InstanceId' \
    --output text)

if [ ! -z "$MALICIOUS_INSTANCES" ]; then
    echo "Terminating malicious instances: $MALICIOUS_INSTANCES"
    aws ec2 terminate-instances --instance-ids $MALICIOUS_INSTANCES
    echo "Unauthorized instances terminated"
fi

# Delete malicious S3 bucket
aws s3 rb s3://crypto-mining-temp-bucket --force
echo "Malicious S3 bucket removed"

# Delete unauthorized IAM user
aws iam detach-user-policy --user-name backup-service-user --policy-arn arn:aws:iam::aws:policy/PowerUserAccess
aws iam delete-user --user-name backup-service-user
echo "Unauthorized IAM user removed"
```

### Phase 2: Evidence Collection (15-30 minutes)

#### 2.1 Preserve CloudTrail Logs
```bash
# Export relevant CloudTrail events for forensic analysis
mkdir -p incident-evidence/cloudtrail-logs

aws logs filter-log-events \
    --log-group-name CloudTrail/AWSCloudTrailLogs \
    --start-time $(date -d '6 hours ago' +%s)000 \
    --filter-pattern '{ $.userIdentity.accessKeyId = "AKIA1234567890ABCDEF" }' \
    --output json > incident-evidence/cloudtrail-logs/malicious-activity.json

echo "CloudTrail evidence collected"
```

#### 2.2 Document Repository History
```bash
# Clone repository and analyze git history
git clone https://github.com/company/web-app.git incident-evidence/repository-clone
cd incident-evidence/repository-clone

# Find when credentials were first committed
git log -p --all -S "AKIA1234567890ABCDEF" > ../credential-history.log

# Check if credentials exist in other branches
git grep -n "AKIA1234567890ABCDEF" $(git rev-list --all)

echo "Repository evidence collected"
```

#### 2.3 Network Analysis
```bash
# Analyze source IPs of malicious activity
cat incident-evidence/cloudtrail-logs/malicious-activity.json | \
    jq -r '.events[] | .sourceIPAddress' | sort | uniq -c > incident-evidence/source-ips.txt

# Check IP reputation
for ip in $(cat incident-evidence/source-ips.txt | awk '{print $2}'); do
    echo "Checking IP: $ip"
    whois $ip | grep -E "(OrgName|country|NetName)" >> incident-evidence/ip-analysis.txt
done

echo "Network forensics completed"
```

### Phase 3: System Hardening (30-60 minutes)

#### 3.1 Rotate All Related Credentials
```bash
# Create new access key for legitimate use
NEW_CREDENTIALS=$(aws iam create-access-key --user-name production-deploy-user --output json)
echo "$NEW_CREDENTIALS" > incident-evidence/new-credentials.json

# Update deployment systems with new credentials
echo "MANUAL ACTION REQUIRED: Update CI/CD systems with new credentials"
echo "New Access Key ID: $(echo $NEW_CREDENTIALS | jq -r .AccessKey.AccessKeyId)"
```

#### 3.2 Implement Additional Security Controls
```bash
# Create CloudWatch alarm for unusual EC2 launches
aws cloudwatch put-metric-alarm \
    --alarm-name "UnauthorizedEC2Launches" \
    --alarm-description "Detects unusual EC2 instance launches" \
    --metric-name "EC2InstanceLaunches" \
    --namespace "AWS/EC2" \
    --statistic Sum \
    --period 300 \
    --threshold 5 \
    --comparison-operator GreaterThanThreshold \
    --evaluation-periods 1 \
    --alarm-actions "arn:aws:sns:us-east-1:123456789012:security-alerts"

# Enable AWS Config for compliance monitoring
aws configservice put-configuration-recorder \
    --configuration-recorder name=SecurityRecorder,roleARN=arn:aws:iam::123456789012:role/ConfigRole \
    --recording-group allSupported=true

echo "Enhanced monitoring configured"
```

#### 3.3 Repository Remediation
```bash
# Remove credentials from git history
cd incident-evidence/repository-clone
git filter-branch --force --index-filter 'git rm --cached --ignore-unmatch .env' --prune-empty --tag-name-filter cat -- --all

# Force push to remove from remote (coordinate with team)
git push origin --force --all
git push origin --force --tags

# Add .env to .gitignore
echo ".env" >> .gitignore
echo "*.env" >> .gitignore
git add .gitignore
git commit -m "Add environment files to gitignore"
git push origin main

echo "Repository sanitized"
```

### Phase 4: Recovery & Monitoring (1-24 hours)

#### 4.1 Restore Legitimate Services
```bash
# Verify legitimate services are working with new credentials
kubectl get pods -n production | grep -E "(Pending|Error|CrashLoopBackOff)"

# Update any failed services
echo " Update the following services with new AWS credentials:"
echo "- Production deployment pipeline"
echo "- Monitoring systems"
echo "- Backup systems"
echo "- Data processing jobs"
```

#### 4.2 Implement Preventive Measures
```bash
# Install pre-commit hooks to prevent future credential exposure
cat > .pre-commit-config.yaml << 'EOF'
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
  - repo: https://github.com/thoughtworks/talisman
    rev: v1.30.0
    hooks:
      - id: talisman-commit
EOF

# Set up GitHub secret scanning for organization
echo "Configure GitHub Advanced Security for all repositories"
echo "Enable secret scanning for private repositories"
echo "Set up secret scanning webhook notifications"
```

## Lessons Learned & Prevention

### Root Cause Analysis

**Primary Cause:** Developer included environment file in git commit  
**Contributing Factors:**
- No pre-commit hooks to scan for secrets
- Overprivileged AWS credentials (AdministratorAccess)
- No MFA required for programmatic access
- Insufficient monitoring of AWS API usage

### Preventive Measures Implemented

#### 1. Code Repository Security
- **Pre-commit hooks**: Gitleaks and Talisman installed
- **GitHub Advanced Security**: Enabled for all repositories
- **Developer training**: Mandatory session on secure coding practices
- **.gitignore templates**: Standard templates for all project types

#### 2. AWS Security Hardening
- **Least privilege IAM**: All service accounts reviewed and restricted
- **MFA enforcement**: Required for all programmatic access
- **CloudWatch alarms**: Unusual activity monitoring
- **AWS Config**: Compliance monitoring enabled

#### 3. Detection & Response
- **SIEM integration**: AWS CloudTrail logs integrated with security platform
- **Automated response**: Lambda functions to auto-disable exposed credentials
- **Incident playbooks**: Updated with credential exposure procedures
- **Regular drills**: Quarterly incident response exercises

### Financial Impact Summary

| Category | Cost |
|----------|------|
| **Direct AWS charges** | $2,847 |
| **Incident response time** | $8,500 (17 hours × $500/hour) |
| **System downtime** | $1,200 (20 minutes production impact) |
| **Total Impact** | **$12,547** |

### Key Takeaways

1. **Speed matters**: The 7-minute response time prevented $180,000+ in additional charges
2. **Automation is critical**: Pre-commit hooks would have prevented this entirely  
3. **Monitoring works**: GitHub secret scanning provided immediate detection
4. **Least privilege principle**: Admin access made the impact much worse
5. **Git history is permanent**: Complete history remediation was necessary

### Communication Timeline

| Time | Audience | Message |
|------|----------|---------|
| 09:25 | Security Team | Incident declared - credential exposure |
| 09:30 | Engineering Manager | AWS credentials compromised - rotation needed |
| 09:45 | CTO/CISO | $2,847 unauthorized charges - contained |
| 10:30 | All Engineering | Security reminder - secret scanning |
| 12:00 | Executive Team | Incident resolved - prevention measures implemented |
| 24hr | Company All-Hands | Lessons learned - security improvements |

This incident demonstrates the critical importance of:
- **Proactive secret scanning** in development workflows
- **Rapid incident response** capabilities  
- **Least privilege access** principles
- **Comprehensive monitoring** and alerting
- **Clear communication** during security incidents

The total financial impact was significant but could have been catastrophic without quick detection and response. The preventive measures implemented will help ensure this type of incident doesn't recur.