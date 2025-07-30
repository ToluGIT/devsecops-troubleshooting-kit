# AWS Security Troubleshooting Guide

This  guide helps you identify, troubleshoot, and resolve security issues in Amazon Web Services environments with a focus on attack scenarios and defensive measures.


## IAM Security Issues

### Overprivileged IAM Roles and Policies

#### Issue: Users or roles with excessive permissions

**Symptoms:**
- Users with AdministratorAccess in production
- Roles with wildcard permissions
- Service accounts with unnecessary privileges

**Diagnosis:**
```bash
# Find overprivileged users and roles
cat > iam-privilege-audit.sh << 'EOF'
#!/bin/bash
echo " IAM Privilege Escalation Audit "

# Find users with AdministratorAccess
echo "1. Users with AdministratorAccess:"
aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --query 'PolicyUsers[].UserName' --output table

# Find roles with AdministratorAccess
echo "2. Roles with AdministratorAccess:"
aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --query 'PolicyRoles[].RoleName' --output table

# Find inline policies with wildcard permissions
echo "3. Checking for wildcard permissions in inline policies..."
for user in $(aws iam list-users --query 'Users[].UserName' --output text); do
    policies=$(aws iam list-user-policies --user-name "$user" --query 'PolicyNames' --output text)
    for policy in $policies; do
        if aws iam get-user-policy --user-name "$user" --policy-name "$policy" --query 'PolicyDocument.Statement[?Effect==`Allow` && Action==`*`]' --output text | grep -q "Action"; then
            echo " User $user has wildcard permissions in policy $policy"
        fi
    done
done

# Find roles that can escalate privileges
echo "4. Roles with privilege escalation capabilities:"
aws iam list-roles --query 'Roles[].RoleName' --output text | while read role; do
    # Check if role can modify IAM
    if aws iam simulate-principal-policy --policy-source-arn "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):role/$role" --action-names "iam:AttachRolePolicy" "iam:PutRolePolicy" "iam:CreateRole" --query 'EvaluationResults[?Decision==`allowed`]' --output text | grep -q "allowed"; then
        echo "  Role $role can escalate privileges"
    fi
done

# Find unused IAM users (haven't logged in for 90+ days)
echo "5. Unused IAM users (>90 days):"
NINETY_DAYS_AGO=$(date -d '90 days ago' +%Y-%m-%d)
aws iam generate-credential-report > /dev/null 2>&1
sleep 5
aws iam get-credential-report --query 'Content' --output text | base64 -d | awk -F',' -v date="$NINETY_DAYS_AGO" 'NR>1 {if ($5 != "N/A" && $5 < date) print " " $1 " - Last login: " $5}'
EOF

chmod +x iam-privilege-audit.sh
./iam-privilege-audit.sh

# Check for cross-account trust relationships
aws iam list-roles --query 'Roles[?AssumeRolePolicyDocument.Statement[?Principal.AWS!=null]].[RoleName,AssumeRolePolicyDocument.Statement[0].Principal.AWS]' --output table
```

**Solution:**
```bash
# Implement least privilege IAM policies
cat > create-minimal-policy.sh << 'EOF'
#!/bin/bash
ROLE_NAME=$1
RESOURCES=$2

if [ -z "$ROLE_NAME" ] || [ -z "$RESOURCES" ]; then
    echo "Usage: $0 <role-name> <comma-separated-resources>"
    echo "Example: $0 ec2-read-role 'arn:aws:ec2:*:*:instance/*,arn:aws:ec2:*:*:volume/*'"
    exit 1
fi

# Create minimal policy with specific resources
cat > minimal-policy.json << POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DescribeVolumes",
                "ec2:DescribeSnapshots"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:RequestedRegion": ["us-east-1", "us-west-2"]
                }
            }
        },
        {
            "Effect": "Allow", 
            "Action": [
                "ec2:StartInstances",
                "ec2:StopInstances"
            ],
            "Resource": [$(echo $RESOURCES | sed 's/,/","/g' | sed 's/^/"/' | sed 's/$/"/')],
            "Condition": {
                "StringEquals": {
                    "ec2:ResourceTag/Environment": ["development", "staging"]
                }
            }
        }
    ]
}
POLICY

# Create and attach policy
aws iam create-policy --policy-name "${ROLE_NAME}-minimal-policy" --policy-document file://minimal-policy.json
aws iam attach-role-policy --role-name "$ROLE_NAME" --policy-arn "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/${ROLE_NAME}-minimal-policy"

echo " Minimal policy created and attached to $ROLE_NAME"
EOF

# Remove dangerous permissions
aws iam detach-role-policy --role-name dangerous-role --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam delete-role-policy --role-name dangerous-role --policy-name DangerousInlinePolicy

# Implement permission boundaries
cat > permission-boundary.json << 'EOF'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        },
        {
            "Effect": "Deny",
            "Action": [
                "iam:CreateUser",
                "iam:CreateRole",
                "iam:AttachRolePolicy",
                "iam:AttachUserPolicy",
                "iam:PutRolePolicy",
                "iam:PutUserPolicy",
                "organizations:*",
                "account:*"
            ],
            "Resource": "*"
        }
    ]
}
EOF

aws iam create-policy --policy-name DeveloperBoundary --policy-document file://permission-boundary.json
aws iam put-user-permissions-boundary --user-name developer --permissions-boundary arn:aws:iam::ACCOUNT:policy/DeveloperBoundary
```

### Compromised Access Keys

#### Issue: AWS access keys exposed or compromised

**Symptoms:**
- Unusual API calls in CloudTrail
- Resources created in unexpected regions
- Cryptocurrency mining instances
- Large data transfer bills

**Diagnosis:**
```bash
# Detect compromised access keys
cat > detect-compromised-keys.sh << 'EOF'
#!/bin/bash
echo " AWS Access Key Compromise Detection "

# Check for unusual API activity
echo "1. Checking for unusual API calls in the last 24 hours:"
aws logs filter-log-events \
    --log-group-name CloudTrail/AccessKeyActivity \
    --start-time $(date -d '24 hours ago' +%s)000 \
    --filter-pattern '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "*AccessDenied*") }' \
    --query 'events[].{Time:eventTime,User:userIdentity.userName,Error:errorCode,Action:eventName}' \
    --output table

# Check for API calls from unusual locations
echo "2. API calls from unusual source IPs:"
aws logs filter-log-events \
    --log-group-name CloudTrail/APIActivity \
    --start-time $(date -d '7 days ago' +%s)000 \
    --filter-pattern '{ $.sourceIPAddress != "10.*" && $.sourceIPAddress != "172.*" && $.sourceIPAddress != "192.168.*" }' \
    --query 'events[].{Time:eventTime,SourceIP:sourceIPAddress,User:userIdentity.userName,Action:eventName}' \
    --output table

# Check for instances launched in unusual regions
echo "3. Resources in unusual regions:"
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
    instances=$(aws ec2 describe-instances --region "$region" --query 'Reservations[].Instances[?State.Name==`running`].InstanceId' --output text 2>/dev/null)
    if [ ! -z "$instances" ] && [ "$region" != "us-east-1" ] && [ "$region" != "us-west-2" ]; then
        echo "  Running instances in $region: $instances"
    fi
done

# Check for cryptocurrency mining indicators
echo "4. Potential cryptocurrency mining activity:"
aws ec2 describe-instances \
    --filters "Name=instance-state-name,Values=running" \
    --query 'Reservations[].Instances[?InstanceType!=`t2.micro` && InstanceType!=`t2.small`].{InstanceId:InstanceId,Type:InstanceType,LaunchTime:LaunchTime}' \
    --output table

# Check for large data transfers
echo "5. Unusual data transfer patterns:"
aws cloudwatch get-metric-statistics \
    --namespace AWS/EC2 \
    --metric-name NetworkOut \
    --start-time $(date -d '24 hours ago' -u +%Y-%m-%dT%H:%M:%SZ) \
    --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
    --period 3600 \
    --statistics Sum \
    --query 'Datapoints[?Sum > `1000000000`]'
EOF

chmod +x detect-compromised-keys.sh
./detect-compromised-keys.sh

# Check which resources were created by specific access keys
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA1234567890ABCDEF \
    --start-time $(date -d '30 days ago' -u +%Y-%m-%dT%H:%M:%SZ) \
    --query 'Events[].{Time:EventTime,Name:EventName,User:Username,Resources:Resources[0].ResourceName}' \
    --output table
```

**Immediate Response:**
```bash
# Emergency access key rotation
cat > emergency-key-rotation.sh << 'EOF'
#!/bin/bash
COMPROMISED_ACCESS_KEY=$1
USER_NAME=$2

if [ -z "$COMPROMISED_ACCESS_KEY" ] || [ -z "$USER_NAME" ]; then
    echo "Usage: $0 <access-key-id> <username>"
    exit 1
fi

echo " EMERGENCY ACCESS KEY ROTATION "
echo "Compromised Key: $COMPROMISED_ACCESS_KEY"
echo "User: $USER_NAME"
echo "Time: $(date)"

# Step 1: Immediately disable the compromised key
echo "Step 1: Disabling compromised access key..."
aws iam update-access-key --user-name "$USER_NAME" --access-key-id "$COMPROMISED_ACCESS_KEY" --status Inactive
echo " Access key disabled"

# Step 2: Check what the key was used for recently
echo "Step 2: Analyzing recent activity..."
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$COMPROMISED_ACCESS_KEY" \
    --start-time $(date -d '7 days ago' -u +%Y-%m-%dT%H:%M:%SZ) \
    --query 'Events[].{Time:EventTime,Name:EventName,Source:SourceIPAddress}' \
    --output table > compromised-activity.txt

echo "Recent activity saved to compromised-activity.txt"

# Step 3: Create new access key for user
echo "Step 3: Creating new access key..."
NEW_KEY=$(aws iam create-access-key --user-name "$USER_NAME" --output json)
echo " New access key created"
echo "$NEW_KEY" > new-access-key.json
echo " New credentials saved to new-access-key.json"

# Step 4: Check for malicious resources
echo "Step 4: Scanning for potentially malicious resources..."

# Check for instances in unusual regions
echo "Checking for instances in all regions..."
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
    instances=$(aws ec2 describe-instances --region "$region" --query 'Reservations[].Instances[?State.Name==`running`].{ID:InstanceId,Type:InstanceType,Launch:LaunchTime}' --output text 2>/dev/null)
    if [ ! -z "$instances" ]; then
        echo "Region $region: $instances" >> malicious-resources.txt
    fi
done

# Check for unusual S3 activity
echo "Checking S3 buckets..."
aws s3api list-buckets --query 'Buckets[?CreationDate>`2024-01-01`]' >> malicious-resources.txt

# Step 5: Clean up malicious resources (with confirmation)
echo "Step 5: Review malicious-resources.txt and clean up manually"
echo "WARNING: Automated cleanup not performed - requires manual review"

echo " EMERGENCY RESPONSE COMPLETE "
echo "1. Compromised key disabled"
echo "2. Activity analysis in compromised-activity.txt" 
echo "3. New key created in new-access-key.json"
echo "4. Potential malicious resources in malicious-resources.txt"
echo "5. Update applications with new credentials immediately"
echo "6. Delete old access key after confirming new one works"
EOF

chmod +x emergency-key-rotation.sh

# Run the emergency response
# ./emergency-key-rotation.sh AKIA1234567890ABCDEF compromised-user

# Set up automated alerting for future incidents
cat > setup-compromise-alerts.sh << 'EOF'
#!/bin/bash
# Create CloudWatch alarm for unusual API activity

aws logs put-metric-filter \
    --log-group-name CloudTrail/SecurityEvents \
    --filter-name CompromisedKeyDetector \
    --filter-pattern '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "*AccessDenied*") || ($.userIdentity.type = "IAMUser" && $.sourceIPAddress != "192.168.*" && $.sourceIPAddress != "10.*") }' \
    --metric-transformations \
        metricName=SuspiciousAPIActivity,metricNamespace=Security/AccessKeys,metricValue=1

aws cloudwatch put-metric-alarm \
    --alarm-name "CompromisedAccessKeyDetection" \
    --alarm-description "Detects potential access key compromise" \
    --metric-name SuspiciousAPIActivity \
    --namespace Security/AccessKeys \
    --statistic Sum \
    --period 300 \
    --threshold 5 \
    --comparison-operator GreaterThanThreshold \
    --evaluation-periods 1 \
    --alarm-actions "arn:aws:sns:us-east-1:ACCOUNT:security-alerts"
EOF
```

## VPC Security & Network Protection

### Security Group Misconfigurations

#### Issue: Overly permissive security groups

**Symptoms:**
- Security groups allowing 0.0.0.0/0 access
- Unnecessary ports open to the internet
- Management ports (SSH, RDP) exposed publicly

**Diagnosis:**
```bash
# Audit security group configurations
cat > sg-security-audit.sh << 'EOF'
#!/bin/bash
echo " Security Group Audit "

# Find security groups with 0.0.0.0/0 access
echo "1. Security groups allowing access from anywhere (0.0.0.0/0):"
aws ec2 describe-security-groups \
    --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].[GroupId,GroupName,IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]].[FromPort,ToPort,IpProtocol]]' \
    --output table

# Find management ports exposed to internet
echo "2. Management ports (SSH/RDP) exposed to internet:"
aws ec2 describe-security-groups \
    --query 'SecurityGroups[?IpPermissions[?(FromPort==`22` || FromPort==`3389`) && IpRanges[?CidrIp==`0.0.0.0/0`]]].[GroupId,GroupName]' \
    --output table

# Find security groups with wide port ranges
echo "3. Security groups with wide port ranges:"
aws ec2 describe-security-groups \
    --query 'SecurityGroups[?IpPermissions[?(ToPort-FromPort)>`100`]].[GroupId,GroupName,IpPermissions[?(ToPort-FromPort)>`100`].[FromPort,ToPort]]' \
    --output table

# Find unused security groups
echo "4. Unused security groups:"
aws ec2 describe-security-groups --query 'SecurityGroups[].GroupId' --output text | while read sg; do
    # Check if SG is attached to any instances
    attached=$(aws ec2 describe-instances --filters "Name=instance.group-id,Values=$sg" --query 'Reservations[].Instances[].InstanceId' --output text)
    # Check if SG is attached to any ENIs
    eni_attached=$(aws ec2 describe-network-interfaces --filters "Name=group-id,Values=$sg" --query 'NetworkInterfaces[].NetworkInterfaceId' --output text)
    
    if [ -z "$attached" ] && [ -z "$eni_attached" ]; then
        sg_name=$(aws ec2 describe-security-groups --group-ids "$sg" --query 'SecurityGroups[0].GroupName' --output text)
        echo " Unused security group: $sg ($sg_name)"
    fi
done

# Check for security groups allowing all protocols
echo "5. Security groups allowing all protocols (-1):"
aws ec2 describe-security-groups \
    --query 'SecurityGroups[?IpPermissions[?IpProtocol==`-1`]].[GroupId,GroupName]' \
    --output table
EOF

chmod +x sg-security-audit.sh
./sg-security-audit.sh
```

**Solution:**
```bash
# Create secure security group templates
cat > create-secure-sg.sh << 'EOF'
#!/bin/bash
VPC_ID=$1
SG_NAME=$2
SG_TYPE=$3

if [ -z "$VPC_ID" ] || [ -z "$SG_NAME" ] || [ -z "$SG_TYPE" ]; then
    echo "Usage: $0 <vpc-id> <sg-name> <type>"
    echo "Types: web, app, db, bastion"
    exit 1
fi

case $SG_TYPE in
    "web")
        # Web tier - only HTTP/HTTPS from internet
        aws ec2 create-security-group \
            --group-name "$SG_NAME" \
            --description "Secure web tier security group" \
            --vpc-id "$VPC_ID"
        
        SG_ID=$(aws ec2 describe-security-groups --filters "Name=group-name,Values=$SG_NAME" --query 'SecurityGroups[0].GroupId' --output text)
        
        # Allow HTTP from internet
        aws ec2 authorize-security-group-ingress \
            --group-id "$SG_ID" \
            --protocol tcp \
            --port 80 \
            --cidr 0.0.0.0/0
        
        # Allow HTTPS from internet  
        aws ec2 authorize-security-group-ingress \
            --group-id "$SG_ID" \
            --protocol tcp \
            --port 443 \
            --cidr 0.0.0.0/0
        ;;
        
    "app")
        # Application tier - only from web tier
        aws ec2 create-security-group \
            --group-name "$SG_NAME" \
            --description "Secure application tier security group" \
            --vpc-id "$VPC_ID"
        
        SG_ID=$(aws ec2 describe-security-groups --filters "Name=group-name,Values=$SG_NAME" --query 'SecurityGroups[0].GroupId' --output text)
        
        # Allow app port from web security group only
        WEB_SG_ID=$(aws ec2 describe-security-groups --filters "Name=group-name,Values=${SG_NAME}-web" --query 'SecurityGroups[0].GroupId' --output text)
        aws ec2 authorize-security-group-ingress \
            --group-id "$SG_ID" \
            --protocol tcp \
            --port 8080 \
            --source-group "$WEB_SG_ID"
        ;;
        
    "db")
        # Database tier - only from app tier
        aws ec2 create-security-group \
            --group-name "$SG_NAME" \
            --description "Secure database tier security group" \
            --vpc-id "$VPC_ID"
        
        SG_ID=$(aws ec2 describe-security-groups --filters "Name=group-name,Values=$SG_NAME" --query 'SecurityGroups[0].GroupId' --output text)
        
        # Allow database port from app security group only
        APP_SG_ID=$(aws ec2 describe-security-groups --filters "Name=group-name,Values=${SG_NAME}-app" --query 'SecurityGroups[0].GroupId' --output text)
        aws ec2 authorize-security-group-ingress \
            --group-id "$SG_ID" \
            --protocol tcp \
            --port 5432 \
            --source-group "$APP_SG_ID"
        ;;
        
    "bastion")
        # Bastion host - SSH from specific IP only
        read -p "Enter your IP address (x.x.x.x): " MY_IP
        
        aws ec2 create-security-group \
            --group-name "$SG_NAME" \
            --description "Secure bastion host security group" \
            --vpc-id "$VPC_ID"
        
        SG_ID=$(aws ec2 describe-security-groups --filters "Name=group-name,Values=$SG_NAME" --query 'SecurityGroups[0].GroupId' --output text)
        
        # Allow SSH from specific IP only
        aws ec2 authorize-security-group-ingress \
            --group-id "$SG_ID" \
            --protocol tcp \
            --port 22 \
            --cidr "$MY_IP/32"
        ;;
esac

echo " Secure security group $SG_NAME created with ID: $SG_ID"
EOF

# Fix overly permissive security groups
cat > fix-permissive-sg.sh << 'EOF'
#!/bin/bash
echo " Fixing Overly Permissive Security Groups "

# Get all security groups with 0.0.0.0/0 access
aws ec2 describe-security-groups \
    --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].[GroupId]' \
    --output text | while read sg_id; do
    
    if [ -z "$sg_id" ]; then continue; fi
    
    echo "Reviewing security group: $sg_id"
    
    # Get the permissive rules
    aws ec2 describe-security-groups --group-ids "$sg_id" \
        --query 'SecurityGroups[0].IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]' > /tmp/permissive-rules.json
    
    # Display rules for review
    echo "Current permissive rules:"
    cat /tmp/permissive-rules.json | jq -r '.[] | "Port \(.FromPort)-\(.ToPort) Protocol \(.IpProtocol)"'
    
    read -p "Remove 0.0.0.0/0 access from $sg_id? (y/N): " confirm
    if [ "$confirm" = "y" ]; then
        # Remove permissive ingress rules
        cat /tmp/permissive-rules.json | jq -c '.[]' | while read rule; do
            aws ec2 revoke-security-group-ingress \
                --group-id "$sg_id" \
                --ip-permissions "$rule"
            echo " Removed permissive rule from $sg_id"
        done
    fi
done
EOF
```

## S3 Security Misconfigurations

### Public S3 Buckets

#### Issue: S3 buckets exposed to public access

**Diagnosis:**
```bash
# S3 security audit
cat > s3-security-audit.sh << 'EOF'
#!/bin/bash
echo " S3 Security Audit "

# Find all S3 buckets
echo "1. Scanning all S3 buckets for security issues..."
aws s3api list-buckets --query 'Buckets[].Name' --output text | while read bucket; do
    echo "Auditing bucket: $bucket"
    
    # Check public access block settings
    echo "  Public Access Block:"
    aws s3api get-public-access-block --bucket "$bucket" 2>/dev/null || echo "      No public access block configured"
    
    # Check bucket policy for public access
    echo "  Bucket Policy:"
    bucket_policy=$(aws s3api get-bucket-policy --bucket "$bucket" --query 'Policy' --output text 2>/dev/null)
    if [ "$bucket_policy" != "None" ] && [ ! -z "$bucket_policy" ]; then
        if echo "$bucket_policy" | jq -e '.Statement[] | select(.Principal == "*" or .Principal.AWS == "*")' >/dev/null 2>&1; then
            echo "      Bucket has public policy"
        fi
    fi
    
    # Check ACL for public access
    echo "  ACL Settings:"
    public_acl=$(aws s3api get-bucket-acl --bucket "$bucket" --query 'Grants[?Grantee.URI==`http://acs.amazonaws.com/groups/global/AllUsers` || Grantee.URI==`http://acs.amazonaws.com/groups/global/AuthenticatedUsers`]' --output text)
    if [ ! -z "$public_acl" ]; then
        echo "      Bucket has public ACL"
    fi
    
    # Check encryption
    echo "  Encryption:"
    encryption=$(aws s3api get-bucket-encryption --bucket "$bucket" --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' --output text 2>/dev/null)
    if [ "$encryption" = "None" ] || [ -z "$encryption" ]; then
        echo "      Bucket not encrypted"
    else
        echo "     Encrypted with $encryption"
    fi
    
    # Check versioning
    echo "  Versioning:"
    versioning=$(aws s3api get-bucket-versioning --bucket "$bucket" --query 'Status' --output text)
    if [ "$versioning" != "Enabled" ]; then
        echo "      Versioning not enabled"
    else
        echo "     Versioning enabled"
    fi
    
    # Check logging
    echo "  Access Logging:"
    logging=$(aws s3api get-bucket-logging --bucket "$bucket" --query 'LoggingEnabled.TargetBucket' --output text 2>/dev/null)
    if [ "$logging" = "None" ] || [ -z "$logging" ]; then
        echo "      Access logging not configured"
    else
        echo "     Logging to $logging"
    fi
    
    echo ""
done

# Find potentially sensitive files
echo "2. Scanning for potentially sensitive files..."
aws s3api list-buckets --query 'Buckets[].Name' --output text | while read bucket; do
    sensitive_files=$(aws s3 ls s3://"$bucket" --recursive | grep -iE "\.(key|pem|p12|pfx|sql|dump|backup|config|env)$" | head -5)
    if [ ! -z "$sensitive_files" ]; then
        echo "  Potentially sensitive files in $bucket:"
        echo "$sensitive_files"
    fi
done
EOF

chmod +x s3-security-audit.sh
./s3-security-audit.sh
```

**Solution:**
```bash
# Secure S3 bucket configuration
cat > secure-s3-bucket.sh << 'EOF'
#!/bin/bash
BUCKET_NAME=$1

if [ -z "$BUCKET_NAME" ]; then
    echo "Usage: $0 <bucket-name>"
    exit 1
fi

echo " Securing S3 Bucket: $BUCKET_NAME "

# Enable public access block
echo "1. Enabling public access block..."
aws s3api put-public-access-block \
    --bucket "$BUCKET_NAME" \
    --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Enable default encryption
echo "2. Enabling default encryption..."
cat > bucket-encryption.json << ENC
{
    "Rules": [
        {
            "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "AES256"
            },
            "BucketKeyEnabled": true
        }
    ]
}
ENC

aws s3api put-bucket-encryption \
    --bucket "$BUCKET_NAME" \
    --server-side-encryption-configuration file://bucket-encryption.json

# Enable versioning
echo "3. Enabling versioning..."
aws s3api put-bucket-versioning \
    --bucket "$BUCKET_NAME" \
    --versioning-configuration Status=Enabled

# Configure lifecycle policy for cost optimization
echo "4. Setting up lifecycle policy..."
cat > lifecycle-policy.json << LIFECYCLE
{
    "Rules": [
        {
            "ID": "DeleteOldVersions",
            "Status": "Enabled",
            "Filter": {},
            "NoncurrentVersionExpiration": {
                "NoncurrentDays": 90
            }
        },
        {
            "ID": "TransitionToIA",
            "Status": "Enabled",
            "Filter": {},
            "Transitions": [
                {
                    "Days": 30,
                    "StorageClass": "STANDARD_IA"
                },
                {
                    "Days": 90,
                    "StorageClass": "GLACIER"
                }
            ]
        }
    ]
}
LIFECYCLE

aws s3api put-bucket-lifecycle-configuration \
    --bucket "$BUCKET_NAME" \
    --lifecycle-configuration file://lifecycle-policy.json

# Set up secure bucket policy
echo "5. Applying secure bucket policy..."
cat > secure-bucket-policy.json << POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyUnSecureCommunications",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [
                "arn:aws:s3:::${BUCKET_NAME}",
                "arn:aws:s3:::${BUCKET_NAME}/*"
            ],
            "Condition": {
                "Bool": {
                    "aws:SecureTransport": "false"
                }
            }
        },
        {
            "Sid": "DenyUnencryptedUploads",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::${BUCKET_NAME}/*",
            "Condition": {
                "StringNotEquals": {
                    "s3:x-amz-server-side-encryption": "AES256"
                }
            }
        }
    ]
}
POLICY

aws s3api put-bucket-policy \
    --bucket "$BUCKET_NAME" \
    --policy file://secure-bucket-policy.json

# Enable access logging
echo "6. Enabling access logging..."
LOGGING_BUCKET="${BUCKET_NAME}-access-logs"
aws s3 mb s3://"$LOGGING_BUCKET" 2>/dev/null || true

cat > bucket-logging.json << LOGGING
{
    "LoggingEnabled": {
        "TargetBucket": "${LOGGING_BUCKET}",
        "TargetPrefix": "${BUCKET_NAME}-access-logs/"
    }
}
LOGGING

aws s3api put-bucket-logging \
    --bucket "$BUCKET_NAME" \
    --bucket-logging-status file://bucket-logging.json

# Enable MFA delete (requires root user)
echo "7. Note: Enable MFA delete using root credentials:"
echo "   aws s3api put-bucket-versioning --bucket $BUCKET_NAME --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa 'SERIAL TOKEN'"

echo " S3 bucket $BUCKET_NAME secured"

# Cleanup temp files
rm -f bucket-encryption.json lifecycle-policy.json secure-bucket-policy.json bucket-logging.json
EOF

chmod +x secure-s3-bucket.sh

# Emergency response for exposed buckets
cat > emergency-s3-response.sh << 'EOF'
#!/bin/bash
BUCKET_NAME=$1

if [ -z "$BUCKET_NAME" ]; then
    echo "Usage: $0 <exposed-bucket-name>"
    exit 1
fi

echo "= EMERGENCY S3 BREACH RESPONSE "
echo "Bucket: $BUCKET_NAME"
echo "Time: $(date)"

# Immediately block all public access
echo "1. Immediately blocking all public access..."
aws s3api put-public-access-block \
    --bucket "$BUCKET_NAME" \
    --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Remove any public bucket policy
echo "2. Removing public bucket policies..."
aws s3api delete-bucket-policy --bucket "$BUCKET_NAME" 2>/dev/null || echo "No bucket policy to remove"

# Check access logs for unauthorized access
echo "3. Checking access logs for unauthorized access..."
LOGGING_BUCKET=$(aws s3api get-bucket-logging --bucket "$BUCKET_NAME" --query 'LoggingEnabled.TargetBucket' --output text 2>/dev/null)
if [ "$LOGGING_BUCKET" != "None" ] && [ ! -z "$LOGGING_BUCKET" ]; then
    echo "Access logs available in: $LOGGING_BUCKET"
    # Download recent logs for analysis
    aws s3 cp s3://"$LOGGING_BUCKET"/ ./access-logs/ --recursive --exclude "*" --include "*$(date +%Y-%m-%d)*"
else
    echo "  No access logs configured - cannot determine who accessed the bucket"
fi

# Generate incident report
cat > s3-breach-report.md << REPORT
# S3 Security Incident Report

**Bucket:** $BUCKET_NAME
**Date:** $(date)
**Handler:** $(aws sts get-caller-identity --query Arn --output text)

## Incident Summary
- S3 bucket was exposed to public access
- Immediate containment: Public access blocked
- Investigation: Access logs being analyzed

## Actions Taken
- [x] Public access blocked immediately
- [x] Bucket policy removed
- [x] Access logs collected (if available)

## Evidence
- Access logs: ./access-logs/ (if logging was enabled)
- Bucket configuration at time of incident: saved below

## Next Steps
1. [ ] Analyze access logs for unauthorized downloads
2. [ ] Determine what data was exposed
3. [ ] Notify stakeholders if sensitive data was accessed
4. [ ] Review and update bucket security policies
5. [ ] Implement monitoring for future exposure

## Bucket Configuration at Time of Incident
$(aws s3api get-bucket-location --bucket $BUCKET_NAME)
$(aws s3api get-bucket-acl --bucket $BUCKET_NAME)
$(aws s3api get-public-access-block --bucket $BUCKET_NAME 2>/dev/null || echo "No public access block was configured")

REPORT

echo " Emergency containment complete"
echo " Incident report: s3-breach-report.md"
echo " Next: Analyze access logs and determine data exposure"
EOF

chmod +x emergency-s3-response.sh
```

## EKS Security

### EKS Cluster Security Issues

#### Issue: EKS cluster with security misconfigurations

**Symptoms:**
- Publicly accessible EKS API server
- Overprivileged node groups
- Missing security controls

**Diagnosis:**
```bash
# EKS cluster security assessment
cat > eks-security-audit.sh << 'EOF'
#!/bin/bash
CLUSTER_NAME=$1

if [ -z "$CLUSTER_NAME" ]; then
    echo "Usage: $0 <cluster-name>"
    exit 1
fi

echo " EKS Security Audit: $CLUSTER_NAME "

# Check cluster configuration
aws eks describe-cluster --name "$CLUSTER_NAME" > eks-cluster-config.json

# Check API server endpoint access
ENDPOINT_ACCESS=$(jq -r '.cluster.resourcesVpcConfig.endpointConfigTypes.privateAccess' eks-cluster-config.json)
PUBLIC_ACCESS=$(jq -r '.cluster.resourcesVpcConfig.endpointConfigTypes.publicAccess' eks-cluster-config.json)

echo "API Server Access:"
echo "  Private: $ENDPOINT_ACCESS"
echo "  Public: $PUBLIC_ACCESS"

if [ "$PUBLIC_ACCESS" = "true" ]; then
    echo "  Public API access enabled"
    PUBLIC_CIDRS=$(jq -r '.cluster.resourcesVpcConfig.publicAccessCidrs[]' eks-cluster-config.json)
    echo "  Allowed CIDRs: $PUBLIC_CIDRS"
fi

# Check node groups
aws eks list-nodegroups --cluster-name "$CLUSTER_NAME" --query 'nodegroups' --output text | while read nodegroup; do
    echo "Nodegroup: $nodegroup"
    
    # Check node group configuration
    aws eks describe-nodegroup --cluster-name "$CLUSTER_NAME" --nodegroup-name "$nodegroup" > "nodegroup-${nodegroup}.json"
    
    # Check instance types
    INSTANCE_TYPES=$(jq -r '.nodegroup.instanceTypes[]' "nodegroup-${nodegroup}.json")
    echo "  Instance types: $INSTANCE_TYPES"
    
    # Check AMI type
    AMI_TYPE=$(jq -r '.nodegroup.amiType' "nodegroup-${nodegroup}.json")
    echo "  AMI type: $AMI_TYPE"
    
    # Check if nodes are in public subnets
    SUBNETS=$(jq -r '.nodegroup.subnets[]' "nodegroup-${nodegroup}.json")
    echo "  Subnets: $SUBNETS"
    
    # Check remote access
    REMOTE_ACCESS=$(jq -r '.nodegroup.remoteAccess' "nodegroup-${nodegroup}.json")
    if [ "$REMOTE_ACCESS" != "null" ]; then
        echo "  Remote access configured"
        echo "  $REMOTE_ACCESS"
    fi
done

# Check cluster logging
LOGGING=$(jq -r '.cluster.logging.clusterLogging[]' eks-cluster-config.json)
echo "Cluster logging:"
echo "$LOGGING"

# Check encryption
ENCRYPTION=$(jq -r '.cluster.encryptionConfig' eks-cluster-config.json)
if [ "$ENCRYPTION" = "null" ]; then
    echo "  Encryption at rest not configured"
else
    echo "Encryption: $ENCRYPTION"
fi

# Check security groups
SECURITY_GROUPS=$(jq -r '.cluster.resourcesVpcConfig.securityGroupIds[]' eks-cluster-config.json)
echo "Security groups: $SECURITY_GROUPS"

for sg in $SECURITY_GROUPS; do
    echo "Analyzing security group: $sg"
    aws ec2 describe-security-groups --group-ids "$sg" --query 'SecurityGroups[0].IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]' --output table
done
EOF

chmod +x eks-security-audit.sh
```

**Solution:**
```bash
# Secure EKS cluster configuration
cat > secure-eks-cluster.sh << 'EOF'
#!/bin/bash
CLUSTER_NAME=$1

if [ -z "$CLUSTER_NAME" ]; then
    echo "Usage: $0 <cluster-name>"
    exit 1
fi

echo " Securing EKS Cluster: $CLUSTER_NAME "

# Enable private endpoint access and restrict public access
echo "1. Configuring API server endpoint access..."
aws eks update-cluster-config \
    --name "$CLUSTER_NAME" \
    --resources-vpc-config \
    endpointConfigTypes='{privateAccess=true,publicAccess=false}'

# Enable comprehensive logging
echo "2. Enabling cluster logging..."
aws eks update-cluster-config \
    --name "$CLUSTER_NAME" \
    --logging '{"clusterLogging":[{"types":["api","audit","authenticator","controllerManager","scheduler"],"enabled":true}]}'

# Update cluster security group rules
echo "3. Updating security group rules..."
CLUSTER_SG=$(aws eks describe-cluster --name "$CLUSTER_NAME" --query 'cluster.resourcesVpcConfig.clusterSecurityGroupId' --output text)

# Remove overly permissive rules
aws ec2 revoke-security-group-ingress \
    --group-id "$CLUSTER_SG" \
    --protocol -1 \
    --cidr 0.0.0.0/0 2>/dev/null || true

# Add specific required rules
aws ec2 authorize-security-group-ingress \
    --group-id "$CLUSTER_SG" \
    --protocol tcp \
    --port 443 \
    --source-group "$CLUSTER_SG"

echo " EKS cluster security configuration updated"
EOF

chmod +x secure-eks-cluster.sh
```

## Lambda Security

### Lambda Function Security Issues

#### Issue: Lambda functions with security vulnerabilities

**Symptoms:**
- Functions with excessive permissions
- Unencrypted environment variables
- Public function URLs

**Diagnosis:**
```bash
# Lambda security assessment
cat > lambda-security-audit.sh << 'EOF'
#!/bin/bash
echo " Lambda Security Audit "

# List all Lambda functions
aws lambda list-functions --query 'Functions[].FunctionName' --output text | while read function; do
    echo "Function: $function"
    
    # Get function configuration
    aws lambda get-function-configuration --function-name "$function" > "lambda-${function}.json"
    
    # Check execution role
    ROLE=$(jq -r '.Role' "lambda-${function}.json")
    echo "  Role: $ROLE"
    
    # Check environment variables
    ENV_VARS=$(jq -r '.Environment.Variables' "lambda-${function}.json")
    if [ "$ENV_VARS" != "null" ]; then
        echo "  Environment variables present"
        # Check for KMS encryption
        KMS_KEY=$(jq -r '.KMSKeyArn' "lambda-${function}.json")
        if [ "$KMS_KEY" = "null" ]; then
            echo "    Environment variables not encrypted"
        else
            echo "  KMS Key: $KMS_KEY"
        fi
    fi
    
    # Check VPC configuration
    VPC_CONFIG=$(jq -r '.VpcConfig' "lambda-${function}.json")
    if [ "$VPC_CONFIG" = "null" ]; then
        echo "    No VPC configuration (internet access)"
    else
        echo "  VPC configured"
    fi
    
    # Check for public function URLs
    FUNCTION_URL=$(aws lambda get-function-url-config --function-name "$function" 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo "    Public function URL configured"
        echo "  $FUNCTION_URL"
    fi
    
    # Check reserved concurrency
    CONCURRENCY=$(jq -r '.ReservedConcurrencyExecutions' "lambda-${function}.json")
    if [ "$CONCURRENCY" = "null" ]; then
        echo "    No reserved concurrency (DoS risk)"
    fi
    
    echo ""
done

# Check IAM policies for Lambda roles
echo "Checking Lambda role permissions..."
aws iam list-roles --query 'Roles[?contains(RoleName, `lambda`)].RoleName' --output text | while read role; do
    echo "Role: $role"
    aws iam list-attached-role-policies --role-name "$role" --query 'AttachedPolicies[].PolicyName' --output text
done
EOF

chmod +x lambda-security-audit.sh
```

**Solution:**
```bash
# Secure Lambda function configuration
cat > secure-lambda-function.sh << 'EOF'
#!/bin/bash
FUNCTION_NAME=$1

if [ -z "$FUNCTION_NAME" ]; then
    echo "Usage: $0 <function-name>"
    exit 1
fi

echo " Securing Lambda Function: $FUNCTION_NAME "

# Create KMS key for encryption
KMS_KEY=$(aws kms create-key --description "Lambda encryption key" --query 'KeyMetadata.KeyId' --output text)
echo "Created KMS key: $KMS_KEY"

# Update function configuration for security
aws lambda update-function-configuration \
    --function-name "$FUNCTION_NAME" \
    --kms-key-arn "arn:aws:kms:$(aws configure get region):$(aws sts get-caller-identity --query Account --output text):key/$KMS_KEY" \
    --reserved-concurrent-executions 100 \
    --dead-letter-config TargetArn=arn:aws:sqs:$(aws configure get region):$(aws sts get-caller-identity --query Account --output text):lambda-dlq

# Create minimal IAM role for Lambda
cat > lambda-role-policy.json << POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "arn:aws:logs:*:*:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "kms:Decrypt"
            ],
            "Resource": "arn:aws:kms:*:*:key/$KMS_KEY"
        }
    ]
}
POLICY

aws iam create-role \
    --role-name "${FUNCTION_NAME}-execution-role" \
    --assume-role-policy-document '{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }'

aws iam put-role-policy \
    --role-name "${FUNCTION_NAME}-execution-role" \
    --policy-name "${FUNCTION_NAME}-policy" \
    --policy-document file://lambda-role-policy.json

# Update function to use secure role
aws lambda update-function-configuration \
    --function-name "$FUNCTION_NAME" \
    --role "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):role/${FUNCTION_NAME}-execution-role"

echo " Lambda function security configuration updated"
EOF

chmod +x secure-lambda-function.sh
```

## CloudTrail & Logging

### CloudTrail Security Issues

#### Issue: Inadequate logging and monitoring

**Symptoms:**
- CloudTrail disabled or misconfigured
- Log files publicly accessible
- No integrity monitoring

**Diagnosis:**
```bash
# CloudTrail security assessment
cat > cloudtrail-audit.sh << 'EOF'
#!/bin/bash
echo " CloudTrail Security Audit "

# List all trails
aws cloudtrail describe-trails --query 'trailList' --output json > cloudtrail-config.json

# Check each trail
jq -r '.[] | .Name' cloudtrail-config.json | while read trail; do
    echo "Trail: $trail"
    
    # Check if trail is logging
    STATUS=$(aws cloudtrail get-trail-status --name "$trail" --query 'IsLogging' --output text)
    echo "  Logging: $STATUS"
    
    # Check S3 bucket
    S3_BUCKET=$(jq -r --arg trail "$trail" '.[] | select(.Name==$trail) | .S3BucketName' cloudtrail-config.json)
    echo "  S3 Bucket: $S3_BUCKET"
    
    # Check if S3 bucket is public
    aws s3api get-bucket-acl --bucket "$S3_BUCKET" --query 'Grants[?Grantee.URI==`http://acs.amazonaws.com/groups/global/AllUsers`]' --output text
    if [ $? -eq 0 ]; then
        echo "    S3 bucket may be publicly accessible"
    fi
    
    # Check encryption
    KMS_KEY=$(jq -r --arg trail "$trail" '.[] | select(.Name==$trail) | .KMSKeyId' cloudtrail-config.json)
    if [ "$KMS_KEY" = "null" ]; then
        echo "    Log files not encrypted"
    else
        echo "  KMS Key: $KMS_KEY"
    fi
    
    # Check log file validation
    LOG_VALIDATION=$(jq -r --arg trail "$trail" '.[] | select(.Name==$trail) | .LogFileValidationEnabled' cloudtrail-config.json)
    if [ "$LOG_VALIDATION" = "false" ]; then
        echo "    Log file validation disabled"
    fi
    
    echo ""
done

# Check CloudWatch integration
echo "Checking CloudWatch integration..."
jq -r '.[] | select(.CloudWatchLogsLogGroupArn) | .Name' cloudtrail-config.json | while read trail; do
    echo "Trail $trail has CloudWatch integration"
done
EOF

chmod +x cloudtrail-audit.sh
```

## Security Services

### AWS Security Hub Issues

#### Issue: Security Hub not configured or missing findings

**Diagnosis:**
```bash
# Security Hub assessment
cat > security-hub-audit.sh << 'EOF'
#!/bin/bash
echo " Security Hub Assessment "

# Check if Security Hub is enabled
HUB_STATUS=$(aws securityhub get-enabled-standards --query 'StandardsSubscriptions[0].StandardsStatus' --output text 2>/dev/null)

if [ "$HUB_STATUS" = "READY" ]; then
    echo "Security Hub is enabled"
    
    # Get findings summary
    aws securityhub get-findings --query 'Findings[].{Id:Id,Title:Title,Severity:Severity.Label}' --output table
    
    # Check compliance scores
    aws securityhub get-compliance-details-by-config-rule --config-rule-name securityhub-* --query 'EvaluationResults[].ComplianceType' --output text | sort | uniq -c
    
else
    echo "  Security Hub is not enabled"
fi

# Check GuardDuty
GUARDDUTY_STATUS=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text 2>/dev/null)

if [ "$GUARDDUTY_STATUS" != "None" ]; then
    echo "GuardDuty detector: $GUARDDUTY_STATUS"
    
    # Check GuardDuty findings
    aws guardduty get-findings --detector-id "$GUARDDUTY_STATUS" --finding-ids $(aws guardduty list-findings --detector-id "$GUARDDUTY_STATUS" --query 'FindingIds[0]' --output text) --query 'Findings[0].{Type:Type,Severity:Severity}' --output table 2>/dev/null
    
else
    echo "  GuardDuty is not enabled"
fi
EOF

chmod +x security-hub-audit.sh
```

## Incident Response

### AWS Incident Response Procedures

#### Emergency response for AWS security incidents

```bash
# AWS incident response script
cat > aws-incident-response.sh << 'EOF'
#!/bin/bash
INCIDENT_TYPE=$1
AFFECTED_RESOURCE=$2
CASE_ID=${3:-"AWS-$(date +%Y%m%d-%H%M%S)"}

if [ -z "$INCIDENT_TYPE" ] || [ -z "$AFFECTED_RESOURCE" ]; then
    echo "Usage: $0 <incident-type> <affected-resource> [case-id]"
    echo "Types: credential-compromise, data-breach, unauthorized-access, malware"
    exit 1
fi

echo " AWS SECURITY INCIDENT RESPONSE "
echo "Incident Type: $INCIDENT_TYPE"
echo "Affected Resource: $AFFECTED_RESOURCE"
echo "Case ID: $CASE_ID"
echo "Time: $(date)"

# Create incident directory
INCIDENT_DIR="aws-incident-${CASE_ID}"
mkdir -p "$INCIDENT_DIR"/{evidence,actions,communications}

case $INCIDENT_TYPE in
    "credential-compromise")
        echo "1. Immediate containment - disabling credentials..."
        
        # If it's an access key
        if [[ $AFFECTED_RESOURCE =~ ^AKIA ]]; then
            # Find the user associated with this access key
            USER_NAME=$(aws iam list-users --query "Users[?AccessKeyId=='$AFFECTED_RESOURCE'].UserName" --output text)
            if [ ! -z "$USER_NAME" ]; then
                # Disable the access key
                aws iam update-access-key --user-name "$USER_NAME" --access-key-id "$AFFECTED_RESOURCE" --status Inactive
                echo " Access key $AFFECTED_RESOURCE disabled"
                
                # Log recent activities
                aws cloudtrail lookup-events \
                    --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$AFFECTED_RESOURCE" \
                    --start-time $(date -d '24 hours ago' -u +%Y-%m-%dT%H:%M:%SZ) \
                    --output json > "$INCIDENT_DIR/evidence/access-key-activity.json"
            fi
        fi
        
        # If it's a role
        if [[ $AFFECTED_RESOURCE =~ ^arn:aws:iam ]]; then
            # Attach deny policy to role
            aws iam attach-role-policy \
                --role-name "$(basename "$AFFECTED_RESOURCE")" \
                --policy-arn arn:aws:iam::aws:policy/AWSDenyAll
            echo " Role $AFFECTED_RESOURCE access denied"
        fi
        ;;
        
    "data-breach")
        echo "1. Immediate containment - securing data..."
        
        # If it's an S3 bucket
        if [[ $AFFECTED_RESOURCE =~ ^s3:// ]]; then
            BUCKET_NAME=$(echo "$AFFECTED_RESOURCE" | sed 's|s3://||')
            
            # Block public access immediately
            aws s3api put-public-access-block \
                --bucket "$BUCKET_NAME" \
                --public-access-block-configuration \
                "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
            echo " S3 bucket $BUCKET_NAME public access blocked"
            
            # Collect access logs
            aws s3api get-bucket-logging --bucket "$BUCKET_NAME" > "$INCIDENT_DIR/evidence/s3-logging-config.json"
        fi
        ;;
        
    "unauthorized-access")
        echo "1. Immediate containment - blocking access..."
        
        # Create IP-based block if IP is known
        read -p "Enter suspicious IP address (or press Enter to skip): " SUSPICIOUS_IP
        if [ ! -z "$SUSPICIOUS_IP" ]; then
            # Create WAF rule to block IP
            aws wafv2 create-ip-set \
                --name "incident-${CASE_ID}-blocked-ips" \
                --scope REGIONAL \
                --ip-address-version IPV4 \
                --addresses "$SUSPICIOUS_IP/32" > "$INCIDENT_DIR/actions/waf-ip-block.json"
            echo " IP $SUSPICIOUS_IP blocked via WAF"
        fi
        ;;
esac

# Collect general evidence
echo "2. Collecting evidence..."

# CloudTrail logs
aws cloudtrail lookup-events \
    --start-time $(date -d '6 hours ago' -u +%Y-%m-%dT%H:%M:%SZ) \
    --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
    --output json > "$INCIDENT_DIR/evidence/cloudtrail-recent.json"

# VPC Flow Logs (if enabled)
aws ec2 describe-flow-logs --query 'FlowLogs[?FlowLogStatus==`ACTIVE`].FlowLogId' --output text | while read flow_log; do
    echo "Flow log: $flow_log" >> "$INCIDENT_DIR/evidence/vpc-flow-logs.txt"
done

# GuardDuty findings
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text 2>/dev/null)
if [ "$DETECTOR_ID" != "None" ]; then
    aws guardduty list-findings --detector-id "$DETECTOR_ID" --output json > "$INCIDENT_DIR/evidence/guardduty-findings.json"
fi

# Generate incident report
cat > "$INCIDENT_DIR/incident-report.md" << REPORT
# AWS Security Incident Report

**Incident ID:** $CASE_ID
**Type:** $INCIDENT_TYPE
**Affected Resource:** $AFFECTED_RESOURCE
**Date:** $(date)
**Handler:** $(aws sts get-caller-identity --query Arn --output text)

## Incident Timeline
- $(date): Incident detected and response initiated
- $(date): Containment measures implemented
- $(date): Evidence collection started

## Actions Taken
- [x] Immediate containment measures applied
- [x] Evidence collection initiated
- [x] AWS resources secured

## Evidence Collected
- CloudTrail logs: evidence/cloudtrail-recent.json
- GuardDuty findings: evidence/guardduty-findings.json
- Resource-specific evidence: evidence/

## Next Steps
1. [ ] Complete forensic analysis
2. [ ] Determine full scope of impact
3. [ ] Implement additional security measures
4. [ ] Update security policies
5. [ ] Communication to stakeholders

## Recommendations
- Review IAM permissions and implement least privilege
- Enable comprehensive logging across all services
- Implement automated threat detection
- Regular security assessments and training

REPORT

echo " AWS incident response completed"
echo " Evidence location: $INCIDENT_DIR"
echo " Incident report: $INCIDENT_DIR/incident-report.md"
EOF

chmod +x aws-incident-response.sh
```