# Terraform Security Troubleshooting Guide

This guide helps you identify and resolve security issues in Terraform infrastructure code and deployments.

## State File Security

### Issue: Terraform state files containing sensitive data

**Symptoms:**
- State files stored locally or in version control
- Unencrypted state files
- Shared state files without access controls

**Diagnosis:**
```bash
# Check for state files in version control
cat > check-state-security.sh << 'EOF'
#!/bin/bash
echo " Terraform State Security Check "

# Check for state files in git
echo "1. Checking for state files in version control:"
find . -name "*.tfstate*" -exec git ls-files {} \; 2>/dev/null | while read file; do
    if [ ! -z "$file" ]; then
        echo "  State file in version control: $file"
    fi
done

# Check for secrets in state files
echo "2. Scanning state files for potential secrets:"
find . -name "*.tfstate*" -type f | while read statefile; do
    if [ -f "$statefile" ]; then
        echo "Checking $statefile:"
        
        # Check for common secret patterns
        grep -i "password\|secret\|key\|token" "$statefile" | head -5 | while read line; do
            echo "    Potential secret: $(echo "$line" | cut -c1-80)..."
        done
        
        # Check for private keys
        if grep -q "BEGIN.*PRIVATE KEY" "$statefile"; then
            echo "    Private key found in state file"
        fi
    fi
done

# Check backend configuration
echo "3. Checking backend configuration:"
find . -name "*.tf" -exec grep -l "backend" {} \; | while read file; do
    echo "Backend config in $file:"
    grep -A 10 "backend" "$file" | while read line; do
        if echo "$line" | grep -q "encrypt.*false"; then
            echo "    Backend encryption disabled"
        fi
    done
done
EOF

chmod +x check-state-security.sh
./check-state-security.sh
```

**Solution:**
```bash
# Secure state file management
cat > secure-terraform-state.sh << 'EOF'
#!/bin/bash
echo " Securing Terraform State "

# Create secure S3 backend configuration
cat > backend.tf << 'BACKEND'
terraform {
  backend "s3" {
    bucket         = "terraform-state-secure-${random_string.bucket_suffix.result}"
    key            = "terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    kms_key_id     = aws_kms_key.terraform_state.arn
    dynamodb_table = "terraform-state-lock"
    
    # Enable versioning and MFA delete
    versioning = true
    
    # Access logging
    logging = {
      target_bucket = "terraform-state-logs-${random_string.bucket_suffix.result}"
    }
  }
}

# KMS key for state encryption
resource "aws_kms_key" "terraform_state" {
  description             = "KMS key for Terraform state encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow Terraform"
        Effect = "Allow"
        Principal = {
          AWS = data.aws_caller_identity.current.arn
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:ReEncrypt*"
        ]
        Resource = "*"
      }
    ]
  })
}

# S3 bucket for state with security controls
resource "aws_s3_bucket" "terraform_state" {
  bucket = "terraform-state-secure-${random_string.bucket_suffix.result}"
  
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.terraform_state.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  versioning_configuration {
    status = "Enabled"
  }
}

# DynamoDB table for state locking
resource "aws_dynamodb_table" "terraform_state_lock" {
  name           = "terraform-state-lock"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }
}

resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

data "aws_caller_identity" "current" {}
BACKEND

# Initialize with new backend
terraform init -migrate-state

# Add .tfstate files to .gitignore
echo "# Terraform state files" >> .gitignore
echo "*.tfstate" >> .gitignore
echo "*.tfstate.*" >> .gitignore
echo ".terraform/" >> .gitignore
echo ".terraform.lock.hcl" >> .gitignore

echo " Terraform state security configured"
EOF

chmod +x secure-terraform-state.sh
```

## Secrets Management

### Issue: Hardcoded secrets in Terraform files

**Symptoms:**
- Passwords and API keys in .tf files
- Secrets in version control
- Plaintext sensitive values

**Diagnosis:**
```bash
# Scan for hardcoded secrets
cat > scan-terraform-secrets.sh << 'EOF'
#!/bin/bash
echo " Terraform Secrets Scan "

# Scan for common secret patterns
echo "1. Scanning for hardcoded secrets:"
find . -name "*.tf" -o -name "*.tfvars" | while read file; do
    echo "Scanning $file:"
    
    # Check for common secret patterns
    grep -n -i "password\s*=\s*[\"'].*[\"']" "$file" && echo "    Hardcoded password found"
    grep -n -i "secret\s*=\s*[\"'].*[\"']" "$file" && echo "    Hardcoded secret found"
    grep -n -i "api_key\s*=\s*[\"'].*[\"']" "$file" && echo "    Hardcoded API key found"
    grep -n -i "token\s*=\s*[\"'].*[\"']" "$file" && echo "    Hardcoded token found"
    
    # Check for AWS credentials
    grep -n "AKIA[0-9A-Z]{16}" "$file" && echo "    AWS access key found"
    grep -n "[A-Za-z0-9/+=]{40}" "$file" && echo "    Potential AWS secret key found"
    
    # Check for private keys
    grep -n "BEGIN.*PRIVATE KEY" "$file" && echo "    Private key found"
done

# Check for sensitive data in variables files
echo "2. Checking variables files for sensitive data:"
find . -name "*.tfvars" | while read file; do
    if [ -f "$file" ]; then
        echo "Variables file: $file"
        grep -v "^#" "$file" | grep -i "password\|secret\|key" | while read line; do
            echo "    Sensitive variable: $line"
        done
    fi
done
EOF

chmod +x scan-terraform-secrets.sh
./scan-terraform-secrets.sh
```

**Solution:**
```bash
# Implement secure secrets management
cat > terraform-secrets-management.tf << 'EOF'
# Use AWS Secrets Manager for sensitive values
resource "aws_secretsmanager_secret" "db_password" {
  name                    = "database-password"
  description             = "Database password for application"
  recovery_window_in_days = 7
  
  kms_key_id = aws_kms_key.secrets.arn
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id = aws_secretsmanager_secret.db_password.id
  secret_string = jsonencode({
    username = "admin"
    password = random_password.db_password.result
  })
}

resource "random_password" "db_password" {
  length  = 32
  special = true
}

# KMS key for secrets encryption
resource "aws_kms_key" "secrets" {
  description             = "KMS key for secrets encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

# Use data source to retrieve secrets
data "aws_secretsmanager_secret_version" "db_password" {
  secret_id = aws_secretsmanager_secret.db_password.id
}

locals {
  db_credentials = jsondecode(data.aws_secretsmanager_secret_version.db_password.secret_string)
}

# Use the secret in resources
resource "aws_db_instance" "main" {
  identifier = "main-database"
  
  username = local.db_credentials.username
  password = local.db_credentials.password
  
  # Other configuration...
}

# Variable definitions for sensitive values
variable "database_password" {
  description = "Database password"
  type        = string
  sensitive   = true
}

# Environment-specific secrets
variable "api_keys" {
  description = "API keys for external services"
  type        = map(string)
  sensitive   = true
}

# Use environment variables for sensitive values
# TF_VAR_database_password=secretvalue terraform plan
EOF

# Create secure variable files
cat > terraform.tfvars.example << 'EOF'
# Example variables file - copy to terraform.tfvars and update values
# DO NOT commit terraform.tfvars to version control

# Use placeholder values
database_password = "REPLACE_WITH_ACTUAL_PASSWORD"
api_keys = {
  external_service = "REPLACE_WITH_API_KEY"
}
EOF

# Update .gitignore for sensitive files
cat >> .gitignore << 'EOF'
# Terraform sensitive files
terraform.tfvars
*.tfvars
.terraform/
EOF

echo " Terraform secrets management configured"
```

## Provider Configuration

### Issue: Insecure provider configurations

**Symptoms:**
- Hardcoded credentials in providers
- Missing provider version constraints
- Insecure provider settings

**Diagnosis:**
```bash
# Check provider security
cat > check-provider-security.sh << 'EOF'
#!/bin/bash
echo " Provider Security Check "

# Check for hardcoded credentials
echo "1. Checking for hardcoded provider credentials:"
find . -name "*.tf" | while read file; do
    if grep -q "provider.*{" "$file"; then
        echo "Checking providers in $file:"
        
        # Check for hardcoded AWS credentials
        if grep -A 20 "provider.*aws" "$file" | grep -q "access_key\|secret_key"; then
            echo "    Hardcoded AWS credentials found"
        fi
        
        # Check for hardcoded Azure credentials
        if grep -A 20 "provider.*azurerm" "$file" | grep -q "client_secret\|subscription_id"; then
            echo "    Hardcoded Azure credentials found"
        fi
        
        # Check for missing assume_role
        if grep -A 20 "provider.*aws" "$file" | grep -v "assume_role" | grep -q "access_key"; then
            echo "    AWS provider not using assume_role"
        fi
    fi
done

# Check for version constraints
echo "2. Checking provider version constraints:"
find . -name "*.tf" | while read file; do
    if grep -q "required_providers" "$file"; then
        echo "Provider versions in $file:"
        grep -A 10 "required_providers" "$file" | while read line; do
            if echo "$line" | grep -q "version.*="; then
                if echo "$line" | grep -q ">= 0\|>= 1\|>= 2"; then
                    echo "    Loose version constraint: $line"
                fi
            fi
        done
    fi
done
EOF

chmod +x check-provider-security.sh
./check-provider-security.sh
```

**Solution:**
```bash
# Create secure provider configuration
cat > providers.tf << 'EOF'
terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
  }
}

# Secure AWS provider configuration
provider "aws" {
  region = var.aws_region
  
  # Use assume_role for cross-account access
  assume_role {
    role_arn     = var.assume_role_arn
    session_name = "terraform-session"
    external_id  = var.external_id
  }
  
  # Default tags for all resources
  default_tags {
    tags = {
      Environment   = var.environment
      ManagedBy     = "terraform"
      Project       = var.project_name
      SecurityLevel = var.security_level
    }
  }
}

# Secure Azure provider configuration
provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = false
    }
    
    storage_blob {
      delete_retention_policy = true
    }
  }
  
  # Use service principal with certificate
  client_id           = var.azure_client_id
  client_certificate_path = var.azure_client_cert_path
  subscription_id     = var.azure_subscription_id
  tenant_id          = var.azure_tenant_id
}

# Secure Google provider configuration
provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
  
  # Use service account key file
  credentials = file(var.gcp_service_account_key_file)
  
  # Request quota project for API calls
  quota_project = var.gcp_quota_project
}

# Secure Kubernetes provider configuration
provider "kubernetes" {
  host                   = data.aws_eks_cluster.cluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority[0].data)
  
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args = [
      "eks",
      "get-token",
      "--cluster-name",
      data.aws_eks_cluster.cluster.name,
      "--region",
      var.aws_region
    ]
  }
}
EOF

# Create variables for provider configuration
cat > variables.tf << 'EOF'
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "assume_role_arn" {
  description = "ARN of the role to assume"
  type        = string
}

variable "external_id" {
  description = "External ID for assume role"
  type        = string
  sensitive   = true
}

variable "environment" {
  description = "Environment name"
  type        = string
  
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "security_level" {
  description = "Security level for resources"
  type        = string
  default     = "high"
  
  validation {
    condition     = contains(["low", "medium", "high"], var.security_level)
    error_message = "Security level must be low, medium, or high."
  }
}
EOF

echo " Secure provider configuration created"
```

## Resource Security

### Issue: Insecurely configured resources

**Symptoms:**
- Resources with public access
- Missing encryption
- Overly permissive security groups

**Diagnosis:**
```bash
# Security audit for Terraform resources
cat > audit-terraform-resources.sh << 'EOF'
#!/bin/bash
echo " Terraform Resource Security Audit "

# Check for public S3 buckets
echo "1. Checking for public S3 buckets:"
find . -name "*.tf" | while read file; do
    if grep -q "aws_s3_bucket\|aws_s3_bucket_public_access_block" "$file"; then
        echo "S3 configuration in $file:"
        
        # Check for public access block
        if ! grep -A 20 "aws_s3_bucket_public_access_block" "$file" | grep -q "block_public_acls.*true"; then
            echo "    S3 public access block not configured"
        fi
        
        # Check for public ACL
        if grep -A 10 "aws_s3_bucket" "$file" | grep -q "acl.*public"; then
            echo "    S3 bucket has public ACL"
        fi
    fi
done

# Check for unencrypted resources
echo "2. Checking for unencrypted resources:"
find . -name "*.tf" | while read file; do
    # Check EBS volumes
    if grep -q "aws_ebs_volume\|aws_instance" "$file"; then
        if ! grep -A 10 "aws_ebs_volume\|aws_instance" "$file" | grep -q "encrypted.*true"; then
            echo "    Unencrypted EBS volume in $file"
        fi
    fi
    
    # Check RDS instances
    if grep -q "aws_db_instance" "$file"; then
        if ! grep -A 20 "aws_db_instance" "$file" | grep -q "storage_encrypted.*true"; then
            echo "    Unencrypted RDS instance in $file"
        fi
    fi
done

# Check security groups
echo "3. Checking security groups:"
find . -name "*.tf" | while read file; do
    if grep -q "aws_security_group" "$file"; then
        echo "Security group in $file:"
        
        # Check for 0.0.0.0/0 access
        if grep -A 20 "aws_security_group" "$file" | grep -q "0.0.0.0/0"; then
            echo "    Security group allows 0.0.0.0/0 access"
        fi
        
        # Check for wide port ranges
        if grep -A 20 "aws_security_group" "$file" | grep -q "from_port.*0.*to_port.*65535"; then
            echo "    Security group has wide port range"
        fi
    fi
done
EOF

chmod +x audit-terraform-resources.sh
./audit-terraform-resources.sh
```

**Solution:**
```bash
# Create secure resource templates
cat > secure-resources.tf << 'EOF'
# Secure S3 bucket configuration
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "${var.project_name}-secure-bucket-${random_string.bucket_suffix.result}"
  
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_public_access_block" "secure_bucket" {
  bucket = aws_s3_bucket.secure_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure_bucket" {
  bucket = aws_s3_bucket.secure_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.s3_encryption.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "secure_bucket" {
  bucket = aws_s3_bucket.secure_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "secure_bucket" {
  bucket = aws_s3_bucket.secure_bucket.id

  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "access-logs/"
}

# Secure security groups
resource "aws_security_group" "web_tier" {
  name_prefix = "${var.project_name}-web-"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP from internet"
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS from internet"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-web-sg"
  }
}

resource "aws_security_group" "app_tier" {
  name_prefix = "${var.project_name}-app-"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.web_tier.id]
    description     = "Application port from web tier"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-app-sg"
  }
}

# Secure RDS instance
resource "aws_db_instance" "main" {
  identifier = "${var.project_name}-db"
  
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.micro"
  
  allocated_storage     = 20
  max_allocated_storage = 100
  storage_type         = "gp2"
  storage_encrypted    = true
  kms_key_id          = aws_kms_key.rds_encryption.arn
  
  db_name  = var.database_name
  username = var.database_username
  password = random_password.db_password.result
  
  vpc_security_group_ids = [aws_security_group.database.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
  
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
  
  skip_final_snapshot = false
  final_snapshot_identifier = "${var.project_name}-db-final-snapshot"
  
  deletion_protection = true
  
  enabled_cloudwatch_logs_exports = ["error", "general", "slow_query"]
  
  tags = {
    Name = "${var.project_name}-database"
  }
}

# KMS keys for encryption
resource "aws_kms_key" "s3_encryption" {
  description             = "KMS key for S3 encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  
  tags = {
    Name = "${var.project_name}-s3-encryption"
  }
}

resource "aws_kms_key" "rds_encryption" {
  description             = "KMS key for RDS encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  
  tags = {
    Name = "${var.project_name}-rds-encryption"
  }
}

# Secure VPC configuration
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name = "${var.project_name}-vpc"
  }
}

resource "aws_flow_log" "vpc_flow_log" {
  iam_role_arn    = aws_iam_role.flow_log.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_log.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.main.id
}

resource "aws_cloudwatch_log_group" "vpc_flow_log" {
  name              = "/aws/vpc/flow-logs"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.logs_encryption.arn
}

resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

resource "random_password" "db_password" {
  length  = 32
  special = true
}
EOF

echo " Secure resource templates created"
```

## Policy as Code

### Issue: Missing infrastructure policy enforcement

**Symptoms:**
- No automated security checks
- Resources deployed without compliance validation
- Missing cost controls

**Solution:**
```bash
# Create Open Policy Agent (OPA) policies for Terraform
mkdir -p policies

cat > policies/security.rego << 'EOF'
package terraform.security

# Deny resources without encryption
deny[msg] {
  input.resource_type == "aws_s3_bucket"
  not input.values.server_side_encryption_configuration
  msg := "S3 bucket must have server-side encryption enabled"
}

deny[msg] {
  input.resource_type == "aws_db_instance"
  input.values.storage_encrypted != true
  msg := "RDS instance must have storage encryption enabled"
}

deny[msg] {
  input.resource_type == "aws_ebs_volume"
  input.values.encrypted != true
  msg := "EBS volume must be encrypted"
}

# Deny public access
deny[msg] {
  input.resource_type == "aws_s3_bucket_public_access_block"
  input.values.block_public_acls != true
  msg := "S3 bucket must block public ACLs"
}

deny[msg] {
  input.resource_type == "aws_security_group"
  input.values.ingress[_].cidr_blocks[_] == "0.0.0.0/0"
  input.values.ingress[_].from_port == 22
  msg := "Security group must not allow SSH access from 0.0.0.0/0"
}

# Require specific tags
required_tags := ["Environment", "Project", "Owner"]

deny[msg] {
  input.resource_type == "aws_instance"
  tag := required_tags[_]
  not input.values.tags[tag]
  msg := sprintf("AWS instance must have tag: %v", [tag])
}
EOF

cat > policies/cost.rego << 'EOF'
package terraform.cost

# Deny expensive instance types in non-production
deny[msg] {
  input.resource_type == "aws_instance"
  input.values.instance_type in ["c5.4xlarge", "c5.9xlarge", "c5.18xlarge"]
  input.values.tags.Environment != "production"
  msg := "Large instance types are only allowed in production"
}

# Limit RDS instance sizes
deny[msg] {
  input.resource_type == "aws_db_instance"
  input.values.instance_class in ["db.r5.2xlarge", "db.r5.4xlarge"]
  input.values.tags.Environment == "development"
  msg := "Large RDS instances are not allowed in development"
}
EOF

# Create policy validation script
cat > validate-policies.sh << 'EOF'
#!/bin/bash
echo "=== Terraform Policy Validation ==="

# Generate Terraform plan in JSON format
terraform plan -out=tfplan.out
terraform show -json tfplan.out > tfplan.json

# Install OPA if not present
if ! command -v opa &> /dev/null; then
    echo "Installing OPA..."
    curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
    chmod +x opa
    sudo mv opa /usr/local/bin/
fi

# Validate against security policies
echo "1. Validating security policies..."
opa eval -d policies/security.rego -I tfplan.json "data.terraform.security.deny[x]" | jq -r '.result[].expressions[].value[]'

# Validate against cost policies
echo "2. Validating cost policies..."
opa eval -d policies/cost.rego -I tfplan.json "data.terraform.cost.deny[x]" | jq -r '.result[].expressions[].value[]'

# Cleanup
rm -f tfplan.out tfplan.json
EOF

chmod +x validate-policies.sh

echo "Policy as Code framework created"
```

This infrastructure security guide provides tools and configurations to secure Terraform deployments with proper state management, secrets handling, secure resource configurations, and policy enforcement.