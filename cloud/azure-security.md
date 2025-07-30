# Azure Security Troubleshooting Guide

This guide helps you identify, troubleshoot, and resolve security issues in Microsoft Azure environments with focus on attack scenarios and defensive measures.


## Azure AD Security Issues

### Overprivileged Azure AD Roles

#### Issue: Users with excessive Azure AD permissions

**Symptoms:**
- Users with Global Administrator role in production
- Service principals with unnecessary permissions
- External users with privileged access

**Diagnosis:**
```bash
# Azure AD privilege audit
cat > azuread-privilege-audit.sh << 'EOF'
#!/bin/bash
echo " Azure AD Privilege Audit "

# Check Global Administrators
echo "1. Global Administrators:"
az ad role assignment list --role "Global Administrator" --query '[].{PrincipalDisplayName:principalDisplayName, PrincipalType:principalType}' --output table

# Check Privileged Role Administrator
echo "2. Privileged Role Administrators:"
az ad role assignment list --role "Privileged Role Administrator" --query '[].{PrincipalDisplayName:principalDisplayName, PrincipalType:principalType}' --output table

# Check Security Administrator  
echo "3. Security Administrators:"
az ad role assignment list --role "Security Administrator" --query '[].{PrincipalDisplayName:principalDisplayName, PrincipalType:principalType}' --output table

# Check external users with admin roles
echo "4. External users with admin roles:"
az ad user list --query '[?userType==`Guest`].{DisplayName:displayName, UserPrincipalName:userPrincipalName}' --output table > external-users.txt

while read user; do
    if [ ! -z "$user" ]; then
        UPN=$(echo "$user" | awk '{print $2}')
        az ad role assignment list --assignee "$UPN" --query '[].{Role:roleDefinitionName}' --output table
    fi
done < external-users.txt

# Check service principals with high privileges
echo "5. Service principals with admin roles:"
az ad sp list --all --query '[].{DisplayName:displayName, AppId:appId}' --output table | while read sp; do
    if [ ! -z "$sp" ]; then
        APP_ID=$(echo "$sp" | awk '{print $2}')
        ROLES=$(az ad role assignment list --assignee "$APP_ID" --query '[].roleDefinitionName' --output tsv)
        if echo "$ROLES" | grep -q -E "(Administrator|Owner|Contributor)"; then
            echo "Service Principal: $sp"
            echo "Roles: $ROLES"
        fi
    fi
done

# Check for users with multiple admin roles
echo "6. Users with multiple admin roles:"
az ad user list --query '[].userPrincipalName' --output text | while read upn; do
    ADMIN_ROLES=$(az ad role assignment list --assignee "$upn" --query '[?contains(roleDefinitionName, `Administrator`)].roleDefinitionName' --output text | wc -w)
    if [ "$ADMIN_ROLES" -gt 1 ]; then
        echo "User $upn has $ADMIN_ROLES admin roles"
    fi
done
EOF

chmod +x azuread-privilege-audit.sh
./azuread-privilege-audit.sh
```

**Solution:**
```bash
# Implement least privilege Azure AD roles
cat > create-minimal-azuread-roles.sh << 'EOF'
#!/bin/bash
USER_UPN=$1
REQUIRED_ROLE=$2

if [ -z "$USER_UPN" ] || [ -z "$REQUIRED_ROLE" ]; then
    echo "Usage: $0 <user-upn> <required-role>"
    echo "Example: $0 user@company.com 'Security Reader'"
    exit 1
fi

echo " Implementing Least Privilege for $USER_UPN "

# Remove all admin roles first
CURRENT_ROLES=$(az ad role assignment list --assignee "$USER_UPN" --query '[?contains(roleDefinitionName, `Administrator`)].{Id:id, Role:roleDefinitionName}' --output json)

echo "$CURRENT_ROLES" | jq -r '.[] | .Id' | while read assignment_id; do
    if [ ! -z "$assignment_id" ]; then
        az role assignment delete --ids "$assignment_id"
        echo "Removed admin role assignment: $assignment_id"
    fi
done

# Assign minimal required role
az role assignment create \
    --assignee "$USER_UPN" \
    --role "$REQUIRED_ROLE" \
    --scope "/subscriptions/$(az account show --query id --output tsv)"

echo "Assigned role: $REQUIRED_ROLE to $USER_UPN"

# Enable Privileged Identity Management if available
PIM_ELIGIBLE=$(az ad role assignment list --assignee "$USER_UPN" --query '[?isEligible==`true`]' --output json)
if [ "$(echo "$PIM_ELIGIBLE" | jq length)" -eq 0 ]; then
    echo "Consider enabling PIM for temporary privileged access"
fi
EOF

chmod +x create-minimal-azuread-roles.sh
```

### Compromised Azure AD Accounts

#### Issue: User accounts showing signs of compromise

**Symptoms:**
- Unusual sign-in patterns
- Multiple failed authentication attempts
- Sign-ins from unusual locations

**Diagnosis:**
```bash
# Azure AD security assessment
cat > azuread-security-audit.sh << 'EOF'
#!/bin/bash
echo " Azure AD Security Audit "

# Check risky sign-ins (requires Azure AD Premium)
echo "1. Risky sign-ins (last 7 days):"
az ad signed-in-user list-owned-objects 2>/dev/null || echo "Azure AD Premium required for risk detection"

# Check sign-ins from unusual locations
echo "2. Checking recent sign-ins..."
# This requires Microsoft Graph API access
echo "Manual check required: Review Azure AD Sign-ins blade for:"
echo "- Sign-ins from new countries"
echo "- Sign-ins outside business hours"
echo "- Multiple simultaneous sign-ins"

# Check for disabled accounts still having active sessions
echo "3. Disabled accounts with recent activity:"
az ad user list --query '[?accountEnabled==`false`].{DisplayName:displayName, UserPrincipalName:userPrincipalName}' --output table

# Check for accounts without MFA
echo "4. Accounts without MFA:"
echo "Manual check required: Azure AD > Users > Multi-Factor Authentication"

# Check for privileged accounts without conditional access
echo "5. Admin accounts conditional access status:"
az ad role assignment list --role "Global Administrator" --query '[].principalDisplayName' --output text | while read admin; do
    if [ ! -z "$admin" ]; then
        echo "Admin: $admin - Check conditional access policies manually"
    fi
done

# Check guest user permissions
echo "6. Guest user access review:"
GUEST_COUNT=$(az ad user list --query '[?userType==`Guest`] | length(@)')
echo "Total guest users: $GUEST_COUNT"
if [ "$GUEST_COUNT" -gt 0 ]; then
    echo "Review guest user access and permissions"
fi
EOF

chmod +x azuread-security-audit.sh
```

## Resource Access & RBAC

### RBAC Permission Issues

#### Issue: Overprivileged resource access

**Symptoms:**
- Users with Owner permissions on subscriptions
- Service principals with Contributor access
- Custom roles with excessive permissions

**Diagnosis:**
```bash
# Azure RBAC audit
cat > azure-rbac-audit.sh << 'EOF'
#!/bin/bash
echo " Azure RBAC Security Audit "

# Check subscription-level permissions
echo "1. Subscription-level role assignments:"
SUBSCRIPTION_ID=$(az account show --query id --output tsv)
az role assignment list --scope "/subscriptions/$SUBSCRIPTION_ID" --query '[].{PrincipalName:principalName, RoleDefinitionName:roleDefinitionName, PrincipalType:principalType}' --output table

# Find users with Owner permissions
echo "2. Users with Owner role:"
az role assignment list --role "Owner" --query '[].{PrincipalName:principalName, Scope:scope}' --output table

# Check for overprivileged service principals
echo "3. Service principals with high permissions:"
az role assignment list --query '[?principalType==`ServicePrincipal` && (roleDefinitionName==`Owner` || roleDefinitionName==`Contributor`)].{PrincipalName:principalName, Role:roleDefinitionName, Scope:scope}' --output table

# Check custom roles
echo "4. Custom roles with potentially excessive permissions:"
az role definition list --custom-role-only --query '[].{RoleName:roleName, Actions:permissions[0].actions}' --output json | jq -r '.[] | select(.Actions[] | contains("*")) | .RoleName'

# Check role assignments at resource group level
echo "5. Resource group level permissions:"
az group list --query '[].name' --output text | while read rg; do
    if [ ! -z "$rg" ]; then
        ASSIGNMENTS=$(az role assignment list --resource-group "$rg" --query 'length(@)')
        if [ "$ASSIGNMENTS" -gt 5 ]; then
            echo "Resource group $rg has $ASSIGNMENTS role assignments - review needed"
        fi
    fi
done

# Check for unused role assignments
echo "6. Checking for stale role assignments..."
az role assignment list --include-inherited --query '[].{Principal:principalName, Role:roleDefinitionName, CreatedOn:createdOn}' --output table | sort -k3
EOF

chmod +x azure-rbac-audit.sh
```

**Solution:**
```bash
# Implement least privilege RBAC
cat > implement-least-privilege-rbac.sh << 'EOF'
#!/bin/bash
PRINCIPAL_ID=$1
RESOURCE_GROUP=$2
REQUIRED_PERMISSIONS=$3

if [ -z "$PRINCIPAL_ID" ] || [ -z "$RESOURCE_GROUP" ] || [ -z "$REQUIRED_PERMISSIONS" ]; then
    echo "Usage: $0 <principal-id> <resource-group> <required-permissions>"
    echo "Example: $0 user@company.com myapp-rg 'Virtual Machine Contributor'"
    exit 1
fi

echo " Implementing Least Privilege RBAC "

# Remove existing high-privilege assignments
CURRENT_ASSIGNMENTS=$(az role assignment list --assignee "$PRINCIPAL_ID" --resource-group "$RESOURCE_GROUP" --query '[?roleDefinitionName==`Owner` || roleDefinitionName==`Contributor`].id' --output text)

for assignment in $CURRENT_ASSIGNMENTS; do
    if [ ! -z "$assignment" ]; then
        az role assignment delete --ids "$assignment"
        echo "Removed high-privilege assignment: $assignment"
    fi
done

# Create specific role assignment
az role assignment create \
    --assignee "$PRINCIPAL_ID" \
    --role "$REQUIRED_PERMISSIONS" \
    --resource-group "$RESOURCE_GROUP"

echo "Assigned role: $REQUIRED_PERMISSIONS"

# Create custom role if needed for specific permissions
if [ "$REQUIRED_PERMISSIONS" = "custom" ]; then
    cat > custom-role.json << ROLE
{
    "Name": "Custom Application Manager",
    "Description": "Can manage specific application resources",
    "Actions": [
        "Microsoft.Compute/virtualMachines/read",
        "Microsoft.Compute/virtualMachines/start/action",
        "Microsoft.Compute/virtualMachines/restart/action",
        "Microsoft.Network/networkInterfaces/read"
    ],
    "NotActions": [
        "Microsoft.Compute/virtualMachines/delete"
    ],
    "AssignableScopes": [
        "/subscriptions/$(az account show --query id --output tsv)/resourceGroups/$RESOURCE_GROUP"
    ]
}
ROLE

    az role definition create --role-definition custom-role.json
    echo "Custom role created"
fi
EOF

chmod +x implement-least-privilege-rbac.sh
```

## Network Security Groups

### NSG Security Issues

#### Issue: Network Security Groups with overly permissive rules

**Symptoms:**
- NSG rules allowing 0.0.0.0/0 access
- Management ports open to internet
- No network segmentation

**Diagnosis:**
```bash
# Network Security Group audit
cat > nsg-security-audit.sh << 'EOF'
#!/bin/bash
echo " Network Security Group Audit "

# List all NSGs
az network nsg list --query '[].{Name:name, ResourceGroup:resourceGroup, Location:location}' --output table

# Check each NSG for security issues
az network nsg list --query '[].{Name:name, ResourceGroup:resourceGroup}' --output json | jq -r '.[] | "\(.ResourceGroup) \(.Name)"' | while read rg nsg; do
    echo "Checking NSG: $nsg in RG: $rg"
    
    # Check for rules allowing internet access
    INTERNET_RULES=$(az network nsg rule list --nsg-name "$nsg" --resource-group "$rg" --query '[?sourceAddressPrefix==`*` || sourceAddressPrefix==`0.0.0.0/0` || sourceAddressPrefix==`Internet`]' --output json)
    
    if [ "$(echo "$INTERNET_RULES" | jq length)" -gt 0 ]; then
        echo "  Rules allowing internet access:"
        echo "$INTERNET_RULES" | jq -r '.[] | "  Port: \(.destinationPortRange), Direction: \(.direction), Access: \(.access)"'
    fi
    
    # Check for management ports open to internet
    MGMT_PORTS=$(az network nsg rule list --nsg-name "$nsg" --resource-group "$rg" --query '[?contains(destinationPortRange, `22`) || contains(destinationPortRange, `3389`) || contains(destinationPortRange, `5985`)]' --output json)
    
    if [ "$(echo "$MGMT_PORTS" | jq length)" -gt 0 ]; then
        echo "  Management ports exposed:"
        echo "$MGMT_PORTS" | jq -r '.[] | "  Port: \(.destinationPortRange), Source: \(.sourceAddressPrefix)"'
    fi
    
    # Check for default allow rules
    DEFAULT_RULES=$(az network nsg rule list --nsg-name "$nsg" --resource-group "$rg" --query '[?access==`Allow` && priority > 3000]' --output json)
    
    if [ "$(echo "$DEFAULT_RULES" | jq length)" -gt 3 ]; then
        echo "  Many allow rules - review necessity"
    fi
    
    echo ""
done

# Check for NSGs not associated with subnets or NICs
echo "Unused NSGs:"
az network nsg list --query '[].{Name:name, ResourceGroup:resourceGroup, Subnets:subnets, NetworkInterfaces:networkInterfaces}' --output json | jq -r '.[] | select(.Subnets == null and .NetworkInterfaces == null) | "Unused: \(.Name) in \(.ResourceGroup)"'
EOF

chmod +x nsg-security-audit.sh
```

**Solution:**
```bash
# Secure NSG configuration
cat > secure-nsg-config.sh << 'EOF'
#!/bin/bash
NSG_NAME=$1
RESOURCE_GROUP=$2
NSG_TYPE=$3

if [ -z "$NSG_NAME" ] || [ -z "$RESOURCE_GROUP" ] || [ -z "$NSG_TYPE" ]; then
    echo "Usage: $0 <nsg-name> <resource-group> <type>"
    echo "Types: web, app, db, mgmt"
    exit 1
fi

echo " Securing NSG: $NSG_NAME (Type: $NSG_TYPE) "

# Remove overly permissive rules
echo "1. Removing permissive rules..."
az network nsg rule list --nsg-name "$NSG_NAME" --resource-group "$RESOURCE_GROUP" --query '[?sourceAddressPrefix==`*` || sourceAddressPrefix==`0.0.0.0/0`].name' --output text | while read rule; do
    if [ ! -z "$rule" ]; then
        az network nsg rule delete --nsg-name "$NSG_NAME" --resource-group "$RESOURCE_GROUP" --name "$rule"
        echo "Removed rule: $rule"
    fi
done

# Create secure rules based on tier type
case $NSG_TYPE in
    "web")
        echo "2. Creating secure web tier rules..."
        az network nsg rule create \
            --nsg-name "$NSG_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --name "AllowHTTP" \
            --protocol Tcp \
            --priority 100 \
            --destination-port-range 80 \
            --source-address-prefix Internet \
            --access Allow
            
        az network nsg rule create \
            --nsg-name "$NSG_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --name "AllowHTTPS" \
            --protocol Tcp \
            --priority 110 \
            --destination-port-range 443 \
            --source-address-prefix Internet \
            --access Allow
        ;;
        
    "app")
        echo "2. Creating secure app tier rules..."
        # Only allow from web tier subnet
        read -p "Enter web tier subnet CIDR: " WEB_SUBNET
        az network nsg rule create \
            --nsg-name "$NSG_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --name "AllowFromWebTier" \
            --protocol Tcp \
            --priority 100 \
            --destination-port-range 8080 \
            --source-address-prefix "$WEB_SUBNET" \
            --access Allow
        ;;
        
    "db")
        echo "2. Creating secure database tier rules..."
        # Only allow from app tier subnet
        read -p "Enter app tier subnet CIDR: " APP_SUBNET
        az network nsg rule create \
            --nsg-name "$NSG_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --name "AllowFromAppTier" \
            --protocol Tcp \
            --priority 100 \
            --destination-port-ranges 1433 3306 5432 \
            --source-address-prefix "$APP_SUBNET" \
            --access Allow
        ;;
        
    "mgmt")
        echo "2. Creating secure management rules..."
        # Only allow from specific management IPs
        read -p "Enter management IP range: " MGMT_IPS
        az network nsg rule create \
            --nsg-name "$NSG_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --name "AllowSSHFromMgmt" \
            --protocol Tcp \
            --priority 100 \
            --destination-port-range 22 \
            --source-address-prefix "$MGMT_IPS" \
            --access Allow
            
        az network nsg rule create \
            --nsg-name "$NSG_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --name "AllowRDPFromMgmt" \
            --protocol Tcp \
            --priority 110 \
            --destination-port-range 3389 \
            --source-address-prefix "$MGMT_IPS" \
            --access Allow
        ;;
esac

# Add explicit deny rule at the end
az network nsg rule create \
    --nsg-name "$NSG_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --name "DenyAllInbound" \
    --protocol "*" \
    --priority 4096 \
    --source-address-prefix "*" \
    --destination-address-prefix "*" \
    --destination-port-range "*" \
    --access Deny

echo " NSG $NSG_NAME secured with least privilege rules"
EOF

chmod +x secure-nsg-config.sh
```

## Key Vault Security

### Key Vault Access Issues

#### Issue: Key Vault with insecure access policies

**Symptoms:**
- Key Vault accessible from all networks
- Overly permissive access policies
- No audit logging

**Diagnosis:**
```bash
# Key Vault security audit
cat > keyvault-security-audit.sh << 'EOF'
#!/bin/bash
echo " Key Vault Security Audit "

# List all Key Vaults
az keyvault list --query '[].{Name:name, ResourceGroup:resourceGroup}' --output table

# Check each Key Vault
az keyvault list --query '[].name' --output text | while read kv; do
    echo "Auditing Key Vault: $kv"
    
    # Check network access
    NETWORK_RULES=$(az keyvault network-rule list --name "$kv" --query 'defaultAction' --output text)
    echo "  Default network action: $NETWORK_RULES"
    
    if [ "$NETWORK_RULES" = "Allow" ]; then
        echo "    Key Vault allows all network access"
    fi
    
    # Check access policies
    ACCESS_POLICIES=$(az keyvault show --name "$kv" --query 'properties.accessPolicies' --output json)
    POLICY_COUNT=$(echo "$ACCESS_POLICIES" | jq length)
    echo "  Access policies: $POLICY_COUNT"
    
    # Check for overly permissive policies
    echo "$ACCESS_POLICIES" | jq -r '.[] | select(.permissions.keys[] == "all" or .permissions.secrets[] == "all" or .permissions.certificates[] == "all") | "    Overly permissive policy for: \(.objectId)"'
    
    # Check soft delete and purge protection
    SOFT_DELETE=$(az keyvault show --name "$kv" --query 'properties.enableSoftDelete' --output text)
    PURGE_PROTECTION=$(az keyvault show --name "$kv" --query 'properties.enablePurgeProtection' --output text)
    
    echo "  Soft delete: $SOFT_DELETE"
    echo "  Purge protection: $PURGE_PROTECTION"
    
    if [ "$SOFT_DELETE" != "true" ]; then
        echo "    Soft delete not enabled"
    fi
    
    if [ "$PURGE_PROTECTION" != "true" ]; then
        echo "    Purge protection not enabled"
    fi
    
    # Check diagnostic logs
    DIAG_SETTINGS=$(az monitor diagnostic-settings list --resource "/subscriptions/$(az account show --query id --output tsv)/resourceGroups/$(az keyvault show --name "$kv" --query resourceGroup --output tsv)/providers/Microsoft.KeyVault/vaults/$kv" --query 'value' --output json)
    
    if [ "$(echo "$DIAG_SETTINGS" | jq length)" -eq 0 ]; then
        echo "    No diagnostic logging configured"
    fi
    
    echo ""
done
EOF

chmod +x keyvault-security-audit.sh
```

**Solution:**
```bash
# Secure Key Vault configuration
cat > secure-keyvault.sh << 'EOF'
#!/bin/bash
KEYVAULT_NAME=$1
RESOURCE_GROUP=$2

if [ -z "$KEYVAULT_NAME" ] || [ -z "$RESOURCE_GROUP" ]; then
    echo "Usage: $0 <keyvault-name> <resource-group>"
    exit 1
fi

echo " Securing Key Vault: $KEYVAULT_NAME "

# Enable soft delete and purge protection
echo "1. Enabling soft delete and purge protection..."
az keyvault update \
    --name "$KEYVAULT_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --enable-soft-delete true \
    --enable-purge-protection true

# Configure network access restrictions
echo "2. Restricting network access..."
az keyvault network-rule add \
    --name "$KEYVAULT_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --vnet-name "allowed-vnet" \
    --subnet "allowed-subnet"

az keyvault update \
    --name "$KEYVAULT_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --default-action Deny

# Remove overly permissive access policies
echo "3. Reviewing access policies..."
CURRENT_POLICIES=$(az keyvault show --name "$KEYVAULT_NAME" --query 'properties.accessPolicies[].objectId' --output text)

for object_id in $CURRENT_POLICIES; do
    PERMISSIONS=$(az keyvault show --name "$KEYVAULT_NAME" --query "properties.accessPolicies[?objectId=='$object_id'].permissions" --output json)
    
    # Check if user has 'all' permissions
    if echo "$PERMISSIONS" | jq -e '.[0].keys[] == "all"' >/dev/null 2>&1; then
        echo "  Object $object_id has 'all' key permissions - consider restricting"
    fi
done

# Set up diagnostic logging
echo "4. Configuring diagnostic logging..."
STORAGE_ACCOUNT=$(az storage account list --resource-group "$RESOURCE_GROUP" --query '[0].name' --output tsv)

if [ ! -z "$STORAGE_ACCOUNT" ]; then
    az monitor diagnostic-settings create \
        --resource "/subscriptions/$(az account show --query id --output tsv)/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.KeyVault/vaults/$KEYVAULT_NAME" \
        --name "KeyVaultDiagnostics" \
        --storage-account "$STORAGE_ACCOUNT" \
        --logs '[{"category": "AuditEvent", "enabled": true, "retentionPolicy": {"enabled": true, "days": 90}}]' \
        --metrics '[{"category": "AllMetrics", "enabled": true, "retentionPolicy": {"enabled": true, "days": 90}}]'
    
    echo " Diagnostic logging configured"
else
    echo "  No storage account found - create one for diagnostic logs"
fi

# Create minimal access policy example
echo "5. Example minimal access policy creation:"
cat << POLICY_EXAMPLE
# Create access policy with minimal permissions:
az keyvault set-policy \\
    --name "$KEYVAULT_NAME" \\
    --object-id <user-object-id> \\
    --secret-permissions get list \\
    --key-permissions get list decrypt \\
    --certificate-permissions get list

# For applications, use Managed Identity:
az keyvault set-policy \\
    --name "$KEYVAULT_NAME" \\
    --object-id <managed-identity-object-id> \\
    --secret-permissions get
POLICY_EXAMPLE

echo " Key Vault $KEYVAULT_NAME security configuration completed"
EOF

chmod +x secure-keyvault.sh
```

## Storage Account Security

### Storage Account Misconfigurations

#### Issue: Storage accounts with public access

**Symptoms:**
- Storage accounts allowing public blob access
- No network restrictions
- Unencrypted data

**Diagnosis:**
```bash
# Storage account security audit
cat > storage-security-audit.sh << 'EOF'
#!/bin/bash
echo " Storage Account Security Audit "

# List all storage accounts
az storage account list --query '[].{Name:name, ResourceGroup:resourceGroup, AllowBlobPublicAccess:allowBlobPublicAccess}' --output table

# Check each storage account
az storage account list --query '[].{Name:name, ResourceGroup:resourceGroup}' --output json | jq -r '.[] | "\(.ResourceGroup) \(.Name)"' | while read rg storage; do
    echo "Auditing Storage Account: $storage"
    
    # Check public access configuration
    PUBLIC_ACCESS=$(az storage account show --name "$storage" --resource-group "$rg" --query 'allowBlobPublicAccess' --output text)
    echo "  Public blob access: $PUBLIC_ACCESS"
    
    if [ "$PUBLIC_ACCESS" = "true" ]; then
        echo "    Public blob access enabled"
    fi
    
    # Check network access
    NETWORK_DEFAULT=$(az storage account show --name "$storage" --resource-group "$rg" --query 'networkRuleSet.defaultAction' --output text)
    echo "  Network default action: $NETWORK_DEFAULT"
    
    if [ "$NETWORK_DEFAULT" = "Allow" ]; then
        echo "    Storage account allows all network access"
    fi
    
    # Check encryption
    ENCRYPTION=$(az storage account show --name "$storage" --resource-group "$rg" --query 'encryption.services.blob.enabled' --output text)
    echo "  Blob encryption: $ENCRYPTION"
    
    # Check for HTTPS-only
    HTTPS_ONLY=$(az storage account show --name "$storage" --resource-group "$rg" --query 'enableHttpsTrafficOnly' --output text)
    echo "  HTTPS only: $HTTPS_ONLY"
    
    if [ "$HTTPS_ONLY" != "true" ]; then
        echo "    HTTPS not enforced"
    fi
    
    # Check access keys last rotation
    echo "  Access keys (rotate regularly):"
    az storage account keys list --account-name "$storage" --resource-group "$rg" --query '[].{KeyName:keyName, CreationTime:creationTime}' --output table
    
    # Check containers with public access
    KEY=$(az storage account keys list --account-name "$storage" --resource-group "$rg" --query '[0].value' --output tsv)
    PUBLIC_CONTAINERS=$(az storage container list --account-name "$storage" --account-key "$KEY" --query '[?properties.publicAccess!=null].name' --output text 2>/dev/null)
    
    if [ ! -z "$PUBLIC_CONTAINERS" ]; then
        echo "    Containers with public access: $PUBLIC_CONTAINERS"
    fi
    
    echo ""
done
EOF

chmod +x storage-security-audit.sh
```

**Solution:**
```bash
# Secure storage account configuration
cat > secure-storage-account.sh << 'EOF'
#!/bin/bash
STORAGE_ACCOUNT=$1
RESOURCE_GROUP=$2

if [ -z "$STORAGE_ACCOUNT" ] || [ -z "$RESOURCE_GROUP" ]; then
    echo "Usage: $0 <storage-account-name> <resource-group>"
    exit 1
fi

echo " Securing Storage Account: $STORAGE_ACCOUNT "

# Disable public blob access
echo "1. Disabling public blob access..."
az storage account update \
    --name "$STORAGE_ACCOUNT" \
    --resource-group "$RESOURCE_GROUP" \
    --allow-blob-public-access false

# Enforce HTTPS only
echo "2. Enforcing HTTPS only..."
az storage account update \
    --name "$STORAGE_ACCOUNT" \
    --resource-group "$RESOURCE_GROUP" \
    --https-only true

# Configure network access restrictions
echo "3. Restricting network access..."
az storage account network-rule add \
    --account-name "$STORAGE_ACCOUNT" \
    --resource-group "$RESOURCE_GROUP" \
    --vnet-name "allowed-vnet" \
    --subnet "allowed-subnet"

az storage account update \
    --name "$STORAGE_ACCOUNT" \
    --resource-group "$RESOURCE_GROUP" \
    --default-action Deny

# Enable advanced threat protection
echo "4. Enabling advanced threat protection..."
az security atp storage update \
    --resource-group "$RESOURCE_GROUP" \
    --storage-account "$STORAGE_ACCOUNT" \
    --is-enabled true

# Configure diagnostic logging
echo "5. Configuring diagnostic logging..."
az monitor diagnostic-settings create \
    --resource "/subscriptions/$(az account show --query id --output tsv)/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.Storage/storageAccounts/$STORAGE_ACCOUNT" \
    --name "StorageDiagnostics" \
    --logs '[{"category": "StorageRead", "enabled": true}, {"category": "StorageWrite", "enabled": true}, {"category": "StorageDelete", "enabled": true}]' \
    --metrics '[{"category": "Transaction", "enabled": true}]'

# Set up blob versioning and soft delete
echo "6. Enabling blob versioning and soft delete..."
KEY=$(az storage account keys list --account-name "$STORAGE_ACCOUNT" --resource-group "$RESOURCE_GROUP" --query '[0].value' --output tsv)

az storage blob service-properties delete-policy update \
    --account-name "$STORAGE_ACCOUNT" \
    --account-key "$KEY" \
    --enable true \
    --days-retained 30

az storage blob service-properties update \
    --account-name "$STORAGE_ACCOUNT" \
    --account-key "$KEY" \
    --enable-versioning

# Remove public access from all containers
echo "7. Securing container access..."
az storage container list --account-name "$STORAGE_ACCOUNT" --account-key "$KEY" --query '[].name' --output text | while read container; do
    if [ ! -z "$container" ]; then
        az storage container set-permission \
            --account-name "$STORAGE_ACCOUNT" \
            --account-key "$KEY" \
            --name "$container" \
            --public-access off
        echo "Removed public access from container: $container"
    fi
done

echo " Storage account $STORAGE_ACCOUNT secured"
EOF

chmod +x secure-storage-account.sh
```

## AKS Security

### AKS Cluster Security Issues

#### Issue: AKS cluster with security misconfigurations

**Diagnosis:**
```bash
# AKS security audit
cat > aks-security-audit.sh << 'EOF'
#!/bin/bash
CLUSTER_NAME=$1
RESOURCE_GROUP=$2

if [ -z "$CLUSTER_NAME" ] || [ -z "$RESOURCE_GROUP" ]; then
    echo "Usage: $0 <cluster-name> <resource-group>"
    exit 1
fi

echo " AKS Security Audit: $CLUSTER_NAME "

# Get cluster details
az aks show --name "$CLUSTER_NAME" --resource-group "$RESOURCE_GROUP" --output json > aks-config.json

# Check API server access
API_ACCESS=$(jq -r '.apiServerAccessProfile.enablePrivateCluster' aks-config.json)
echo "Private cluster: $API_ACCESS"

if [ "$API_ACCESS" != "true" ]; then
    echo "  AKS API server is publicly accessible"
fi

# Check network policy
NETWORK_POLICY=$(jq -r '.networkProfile.networkPolicy' aks-config.json)
echo "Network policy: $NETWORK_POLICY"

if [ "$NETWORK_POLICY" = "null" ]; then
    echo "  No network policy configured"
fi

# Check RBAC
RBAC_ENABLED=$(jq -r '.enableRbac' aks-config.json)
echo "RBAC enabled: $RBAC_ENABLED"

# Check AAD integration
AAD_PROFILE=$(jq -r '.aadProfile' aks-config.json)
if [ "$AAD_PROFILE" = "null" ]; then
    echo "  Azure AD integration not configured"
else
    echo "Azure AD integration: configured"
fi

# Check node pool configurations
echo "Node pool security:"
jq -r '.agentPoolProfiles[] | "Pool: \(.name), VM Size: \(.vmSize), OS Disk Type: \(.osDiskType)"' aks-config.json

# Check for system-assigned managed identity
IDENTITY_TYPE=$(jq -r '.identity.type' aks-config.json)
echo "Identity type: $IDENTITY_TYPE"

# Check authorized IP ranges
AUTHORIZED_IPS=$(jq -r '.apiServerAccessProfile.authorizedIpRanges' aks-config.json)
if [ "$AUTHORIZED_IPS" = "null" ] || [ "$AUTHORIZED_IPS" = "[]" ]; then
    echo "  No authorized IP ranges configured"
else
    echo "Authorized IP ranges: $AUTHORIZED_IPS"
fi

# Check encryption at rest
ENCRYPTION=$(jq -r '.diskEncryptionSetId' aks-config.json)
if [ "$ENCRYPTION" = "null" ]; then
    echo "  Disk encryption not configured"
else
    echo "Disk encryption: configured"
fi
EOF

chmod +x aks-security-audit.sh
```

## Incident Response

### Azure Incident Response Procedures

```bash
# Azure incident response script
cat > azure-incident-response.sh << 'EOF'
#!/bin/bash
INCIDENT_TYPE=$1
AFFECTED_RESOURCE=$2
CASE_ID=${3:-"AZURE-$(date +%Y%m%d-%H%M%S)"}

if [ -z "$INCIDENT_TYPE" ] || [ -z "$AFFECTED_RESOURCE" ]; then
    echo "Usage: $0 <incident-type> <affected-resource> [case-id]"
    echo "Types: account-compromise, data-breach, unauthorized-access, malware"
    exit 1
fi

echo " AZURE SECURITY INCIDENT RESPONSE "
echo "Incident Type: $INCIDENT_TYPE"
echo "Affected Resource: $AFFECTED_RESOURCE"
echo "Case ID: $CASE_ID"
echo "Time: $(date)"

# Create incident directory
INCIDENT_DIR="azure-incident-${CASE_ID}"
mkdir -p "$INCIDENT_DIR"/{evidence,actions,communications}

case $INCIDENT_TYPE in
    "account-compromise")
        echo "1. Immediate containment - securing account..."
        
        # If it's a user account
        if [[ $AFFECTED_RESOURCE =~ @ ]]; then
            # Disable the user account
            az ad user update --id "$AFFECTED_RESOURCE" --account-enabled false
            echo "User account $AFFECTED_RESOURCE disabled"
            
            # Revoke all active sessions
            az ad user revoke-sign-in-sessions --id "$AFFECTED_RESOURCE"
            echo "Active sessions revoked"
            
            # Get recent sign-in activity
            echo "Collecting sign-in logs..." > "$INCIDENT_DIR/evidence/signin-activity.txt"
        fi
        ;;
        
    "data-breach")
        echo "1. Immediate containment - securing data..."
        
        # If it's a storage account
        if [[ $AFFECTED_RESOURCE =~ ^storage ]]; then
            # Get resource group
            STORAGE_RG=$(az storage account show --name "$AFFECTED_RESOURCE" --query resourceGroup --output tsv)
            
            # Disable public access
            az storage account update \
                --name "$AFFECTED_RESOURCE" \
                --resource-group "$STORAGE_RG" \
                --allow-blob-public-access false
            echo "Storage account $AFFECTED_RESOURCE public access disabled"
            
            # Collect access logs
            echo "Collecting storage logs..." > "$INCIDENT_DIR/evidence/storage-logs.txt"
        fi
        ;;
        
    "unauthorized-access")
        echo "1. Immediate containment - blocking access..."
        
        # Create conditional access policy to block
        read -p "Enter suspicious IP address: " SUSPICIOUS_IP
        if [ ! -z "$SUSPICIOUS_IP" ]; then
            echo "Manual action required: Create conditional access policy to block IP $SUSPICIOUS_IP"
        fi
        ;;
esac

# Collect general evidence
echo "2. Collecting evidence..."

# Activity logs
az monitor activity-log list \
    --start-time $(date -d '6 hours ago' -u +%Y-%m-%dT%H:%M:%SZ) \
    --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
    --output json > "$INCIDENT_DIR/evidence/activity-logs.json"

# Azure AD audit logs (if available)
echo "Collecting Azure AD audit logs..." > "$INCIDENT_DIR/evidence/aad-audit-logs.txt"

# Security Center alerts
az security alert list --output json > "$INCIDENT_DIR/evidence/security-alerts.json" 2>/dev/null || echo "No Security Center access"

# Generate incident report
cat > "$INCIDENT_DIR/incident-report.md" << REPORT
# Azure Security Incident Report

**Incident ID:** $CASE_ID
**Type:** $INCIDENT_TYPE
**Affected Resource:** $AFFECTED_RESOURCE
**Date:** $(date)
**Handler:** $(az account show --query user.name --output tsv)

## Incident Timeline
- $(date): Incident detected and response initiated
- $(date): Containment measures implemented
- $(date): Evidence collection started

## Actions Taken
- [x] Immediate containment measures applied
- [x] Evidence collection initiated
- [x] Azure resources secured

## Evidence Collected
- Activity logs: evidence/activity-logs.json
- Security alerts: evidence/security-alerts.json
- Resource-specific evidence: evidence/

## Next Steps
1. [ ] Complete forensic analysis
2. [ ] Determine full scope of impact
3. [ ] Implement additional security measures
4. [ ] Update security policies
5. [ ] Communication to stakeholders

## Recommendations
- Review Azure AD permissions and implement PIM
- Enable comprehensive logging across all services
- Implement conditional access policies
- Regular security assessments and training

REPORT

echo "Azure incident response completed"
echo "Evidence location: $INCIDENT_DIR"
echo "Incident report: $INCIDENT_DIR/incident-report.md"
EOF

chmod +x azure-incident-response.sh
```