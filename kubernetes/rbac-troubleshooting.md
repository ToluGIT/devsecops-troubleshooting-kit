# Kubernetes RBAC Troubleshooting Guide

This guide helps you diagnose and resolve Role-Based Access Control (RBAC) issues in Kubernetes clusters, including permission problems, authentication failures, and authorization misconfigurations.


## RBAC Fundamentals

### Understanding RBAC Components

**Core RBAC Objects:**
- **Role/ClusterRole** - Define what can be done
- **RoleBinding/ClusterRoleBinding** - Define who can do it
- **ServiceAccount** - Identity for pods and processes
- **User/Group** - Human or system identities

### Quick RBAC Health Check
```bash
# RBAC cluster health check
cat > rbac-health-check.sh << 'EOF'
#!/bin/bash
echo "=== Kubernetes RBAC Health Check ==="

# Check if RBAC is enabled
echo "1. Checking RBAC status..."
kubectl auth can-i --list --as=system:serviceaccount:default:default 2>/dev/null && echo " RBAC is enabled" || echo " RBAC may not be enabled"

# Check cluster admin access
echo "2. Verifying cluster admin access..."
kubectl auth can-i "*" "*" --all-namespaces && echo " Cluster admin access confirmed" || echo "  Limited cluster access"

# List all ClusterRoles
echo "3. Cluster-wide roles summary:"
kubectl get clusterroles --no-headers | wc -l | awk '{print "Total ClusterRoles: " $1}'

# List all Roles across namespaces
echo "4. Namespace-scoped roles summary:"
kubectl get roles --all-namespaces --no-headers | wc -l | awk '{print "Total Roles: " $1}'

# Check for dangerous permissions
echo "5. Checking for overly permissive roles..."
echo "ClusterRoles with '*' permissions:"
kubectl get clusterroles -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.rules[*].verbs}{"\n"}{end}' | grep "\*" | head -5

# Service account summary
echo "6. Service accounts summary:"
kubectl get serviceaccounts --all-namespaces --no-headers | wc -l | awk '{print "Total ServiceAccounts: " $1}'

# Check default service account permissions
echo "7. Default service account permissions:"
kubectl auth can-i --list --as=system:serviceaccount:default:default | head -10
EOF

chmod +x rbac-health-check.sh
./rbac-health-check.sh
```

## Common RBAC Issues

### Issue: "Forbidden" Errors

**Symptoms:**
- API calls return 403 Forbidden
- Pods failing to access Kubernetes API
- Users unable to access resources

**Diagnosis:**
```bash
# Diagnose RBAC permission issues
cat > diagnose-rbac-forbidden.sh << 'EOF'
#!/bin/bash
echo "=== Diagnosing RBAC Forbidden Errors ==="

SUBJECT_TYPE=${1:-user}  # user, serviceaccount, group
SUBJECT_NAME=${2:-test-user}
NAMESPACE=${3:-default}
RESOURCE=${4:-pods}
VERB=${5:-get}

if [ "$SUBJECT_TYPE" = "serviceaccount" ]; then
    SUBJECT="system:serviceaccount:${NAMESPACE}:${SUBJECT_NAME}"
else
    SUBJECT="$SUBJECT_NAME"
fi

echo "Checking permissions for:"
echo "  Subject: $SUBJECT"
echo "  Resource: $RESOURCE"
echo "  Verb: $VERB"
echo "  Namespace: $NAMESPACE"
echo ""

# Test specific permission
echo "1. Testing specific permission..."
if [ "$NAMESPACE" = "cluster" ]; then
    kubectl auth can-i "$VERB" "$RESOURCE" --as="$SUBJECT" && echo " Permission granted" || echo " Permission denied"
else
    kubectl auth can-i "$VERB" "$RESOURCE" -n "$NAMESPACE" --as="$SUBJECT" && echo " Permission granted" || echo " Permission denied"
fi

# List all permissions for the subject
echo "2. All permissions for $SUBJECT:"
kubectl auth can-i --list --as="$SUBJECT" -n "$NAMESPACE" 2>/dev/null | head -20

# Find applicable roles and bindings
echo "3. Finding applicable roles and bindings..."

if [ "$SUBJECT_TYPE" = "serviceaccount" ]; then
    # Check RoleBindings
    echo "RoleBindings in namespace $NAMESPACE:"
    kubectl get rolebindings -n "$NAMESPACE" -o json | jq -r '.items[] | select(.subjects[]?.name == "'$SUBJECT_NAME'" and .subjects[]?.kind == "ServiceAccount") | "  - " + .metadata.name + " -> " + .roleRef.name'
    
    # Check ClusterRoleBindings
    echo "ClusterRoleBindings:"
    kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.subjects[]?.name == "'$SUBJECT_NAME'" and .subjects[]?.namespace == "'$NAMESPACE'" and .subjects[]?.kind == "ServiceAccount") | "  - " + .metadata.name + " -> " + .roleRef.name'
else
    # Check for user bindings
    echo "RoleBindings for user $SUBJECT_NAME:"
    kubectl get rolebindings -n "$NAMESPACE" -o json | jq -r '.items[] | select(.subjects[]?.name == "'$SUBJECT_NAME'" and (.subjects[]?.kind == "User" or .subjects[]?.kind == null)) | "  - " + .metadata.name + " -> " + .roleRef.name'
    
    echo "ClusterRoleBindings for user $SUBJECT_NAME:"
    kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.subjects[]?.name == "'$SUBJECT_NAME'" and (.subjects[]?.kind == "User" or .subjects[]?.kind == null)) | "  - " + .metadata.name + " -> " + .roleRef.name'
fi

# Check if resource exists in API
echo "4. Verifying resource API availability..."
kubectl api-resources | grep -i "$RESOURCE" || echo "  Resource $RESOURCE not found in API"

# Detailed role analysis
echo "5. Analyzing role permissions..."
BINDING_NAME=$(kubectl get rolebindings -n "$NAMESPACE" -o json | jq -r '.items[] | select(.subjects[]?.name == "'$SUBJECT_NAME'") | .roleRef.name' | head -1)

if [ -n "$BINDING_NAME" ] && [ "$BINDING_NAME" != "null" ]; then
    echo "Role: $BINDING_NAME"
    kubectl get role "$BINDING_NAME" -n "$NAMESPACE" -o yaml 2>/dev/null | grep -A 10 "rules:" || \
    kubectl get clusterrole "$BINDING_NAME" -o yaml 2>/dev/null | grep -A 10 "rules:"
else
    echo "No direct role binding found"
fi

echo ""
echo "Troubleshooting suggestions:"
echo "1. Verify the subject name and type are correct"
echo "2. Check if the resource API group is specified correctly"
echo "3. Ensure the namespace exists and is accessible"
echo "4. Verify the role has the required verbs for the resource"
echo "5. Check for typos in resource names or verbs"
EOF

chmod +x diagnose-rbac-forbidden.sh

# Usage examples:
echo "Usage examples:"
echo "./diagnose-rbac-forbidden.sh serviceaccount my-sa default pods get"
echo "./diagnose-rbac-forbidden.sh user john@company.com kube-system services list"
```

**Solution:**
```bash
# Fix common RBAC permission issues
cat > fix-rbac-permissions.sh << 'EOF'
#!/bin/bash
echo "=== Fixing RBAC Permission Issues ==="

ACTION=$1
SUBJECT_TYPE=$2
SUBJECT_NAME=$3
NAMESPACE=${4:-default}

if [ -z "$ACTION" ] || [ -z "$SUBJECT_TYPE" ] || [ -z "$SUBJECT_NAME" ]; then
    echo "Usage: $0 <action> <subject-type> <subject-name> [namespace]"
    echo "Actions: create-basic, create-admin, create-readonly, fix-serviceaccount"
    echo "Subject types: user, serviceaccount, group"
    exit 1
fi

case $ACTION in
    "create-basic")
        echo "Creating basic permissions for $SUBJECT_TYPE: $SUBJECT_NAME"
        
        # Create basic role
        cat > basic-role.yaml << ROLE
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: $NAMESPACE
  name: ${SUBJECT_NAME}-basic
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["services"]
  verbs: ["get", "list"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "watch"]
ROLE

        # Create role binding
        cat > basic-rolebinding.yaml << BINDING
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ${SUBJECT_NAME}-basic-binding
  namespace: $NAMESPACE
subjects:
- kind: $(echo $SUBJECT_TYPE | sed 's/serviceaccount/ServiceAccount/; s/user/User/; s/group/Group/')
  name: $SUBJECT_NAME
  $([ "$SUBJECT_TYPE" = "serviceaccount" ] && echo "namespace: $NAMESPACE" || echo "apiGroup: rbac.authorization.k8s.io")
roleRef:
  kind: Role
  name: ${SUBJECT_NAME}-basic
  apiGroup: rbac.authorization.k8s.io
BINDING

        kubectl apply -f basic-role.yaml
        kubectl apply -f basic-rolebinding.yaml
        echo " Basic permissions created"
        ;;
        
    "create-readonly")
        echo "Creating read-only permissions for $SUBJECT_TYPE: $SUBJECT_NAME"
        
        cat > readonly-rolebinding.yaml << READONLY
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ${SUBJECT_NAME}-readonly
  namespace: $NAMESPACE
subjects:
- kind: $(echo $SUBJECT_TYPE | sed 's/serviceaccount/ServiceAccount/; s/user/User/; s/group/Group/')
  name: $SUBJECT_NAME
  $([ "$SUBJECT_TYPE" = "serviceaccount" ] && echo "namespace: $NAMESPACE" || echo "apiGroup: rbac.authorization.k8s.io")
roleRef:
  kind: ClusterRole
  name: view
  apiGroup: rbac.authorization.k8s.io
READONLY

        kubectl apply -f readonly-rolebinding.yaml
        echo " Read-only permissions created using built-in 'view' ClusterRole"
        ;;
        
    "create-admin")
        echo "  Creating admin permissions for $SUBJECT_TYPE: $SUBJECT_NAME"
        echo "This grants significant privileges. Proceed? (y/N)"
        read -r confirm
        
        if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
            cat > admin-rolebinding.yaml << ADMIN
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ${SUBJECT_NAME}-admin
  namespace: $NAMESPACE
subjects:
- kind: $(echo $SUBJECT_TYPE | sed 's/serviceaccount/ServiceAccount/; s/user/User/; s/group/Group/')
  name: $SUBJECT_NAME
  $([ "$SUBJECT_TYPE" = "serviceaccount" ] && echo "namespace: $NAMESPACE" || echo "apiGroup: rbac.authorization.k8s.io")
roleRef:
  kind: ClusterRole
  name: admin
  apiGroup: rbac.authorization.k8s.io
ADMIN

            kubectl apply -f admin-rolebinding.yaml
            echo " Admin permissions created using built-in 'admin' ClusterRole"
        else
            echo "Admin permission creation cancelled"
        fi
        ;;
        
    "fix-serviceaccount")
        echo "Fixing service account: $SUBJECT_NAME in namespace: $NAMESPACE"
        
        # Ensure service account exists
        kubectl get sa "$SUBJECT_NAME" -n "$NAMESPACE" 2>/dev/null || \
        kubectl create sa "$SUBJECT_NAME" -n "$NAMESPACE"
        
        # Create a sensible default role for service accounts
        cat > sa-default-role.yaml << SA_ROLE
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: $NAMESPACE
  name: ${SUBJECT_NAME}-role
rules:
- apiGroups: [""]
  resources: ["pods", "pods/status"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["configmaps", "secrets"]
  verbs: ["get"]
- apiGroups: [""]
  resources: ["events"]
  verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ${SUBJECT_NAME}-binding
  namespace: $NAMESPACE
subjects:
- kind: ServiceAccount
  name: $SUBJECT_NAME
  namespace: $NAMESPACE
roleRef:
  kind: Role
  name: ${SUBJECT_NAME}-role
  apiGroup: rbac.authorization.k8s.io
SA_ROLE

        kubectl apply -f sa-default-role.yaml
        echo " Service account $SUBJECT_NAME configured with default permissions"
        ;;
        
    *)
        echo "Unknown action: $ACTION"
        exit 1
        ;;
esac

# Verify permissions were applied
echo ""
echo "Verifying applied permissions..."
if [ "$SUBJECT_TYPE" = "serviceaccount" ]; then
    kubectl auth can-i --list --as="system:serviceaccount:${NAMESPACE}:${SUBJECT_NAME}" -n "$NAMESPACE" | head -10
else
    kubectl auth can-i --list --as="$SUBJECT_NAME" -n "$NAMESPACE" | head -10
fi

# Cleanup temp files
rm -f basic-role.yaml basic-rolebinding.yaml readonly-rolebinding.yaml admin-rolebinding.yaml sa-default-role.yaml
EOF

chmod +x fix-rbac-permissions.sh
```

## Service Account Problems

### Issue: Pod cannot access Kubernetes API

**Symptoms:**
- Pods getting 401 Unauthorized errors
- Applications unable to call Kubernetes API
- Service account tokens not working

**Diagnosis:**
```bash
# Service account debugging
cat > debug-serviceaccount.sh << 'EOF'
#!/bin/bash
echo "=== Service Account Debugging ==="

SA_NAME=${1:-default}
NAMESPACE=${2:-default}
POD_NAME=$3

echo "Debugging Service Account: $SA_NAME in namespace: $NAMESPACE"

# Check if service account exists
echo "1. Service Account Status:"
if kubectl get sa "$SA_NAME" -n "$NAMESPACE" >/dev/null 2>&1; then
    echo " Service Account exists"
    kubectl get sa "$SA_NAME" -n "$NAMESPACE" -o yaml | grep -A 5 secrets
else
    echo " Service Account not found"
    exit 1
fi

# Check service account token
echo "2. Service Account Token:"
TOKEN_SECRET=$(kubectl get sa "$SA_NAME" -n "$NAMESPACE" -o jsonpath='{.secrets[0].name}' 2>/dev/null)

if [ -n "$TOKEN_SECRET" ] && [ "$TOKEN_SECRET" != "null" ]; then
    echo " Token secret: $TOKEN_SECRET"
    
    # Verify token exists and is valid
    TOKEN=$(kubectl get secret "$TOKEN_SECRET" -n "$NAMESPACE" -o jsonpath='{.data.token}' 2>/dev/null | base64 -d)
    if [ -n "$TOKEN" ]; then
        echo " Token exists (length: ${#TOKEN} characters)"
        
        # Test token validity
        if curl -s -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc.cluster.local/api/v1/namespaces >/dev/null 2>&1; then
            echo " Token is valid"
        else
            echo " Token may be invalid or API server unreachable"
        fi
    else
        echo " No token found in secret"
    fi
else
    echo "  No token secret found (may be using projected tokens)"
fi

# Check RBAC permissions
echo "3. RBAC Permissions:"
kubectl auth can-i --list --as="system:serviceaccount:${NAMESPACE}:${SA_NAME}" -n "$NAMESPACE" | head -10

# If pod name provided, check pod-specific issues
if [ -n "$POD_NAME" ]; then
    echo "4. Pod-specific Analysis:"
    
    # Check if pod uses the service account
    POD_SA=$(kubectl get pod "$POD_NAME" -n "$NAMESPACE" -o jsonpath='{.spec.serviceAccountName}' 2>/dev/null)
    echo "Pod $POD_NAME uses service account: ${POD_SA:-default}"
    
    if [ "$POD_SA" = "$SA_NAME" ] || ([ -z "$POD_SA" ] && [ "$SA_NAME" = "default" ]); then
        echo " Pod uses correct service account"
        
        # Check if token is mounted
        echo "Checking token mount in pod..."
        kubectl exec "$POD_NAME" -n "$NAMESPACE" -- ls -la /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null && echo " Service account token mounted" || echo " Service account token not mounted"
        
        # Test API access from within pod
        echo "Testing API access from pod..."
        kubectl exec "$POD_NAME" -n "$NAMESPACE" -- wget -q --header="Authorization: Bearer \$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" --no-check-certificate https://kubernetes.default.svc.cluster.local/api/v1/namespaces -O - >/dev/null 2>&1 && echo " API access from pod successful" || echo " API access from pod failed"
    else
        echo " Pod uses different service account: $POD_SA"
    fi
fi

# Check for automountServiceAccountToken
echo "5. Service Account Auto-mount Status:"
AUTOMOUNT=$(kubectl get sa "$SA_NAME" -n "$NAMESPACE" -o jsonpath='{.automountServiceAccountToken}' 2>/dev/null)
if [ "$AUTOMOUNT" = "false" ]; then
    echo "  automountServiceAccountToken is disabled"
else
    echo " Service account token auto-mount is enabled"
fi

# Suggest fixes
echo ""
echo "Common fixes:"
echo "1. Ensure service account has proper RBAC permissions"
echo "2. Check if automountServiceAccountToken is not disabled"
echo "3. Verify pod is using the correct service account"
echo "4. For projected tokens, check TokenRequest API is working"
echo "5. Ensure API server is reachable from pod network"
EOF

chmod +x debug-serviceaccount.sh
```

**Solution:**
```bash
# Fix service account issues
cat > fix-serviceaccount.sh << 'EOF'
#!/bin/bash
echo "=== Fixing Service Account Issues ==="

SA_NAME=${1:-default}
NAMESPACE=${2:-default}
ISSUE_TYPE=$3

echo "Fixing Service Account: $SA_NAME in namespace: $NAMESPACE"

case $ISSUE_TYPE in
    "missing-sa")
        echo "Creating missing service account..."
        kubectl create sa "$SA_NAME" -n "$NAMESPACE"
        echo " Service account created"
        ;;
        
    "missing-permissions")
        echo "Adding basic permissions to service account..."
        cat > sa-basic-permissions.yaml << PERM
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: $NAMESPACE
  name: ${SA_NAME}-basic
rules:
- apiGroups: [""]
  resources: ["pods", "services", "configmaps"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["events"]
  verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ${SA_NAME}-basic-binding
  namespace: $NAMESPACE
subjects:
- kind: ServiceAccount
  name: $SA_NAME
  namespace: $NAMESPACE
roleRef:
  kind: Role
  name: ${SA_NAME}-basic
  apiGroup: rbac.authorization.k8s.io
PERM
        kubectl apply -f sa-basic-permissions.yaml
        rm sa-basic-permissions.yaml
        echo " Basic permissions added"
        ;;
        
    "enable-automount")
        echo "Enabling service account token auto-mount..."
        kubectl patch sa "$SA_NAME" -n "$NAMESPACE" -p '{"automountServiceAccountToken": true}'
        echo " Auto-mount enabled"
        ;;
        
    "recreate-token")
        echo "Recreating service account token secret..."
        
        # For Kubernetes < 1.24 with manual token secrets
        cat > sa-token-secret.yaml << TOKEN
apiVersion: v1
kind: Secret
metadata:
  name: ${SA_NAME}-token
  namespace: $NAMESPACE
  annotations:
    kubernetes.io/service-account.name: $SA_NAME
type: kubernetes.io/service-account-token
TOKEN
        
        kubectl apply -f sa-token-secret.yaml
        rm sa-token-secret.yaml
        echo " Token secret created"
        ;;
        
    "pod-restart")
        echo "Available pods using service account $SA_NAME:"
        kubectl get pods -n "$NAMESPACE" -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.serviceAccountName}{"\n"}{end}' | grep "$SA_NAME" || echo "No pods found using this service account"
        
        echo "Restart pods to pick up new service account configuration? (y/N)"
        read -r confirm
        if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
            kubectl get pods -n "$NAMESPACE" -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.serviceAccountName}{"\n"}{end}' | grep "$SA_NAME" | cut -f1 | while read pod; do
                kubectl delete pod "$pod" -n "$NAMESPACE" --grace-period=0 --force 2>/dev/null || true
                echo "Restarted pod: $pod"
            done
        fi
        ;;
        
    *)
        echo "Unknown issue type. Available types:"
        echo "  missing-sa - Create missing service account"
        echo "  missing-permissions - Add basic RBAC permissions"
        echo "  enable-automount - Enable token auto-mounting"
        echo "  recreate-token - Recreate service account token"
        echo "  pod-restart - Restart pods using the service account"
        ;;
esac

# Verify fix
echo ""
echo "Verifying service account status..."
kubectl get sa "$SA_NAME" -n "$NAMESPACE"
kubectl auth can-i --list --as="system:serviceaccount:${NAMESPACE}:${SA_NAME}" -n "$NAMESPACE" | head -5
EOF

chmod +x fix-serviceaccount.sh
```

## RBAC Security Hardening

### Implementing Least Privilege
```bash
# RBAC security hardening script
cat > harden-rbac.sh << 'EOF'
#!/bin/bash
echo "=== RBAC Security Hardening ==="

# Audit overly permissive roles
echo "1. Auditing overly permissive roles..."

echo "ClusterRoles with dangerous permissions:"
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]?.verbs[]? == "*" or .rules[]?.resources[]? == "*") | .metadata.name' | while read role; do
    echo "  $role has wildcard permissions"
    kubectl describe clusterrole "$role" | grep -A 5 "Resources:\|Verbs:"
    echo ""
done

# Check for subjects with cluster-admin
echo "2. Checking cluster-admin bindings..."
echo "Subjects with cluster-admin access:"
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name == "cluster-admin") | .subjects[]? | "  - \(.kind): \(.name) \(if .namespace then "(\(.namespace))" else "" end)"'

# Find service accounts with admin access
echo "3. Service accounts with admin privileges..."
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name == "admin" or .roleRef.name == "cluster-admin") | select(.subjects[]?.kind == "ServiceAccount") | "  - " + .metadata.name + ": " + (.subjects[] | select(.kind == "ServiceAccount") | .name + "@" + .namespace)'

# Remove default permissions from default service account
echo "4. Hardening default service accounts..."
kubectl get namespaces -o name | while read ns; do
    namespace=$(basename "$ns")
    
    # Remove any bindings to default service account
    kubectl get rolebindings -n "$namespace" -o json | jq -r '.items[] | select(.subjects[]?.name == "default" and .subjects[]?.kind == "ServiceAccount") | .metadata.name' | while read binding; do
        echo "  Found binding to default SA in $namespace: $binding"
        echo "Remove this binding? (y/N)"
        read -r confirm
        if [ "$confirm" = "y" ]; then
            kubectl delete rolebinding "$binding" -n "$namespace"
            echo "Removed binding: $binding"
        fi
    done
done

# Create security-focused roles
echo "5. Creating security-focused role templates..."

# Read-only role
cat > readonly-security-role.yaml << READONLY_ROLE
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: security-readonly
rules:
- apiGroups: [""]
  resources: ["pods", "services", "endpoints", "persistentvolumeclaims", "events", "configmaps", "secrets"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "daemonsets", "replicasets", "statefulsets"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["policy"]
  resources: ["podsecuritypolicies"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
  verbs: ["get", "list", "watch"]
READONLY_ROLE

# Developer role (namespace-scoped)
cat > developer-role.yaml << DEV_ROLE
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
  name: developer
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log", "pods/portforward"]
  verbs: ["get", "list", "watch", "create", "delete"]
- apiGroups: [""]
  resources: ["services"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]  # Read-only access to secrets
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: [""]
  resources: ["events"]
  verbs: ["get", "list", "watch"]
DEV_ROLE

# Monitoring role
cat > monitoring-role.yaml << MONITOR_ROLE
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: monitoring
rules:
- apiGroups: [""]
  resources: ["nodes", "nodes/metrics", "services", "endpoints", "pods"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["nodes/stats"]
  verbs: ["get"]
- nonResourceURLs: ["/metrics", "/metrics/cadvisor"]
  verbs: ["get"]
MONITOR_ROLE

kubectl apply -f readonly-security-role.yaml
kubectl apply -f developer-role.yaml  
kubectl apply -f monitoring-role.yaml

echo " Security-focused roles created"

# Cleanup
rm readonly-security-role.yaml developer-role.yaml monitoring-role.yaml

echo ""
echo "Hardening recommendations:"
echo "1. Remove wildcard permissions from custom roles"
echo "2. Use namespace-scoped roles instead of cluster roles when possible"
echo "3. Regularly audit and rotate service account tokens"
echo "4. Implement principle of least privilege"
echo "5. Monitor RBAC changes with audit logging"
echo "6. Use tools like kubectl-who-can for permission analysis"
EOF

chmod +x harden-rbac.sh
```

This RBAC troubleshooting guide provides tools to diagnose permission issues, debug service account problems, and implement security hardening for Kubernetes clusters. The scripts help identify and resolve common RBAC misconfigurations while promoting security best practices.