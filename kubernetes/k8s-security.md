# Kubernetes Security Troubleshooting Guide

This guide helps you identify, troubleshoot, and resolve security issues in Kubernetes clusters, from RBAC misconfigurations to pod security vulnerabilities.

## Table of Contents

- [RBAC & Access Control](#rbac--access-control)
- [Pod Security Standards](#pod-security-standards)
- [Network Policies](#network-policies)
- [Secrets Management](#secrets-management)
- [Admission Controllers](#admission-controllers)
- [Runtime Security](#runtime-security)
- [Service Mesh Security](#service-mesh-security)
- [Compliance & CIS Benchmarks](#compliance--cis-benchmarks)
- [Security Monitoring](#security-monitoring)
- [Incident Response](#incident-response)

## RBAC & Access Control

### Overprivileged Service Accounts

#### Issue: Service accounts with excessive cluster permissions

**Symptoms:**
- Pods running with cluster-admin privileges
- Service accounts with unnecessary API access
- Security scanner flagging RBAC violations

**Diagnosis:**
```bash
# Identify overprivileged service accounts
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.subjects[]?.kind == "ServiceAccount") | "\(.metadata.name): \(.subjects[] | select(.kind == "ServiceAccount") | "\(.namespace)/\(.name)")"'

# Check specific service account permissions
kubectl auth can-i --list --as=system:serviceaccount:default:my-service-account

# Find service accounts with cluster-admin
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name == "cluster-admin") | .subjects[] | select(.kind == "ServiceAccount") | "\(.namespace)/\(.name)"'

# Audit current pod service account usage
kubectl get pods --all-namespaces -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,SERVICE_ACCOUNT:.spec.serviceAccountName | grep -v "default"

# Check what resources a service account can access
cat > check-rbac-permissions.sh << 'EOF'
#!/bin/bash
SA_NAMESPACE=${1:-default}
SA_NAME=${2:-default}

echo "RBAC Analysis for $SA_NAMESPACE/$SA_NAME"

# Direct role bindings
echo "Direct RoleBindings:"
kubectl get rolebindings --all-namespaces -o json | jq -r --arg ns "$SA_NAMESPACE" --arg name "$SA_NAME" '.items[] | select(.subjects[]? | select(.kind == "ServiceAccount" and .namespace == $ns and .name == $name)) | "\(.metadata.namespace)/\(.metadata.name) -> \(.roleRef.name)"'

# Direct cluster role bindings  
echo "Direct ClusterRoleBindings:"
kubectl get clusterrolebindings -o json | jq -r --arg ns "$SA_NAMESPACE" --arg name "$SA_NAME" '.items[] | select(.subjects[]? | select(.kind == "ServiceAccount" and .namespace == $ns and .name == $name)) | "\(.metadata.name) -> \(.roleRef.name)"'

# Test specific permissions
echo "Testing critical permissions:"
PERMISSIONS=("create pods" "delete pods" "get secrets" "create clusterroles" "escalate" "bind" "impersonate")

for perm in "${PERMISSIONS[@]}"; do
    result=$(kubectl auth can-i $perm --as=system:serviceaccount:$SA_NAMESPACE:$SA_NAME 2>/dev/null)
    if [ "$result" = "yes" ]; then
        echo "Can $perm"
    else
        echo "Cannot $perm"
    fi
done
EOF
```

**Solution:**
```bash
# Create minimal privilege service accounts
cat > minimal-rbac.yaml << 'EOF'
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-reader
  namespace: production
  
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: production
  name: app-reader-role
rules:
- apiGroups: [""]
  resources: ["configmaps", "secrets"]
  verbs: ["get", "list"]
  resourceNames: ["app-config", "app-secrets"]  # Restrict to specific resources
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-reader-binding
  namespace: production
subjects:
- kind: ServiceAccount
  name: app-reader
  namespace: production
roleRef:
  kind: Role
  name: app-reader-role
  apiGroup: rbac.authorization.k8s.io
EOF

# Replace overprivileged assignments
kubectl delete clusterrolebinding dangerous-binding
kubectl apply -f minimal-rbac.yaml

# Update pod spec to use minimal service account
cat > secure-pod.yaml << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
spec:
  serviceAccountName: app-reader  # Use minimal privilege account
  automountServiceAccountToken: false  # Disable if not needed
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
EOF

# Audit and cleanup script
cat > rbac-cleanup.sh << 'EOF'
#!/bin/bash
echo "RBAC Security Cleanup"

# Find unused service accounts
echo "Unused service accounts:"
for ns in $(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}'); do
    for sa in $(kubectl get serviceaccounts -n $ns -o jsonpath='{.items[*].metadata.name}'); do
        if [ "$sa" != "default" ]; then
            pod_count=$(kubectl get pods -n $ns --field-selector=spec.serviceAccountName=$sa --no-headers 2>/dev/null | wc -l)
            if [ "$pod_count" -eq 0 ]; then
                echo "  $ns/$sa (not used by any pods)"
            fi
        fi
    done
done

# Find cluster-admin bindings to investigate
echo "Cluster-admin bindings requiring review:"
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name == "cluster-admin") | "\(.metadata.name): \(.subjects)"'

# Find bindings with dangerous permissions
echo "Potentially dangerous permissions:"
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]?.verbs[]? == "escalate" or .rules[]?.verbs[]? == "bind" or .rules[]?.verbs[]? == "impersonate") | .metadata.name'
EOF
```

### User Access Issues

#### Issue: Users cannot access required resources

**Symptoms:**
- "Forbidden" errors when accessing resources
- kubectl commands failing with permission denied
- Applications unable to read ConfigMaps/Secrets

**Diagnosis:**
```bash
# Test user permissions
kubectl auth can-i create pods --as=user@company.com
kubectl auth can-i get secrets --as=user@company.com --namespace=production

# Check what user can do
kubectl auth can-i --list --as=user@company.com --namespace=production

# Find user's role bindings
kubectl get rolebindings,clusterrolebindings -A -o json | jq -r '.items[] | select(.subjects[]?.name == "user@company.com") | "\(.kind)/\(.metadata.name) in \(.metadata.namespace // "cluster") -> \(.roleRef.name)"'

# Debug authentication
kubectl config current-context
kubectl config view --minify
```

**Solution:**
```bash
# Create appropriate role for user needs
cat > user-permissions.yaml << 'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: development
  name: developer-role
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log", "configmaps"]
  verbs: ["get", "list", "create", "update", "patch", "delete"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "create", "update", "patch", "delete"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]  # Read-only access to secrets

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: developer-binding
  namespace: development
subjects:
- kind: User
  name: developer@company.com
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: developer-role
  apiGroup: rbac.authorization.k8s.io
EOF

kubectl apply -f user-permissions.yaml

# Verify permissions were applied
kubectl auth can-i create pods --as=developer@company.com --namespace=development
```

## Pod Security Standards

### Pod Security Policy Violations

#### Issue: Pods running with insecure configurations

**Symptoms:**
- Containers running as root
- Privileged containers in production
- Containers with dangerous capabilities

**Diagnosis:**
```bash
# Find privileged pods
kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.containers[]?.securityContext?.privileged == true) | "\(.metadata.namespace)/\(.metadata.name)"'

# Find root-running containers
kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.containers[]?.securityContext?.runAsUser == 0 or (.spec.containers[]?.securityContext?.runAsUser == null and .spec.securityContext?.runAsUser == null)) | "\(.metadata.namespace)/\(.metadata.name)"'

# Check for dangerous capabilities
kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.containers[]?.securityContext?.capabilities?.add[]? == "SYS_ADMIN" or .spec.containers[]?.securityContext?.capabilities?.add[]? == "NET_ADMIN") | "\(.metadata.namespace)/\(.metadata.name)"'

# Find pods with host namespace access
kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.hostNetwork == true or .spec.hostPID == true or .spec.hostIPC == true) | "\(.metadata.namespace)/\(.metadata.name): hostNetwork=\(.spec.hostNetwork), hostPID=\(.spec.hostPID), hostIPC=\(.spec.hostIPC)"'

# Pod security audit script
cat > pod-security-audit.sh << 'EOF'
#!/bin/bash
echo " Pod Security Audit "

echo "1. Privileged containers:"
kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.containers[]?.securityContext?.privileged == true) | "  \(.metadata.namespace)/\(.metadata.name)"'

echo -e "\n2. Root-running containers:"
kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.containers[]?.securityContext?.runAsUser == 0) | "  \(.metadata.namespace)/\(.metadata.name)"'

echo -e "\n3. Containers with host access:"
kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.hostNetwork == true or .spec.hostPID == true or .spec.hostIPC == true) | "  \(.metadata.namespace)/\(.metadata.name)"'

echo -e "\n4. Containers without resource limits:"
kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.containers[] | has("resources") | not) | "  \(.metadata.namespace)/\(.metadata.name)"'

echo -e "\n5. Containers with dangerous capabilities:"
kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.containers[]?.securityContext?.capabilities?.add[]? | test("SYS_ADMIN|NET_ADMIN|SYS_PTRACE")) | "  \(.metadata.namespace)/\(.metadata.name)"'
EOF
```

**Solution:**
```bash
# Implement Pod Security Standards
cat > pod-security-standards.yaml << 'EOF'
# Namespace with restricted security standard
apiVersion: v1
kind: Namespace
metadata:
  name: production-secure
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted

---
# Secure pod specification
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
  namespace: production-secure
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      runAsUser: 1000
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
    resources:
      limits:
        memory: "256Mi"
        cpu: "250m"
      requests:
        memory: "128Mi"
        cpu: "100m"
    volumeMounts:
    - name: tmp
      mountPath: /tmp
    - name: cache
      mountPath: /app/cache
  volumes:
  - name: tmp
    emptyDir: {}
  - name: cache
    emptyDir: {}
EOF

# Apply security policies using OPA Gatekeeper
cat > gatekeeper-policy.yaml << 'EOF'
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8srequiredsecuritycontext
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredSecurityContext
      validation:
        properties:
          runAsNonRoot:
            type: boolean
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredsecuritycontext
        
        violation[{"msg": msg}] {
            container := input.review.object.spec.containers[_]
            not container.securityContext.runAsNonRoot == true
            msg := "Container must run as non-root user"
        }
        
        violation[{"msg": msg}] {
            container := input.review.object.spec.containers[_]
            container.securityContext.allowPrivilegeEscalation == true
            msg := "Container must not allow privilege escalation"
        }

---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredSecurityContext
metadata:
  name: must-have-security-context
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    excludedNamespaces: ["kube-system", "kube-public"]
  parameters:
    runAsNonRoot: true
EOF

kubectl apply -f gatekeeper-policy.yaml
```

### Security Context Issues

#### Issue: Missing or inadequate security contexts

**Solution:**
```bash
# Create security context baseline
cat > security-baseline.yaml << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: baseline-secure-pod
spec:
  # Pod-level security context
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    supplementalGroups: [1000]
    seLinuxOptions:
      level: "s0:c123,c456"
    seccompProfile:
      type: RuntimeDefault
    sysctls:
    - name: net.ipv4.ip_unprivileged_port_start
      value: "1024"
  
  containers:
  - name: app
    image: myapp:latest
    # Container-level security context (overrides pod-level)
    securityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      runAsUser: 1000
      runAsGroup: 1000
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
        add:
        - NET_BIND_SERVICE  # Only if needed for port < 1024
    
    # Resource constraints for security
    resources:
      limits:
        memory: "512Mi"
        cpu: "500m"
        ephemeral-storage: "1Gi"
      requests:
        memory: "256Mi"
        cpu: "250m"
        ephemeral-storage: "512Mi"
    
    # Volume mounts for writable directories
    volumeMounts:
    - name: tmp-volume
      mountPath: /tmp
    - name: cache-volume
      mountPath: /app/cache
    - name: logs-volume
      mountPath: /app/logs
  
  volumes:
  - name: tmp-volume
    emptyDir:
      sizeLimit: "100Mi"
  - name: cache-volume
    emptyDir:
      sizeLimit: "500Mi"
  - name: logs-volume
    emptyDir:
      sizeLimit: "1Gi"
EOF

# Deployment with security context
cat > secure-deployment.yaml << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-web-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: secure-web-app
  template:
    metadata:
      labels:
        app: secure-web-app
    spec:
      serviceAccountName: web-app-sa  # Minimal privilege SA
      automountServiceAccountToken: false  # Disable if not needed
      
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      
      containers:
      - name: web
        image: nginx:1.21-alpine
        ports:
        - containerPort: 8080  # Non-privileged port
        
        securityContext:
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          runAsUser: 1000
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
        
        resources:
          limits:
            memory: "256Mi"
            cpu: "250m"
          requests:
            memory: "128Mi"
            cpu: "100m"
        
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: var-cache
          mountPath: /var/cache/nginx
        - name: var-run
          mountPath: /var/run
        - name: nginx-config
          mountPath: /etc/nginx/nginx.conf
          subPath: nginx.conf
          readOnly: true
      
      volumes:
      - name: tmp
        emptyDir: {}
      - name: var-cache
        emptyDir: {}
      - name: var-run
        emptyDir: {}
      - name: nginx-config
        configMap:
          name: nginx-config
EOF
```

## Network Policies

### Network Segmentation Issues

#### Issue: Pods can communicate without restrictions

**Diagnosis:**
```bash
# Check if network policies are enabled
kubectl get networkpolicies --all-namespaces

# Test pod-to-pod connectivity
kubectl exec -it pod1 -- nc -zv pod2-service 80

# Check current network policy coverage
cat > network-policy-audit.sh << 'EOF'
#!/bin/bash
echo "=== Network Policy Audit ==="

# Check namespaces without network policies
echo "Namespaces without network policies:"
for ns in $(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}'); do
    policy_count=$(kubectl get networkpolicies -n $ns --no-headers 2>/dev/null | wc -l)
    if [ "$policy_count" -eq 0 ] && [ "$ns" != "kube-system" ] && [ "$ns" != "kube-public" ]; then
        echo " $ns (no network policies)"
    fi
done

# Check for default-deny policies
echo -e "\nNamespaces with default-deny policies:"
kubectl get networkpolicies --all-namespaces -o json | jq -r '.items[] | select(.spec.podSelector == {}) | "\(.metadata.namespace)/\(.metadata.name)"'
EOF
```

**Solution:**
```bash
# Implement default-deny network policy
cat > default-deny.yaml << 'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}  # Applies to all pods in namespace
  policyTypes:
  - Ingress
  - Egress
  # No ingress/egress rules = deny all traffic
EOF

# Allow specific communication patterns
cat > app-network-policies.yaml << 'EOF'
# Allow frontend to communicate with backend
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-to-backend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080

---
# Allow backend to communicate with database
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-to-database
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Egress
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432
  # Allow DNS resolution
  - to: []
    ports:
    - protocol: UDP
      port: 53

---
# Allow ingress controller to reach frontend
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ingress-to-frontend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: frontend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 80
    - protocol: TCP
      port: 443
EOF

kubectl apply -f default-deny.yaml
kubectl apply -f app-network-policies.yaml

# Test network policy effectiveness
cat > test-network-policies.sh << 'EOF'
#!/bin/bash
echo "=== Testing Network Policy Enforcement ==="

# Test 1: Frontend should be able to reach backend
echo "Testing frontend -> backend (should succeed):"
kubectl exec -n production deployment/frontend -- curl -s --connect-timeout 5 http://backend:8080/health

# Test 2: Frontend should NOT be able to reach database directly  
echo "Testing frontend -> database (should fail):"
kubectl exec -n production deployment/frontend -- curl -s --connect-timeout 5 http://database:5432 && echo "FAILED: Frontend can reach database" || echo "SUCCESS: Frontend blocked from database"

# Test 3: Backend should be able to reach database
echo "Testing backend -> database (should succeed):"
kubectl exec -n production deployment/backend -- nc -zv database 5432

# Test 4: External access should be blocked
echo "Testing external access (should be blocked by default-deny):"
kubectl run test-pod --rm -it --image=busybox --restart=Never --namespace=production -- wget -qO- --timeout=5 http://frontend
EOF
```

## Secrets Management

### Secret Exposure Issues

#### Issue: Secrets visible in cluster or container environment

**Diagnosis:**
```bash
# Check for secrets with weak encoding
kubectl get secrets --all-namespaces -o json | jq -r '.items[] | select(.type == "Opaque") | "\(.metadata.namespace)/\(.metadata.name)"'

# Decode and check secret contents  
kubectl get secret mysecret -o jsonpath='{.data.password}' | base64 -d

# Find pods with secrets as environment variables
kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.containers[].env[]?.valueFrom.secretKeyRef) | "\(.metadata.namespace)/\(.metadata.name)"'

# Check for automounted service account tokens
kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.automountServiceAccountToken != false) | "\(.metadata.namespace)/\(.metadata.name)"'

# Secrets audit script
cat > secrets-audit.sh << 'EOF'
#!/bin/bash
echo "Kubernetes Secrets Security Audit"

echo "1. Secrets exposed as environment variables:"
kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.containers[].env[]?.valueFrom.secretKeyRef) | " \(.metadata.namespace)/\(.metadata.name) exposes secrets as env vars"'

echo -e "\n2. Service account tokens that are auto-mounted:"
kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.automountServiceAccountToken != false and (.spec.automountServiceAccountToken == null or .spec.automountServiceAccountToken == true)) | " \(.metadata.namespace)/\(.metadata.name)"'

echo -e "\n3. Secrets without proper labels/annotations:"
kubectl get secrets --all-namespaces -o json | jq -r '.items[] | select(.metadata.labels == null or .metadata.annotations == null) | " \(.metadata.namespace)/\(.metadata.name)"'

echo -e "\n4. Old secrets (> 90 days):"
NINETY_DAYS_AGO=$(date -d '90 days ago' -u +%Y-%m-%dT%H:%M:%SZ)
kubectl get secrets --all-namespaces -o json | jq -r --arg date "$NINETY_DAYS_AGO" '.items[] | select(.metadata.creationTimestamp < $date) | " \(.metadata.namespace)/\(.metadata.name) created \(.metadata.creationTimestamp)"'
EOF
```

**Solution:**
```bash
# Use volume mounts instead of environment variables
cat > secure-secret-usage.yaml << 'EOF'
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
  namespace: production
  labels:
    app: myapp
    security.policy/encrypt-at-rest: "true"
  annotations:
    secret.reloader.stakater.com/match: "true"
    vault.security.banzaicloud.io/vault-addr: "https://vault.company.com"
type: Opaque
data:
  database-password: <base64-encoded-password>
  api-key: <base64-encoded-key>

---
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
spec:
  serviceAccountName: app-reader
  automountServiceAccountToken: false  # Disable if not needed
  
  containers:
  - name: app
    image: myapp:latest
    
    # DON'T do this - secrets in environment variables
    # env:
    # - name: DB_PASSWORD
    #   valueFrom:
    #     secretKeyRef:
    #       name: app-secrets
    #       key: database-password
    
    # DO this - mount secrets as files
    volumeMounts:
    - name: secrets-volume
      mountPath: "/etc/secrets"
      readOnly: true
    
    # Application reads from files
    command: ["/app/start.sh"]
    args: ["--db-password-file=/etc/secrets/database-password"]
  
  volumes:
  - name: secrets-volume
    secret:
      secretName: app-secrets
      defaultMode: 0400  # Read-only for owner only
EOF

# External secrets integration with Vault
cat > external-secrets.yaml << 'EOF'
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: vault-backend
  namespace: production
spec:
  provider:
    vault:
      server: "https://vault.company.com"
      path: "secret"
      version: "v2"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "external-secrets-role"

---
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: vault-secret
  namespace: production
spec:
  refreshInterval: 15s
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: app-secrets
    creationPolicy: Owner
  data:
  - secretKey: database-password
    remoteRef:
      key: secret/myapp
      property: db_password
  - secretKey: api-key
    remoteRef:
      key: secret/myapp
      property: api_key
EOF

# Secret rotation automation
cat > rotate-secrets.sh << 'EOF'
#!/bin/bash
echo "=== Secret Rotation Process ==="

SECRET_NAME=${1:-app-secrets}
NAMESPACE=${2:-production}

# Generate new password
NEW_PASSWORD=$(openssl rand -base64 32)

# Update external secret store (Vault example)
vault kv put secret/myapp db_password="$NEW_PASSWORD"

# Force external-secrets to refresh
kubectl annotate externalsecret vault-secret -n $NAMESPACE force-sync=$(date +%s)

# Wait for secret update
echo "Waiting for secret update..."
sleep 30

# Restart pods that use the secret
kubectl rollout restart deployment/myapp -n $NAMESPACE

# Verify rotation
echo "Verifying secret rotation..."
kubectl get secret $SECRET_NAME -n $NAMESPACE -o jsonpath='{.metadata.annotations.external-secrets\.io/last-sync-time}'
EOF
```

## Runtime Security

### Container Runtime Monitoring

#### Detecting suspicious runtime activity

```bash
# Deploy Falco for runtime security
cat > falco-security-rules.yaml << 'EOF'
# Custom Falco rules for Kubernetes
- rule: Suspicious Container Network Activity
  desc: Detect unusual network connections from containers
  condition: >
    container and
    fd.type=ipv4 and
    (fd.net != "127.0.0.1" and fd.net != "localhost") and
    not k8s_containers
  output: >
    Suspicious network activity from container 
    (user=%user.name container=%container.name 
     command=%proc.cmdline connection=%fd.name)
  priority: WARNING

- rule: Container Crypto Mining Activity  
  desc: Detect cryptocurrency mining in containers
  condition: >
    container and
    (proc.name in (xmrig, cpuminer, ccminer) or
     proc.cmdline contains stratum+tcp)
  output: >
    Cryptocurrency mining detected in container
    (user=%user.name container=%container.name 
     command=%proc.cmdline)
  priority: CRITICAL

- rule: K8s Secret Access
  desc: Detect access to Kubernetes secrets
  condition: >
    container and k8s_containers and
    fd.name startswith /var/run/secrets/kubernetes.io/serviceaccount
  output: >
    Container accessing service account token
    (user=%user.name container=%container.name 
     file=%fd.name command=%proc.cmdline)
  priority: INFO

- rule: Privilege Escalation Attempt
  desc: Detect attempts to escalate privileges
  condition: >
    container and
    (proc.name in (su, sudo, setuid, setgid) or
     (syscall.type=setuid and evt.dir=>) or
     (syscall.type=setgid and evt.dir=>))
  output: >
    Privilege escalation attempt in container
    (user=%user.name container=%container.name 
     command=%proc.cmdline)
  priority: HIGH
EOF

# Runtime monitoring script
cat > runtime-monitor.sh << 'EOF'
#!/bin/bash
echo "Runtime Security Monitoring"

# Monitor process activity in containers
echo "1. Monitoring unusual process spawning..."
kubectl get pods --all-namespaces -o json | jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name)"' | while read pod; do
    namespace=$(echo $pod | cut -d/ -f1)
    name=$(echo $pod | cut -d/ -f2)
    
    # Check for suspicious processes
    processes=$(kubectl exec -n $namespace $name -- ps aux 2>/dev/null | grep -E "(wget|curl|nc|ncat|socat|python|perl|bash|sh).*http" || true)
    if [ ! -z "$processes" ]; then
        echo "Suspicious network activity in $pod"
        echo "$processes"
    fi
done

# Monitor network connections
echo -e "\n2. Checking for unusual network connections..."
kubectl get pods --all-namespaces -o json | jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name)"' | while read pod; do
    namespace=$(echo $pod | cut -d/ -f1)
    name=$(echo $pod | cut -d/ -f2)
    
    # Check for connections to suspicious ports
    connections=$(kubectl exec -n $namespace $name -- netstat -tun 2>/dev/null | grep -E ":(22|23|135|445|1433|3306|3389|5432|6379|27017)" || true)
    if [ ! -z "$connections" ]; then
        echo "Potentially suspicious connections from $pod"
        echo "$connections"
    fi
done

# Check for containers with unusual resource usage
echo -e "\n3. Checking resource usage patterns..."
kubectl top pods --all-namespaces --sort-by=cpu | head -10 | while read line; do
    if [[ $line =~ ([0-9]+)m.*([0-9]+)Mi && ${BASH_REMATCH[1]} -gt 500 ]]; then
        echo "High CPU usage: $line"
    fi
done
EOF

chmod +x runtime-monitor.sh
```

## Emergency Response

### Kubernetes Security Incident Response

```bash
# Emergency cluster isolation script
cat > k8s-emergency-response.sh << 'EOF'
#!/bin/bash
NAMESPACE=${1}
POD_NAME=${2}
INCIDENT_ID=${3:-"incident-$(date +%Y%m%d-%H%M%S)"}

if [ -z "$NAMESPACE" ] || [ -z "$POD_NAME" ]; then
    echo "Usage: $0 <namespace> <pod-name> [incident-id]"
    exit 1
fi

echo "KUBERNETES SECURITY INCIDENT RESPONSE"
echo "Incident ID: $INCIDENT_ID"
echo "Target: $NAMESPACE/$POD_NAME"
echo "Time: $(date)"

# Create incident directory
INCIDENT_DIR="incidents/$INCIDENT_ID"
mkdir -p $INCIDENT_DIR

# Step 1: Immediate isolation
echo "Step 1: Isolating pod..."
kubectl patch pod $POD_NAME -n $NAMESPACE -p '{"spec":{"nodeSelector":{"quarantine":"true"}}}'
kubectl label pod $POD_NAME -n $NAMESPACE quarantined=true

# Step 2: Evidence collection
echo "Step 2: Collecting evidence..."

# Pod description and status
kubectl describe pod $POD_NAME -n $NAMESPACE > $INCIDENT_DIR/pod-describe.txt

# Pod logs
kubectl logs $POD_NAME -n $NAMESPACE --all-containers=true > $INCIDENT_DIR/pod-logs.txt
kubectl logs $POD_NAME -n $NAMESPACE --previous --all-containers=true > $INCIDENT_DIR/pod-logs-previous.txt 2>/dev/null || true

# Pod manifest
kubectl get pod $POD_NAME -n $NAMESPACE -o yaml > $INCIDENT_DIR/pod-manifest.yaml

# Network policies affecting the pod
kubectl get networkpolicies -n $NAMESPACE -o yaml > $INCIDENT_DIR/networkpolicies.yaml

# Events related to the pod
kubectl get events -n $NAMESPACE --field-selector involvedObject.name=$POD_NAME > $INCIDENT_DIR/events.txt

# Cluster-wide events from the last hour
kubectl get events --all-namespaces --sort-by='.lastTimestamp' | tail -100 > $INCIDENT_DIR/cluster-events.txt

# Step 3: Runtime analysis
echo "Step 3: Performing runtime analysis..."
if kubectl exec -n $NAMESPACE $POD_NAME -- ps aux > $INCIDENT_DIR/processes.txt 2>/dev/null; then
    echo "Process list collected"
else
    echo "Could not collect process list"
fi

if kubectl exec -n $NAMESPACE $POD_NAME -- netstat -tulpn > $INCIDENT_DIR/network-connections.txt 2>/dev/null; then
    echo "Network connections collected"
else
    echo "Could not collect network connections"
fi

# Step 4: Check for persistence mechanisms
echo "Step 4: Checking for persistence..."

# Check if pod is part of a deployment/daemonset/statefulset
OWNER=$(kubectl get pod $POD_NAME -n $NAMESPACE -o jsonpath='{.metadata.ownerReferences[0].kind}')
if [ ! -z "$OWNER" ]; then
    echo "Pod is owned by: $OWNER"
    OWNER_NAME=$(kubectl get pod $POD_NAME -n $NAMESPACE -o jsonpath='{.metadata.ownerReferences[0].name}')
    kubectl get $OWNER $OWNER_NAME -n $NAMESPACE -o yaml > $INCIDENT_DIR/owner-manifest.yaml
fi

# Check secrets and configmaps used
kubectl get pod $POD_NAME -n $NAMESPACE -o json | jq -r '.spec.volumes[]? | select(.secret) | .secret.secretName' | while read secret; do
    kubectl get secret $secret -n $NAMESPACE -o yaml > $INCIDENT_DIR/secret-$secret.yaml
done

# Step 5: Network isolation
echo "Step 5: Implementing network isolation..."
cat > $INCIDENT_DIR/quarantine-policy.yaml << POLICY
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: quarantine-$POD_NAME
  namespace: $NAMESPACE
spec:
  podSelector:
    matchLabels:
      quarantined: "true"
  policyTypes:
  - Ingress
  - Egress
  # No rules = deny all traffic
POLICY

kubectl apply -f $INCIDENT_DIR/quarantine-policy.yaml

# Step 6: Create forensic snapshot
echo "Step 6: Creating forensic evidence..."
kubectl exec -n $NAMESPACE $POD_NAME -- tar -czf /tmp/forensic-snapshot.tar.gz /etc /var/log /tmp /home 2>/dev/null || true
kubectl cp $NAMESPACE/$POD_NAME:/tmp/forensic-snapshot.tar.gz $INCIDENT_DIR/forensic-snapshot.tar.gz 2>/dev/null || echo "Could not create forensic snapshot"

# Step 7: Generate incident report
echo "Step 7: Generating incident report..."
cat > $INCIDENT_DIR/incident-report.md << REPORT
# Kubernetes Security Incident Report

**Incident ID:** $INCIDENT_ID
**Date:** $(date)
**Handler:** $(kubectl config current-context | cut -d@ -f1)
**Affected Resource:** $NAMESPACE/$POD_NAME

## Incident Timeline
- $(date): Incident detected and response initiated
- $(date): Pod isolated and evidence collection started

## Evidence Collected
- [x] Pod description and manifest
- [x] Container logs (current and previous)
- [x] Process list and network connections
- [x] Related events and network policies
- [x] Forensic snapshot (if successful)

## Immediate Actions Taken
- [x] Pod isolated with quarantine label
- [x] Network policies applied to deny all traffic
- [x] Evidence preserved for analysis

## Next Steps
- [ ] Analyze collected evidence
- [ ] Determine attack vector and scope
- [ ] Check for lateral movement
- [ ] Review and update security controls
- [ ] Coordinate with incident response team

## Evidence Files
- pod-describe.txt: Pod configuration and status
- pod-logs.txt: Current container logs
- processes.txt: Running processes at time of isolation
- network-connections.txt: Active network connections
- quarantine-policy.yaml: Applied network isolation policy

REPORT

echo " INCIDENT RESPONSE COMPLETE"
echo "Evidence collected in: $INCIDENT_DIR"
echo "Pod quarantined and network isolated"
echo "Review incident-report.md for next steps"


EOF

chmod +x k8s-emergency-response.sh
```
