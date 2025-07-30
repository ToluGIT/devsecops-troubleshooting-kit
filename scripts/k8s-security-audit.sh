#!/bin/bash

# Kubernetes Security Audit Script
# This script performs a security audit of a Kubernetes cluster

set -e

# Configuration
AUDIT_DIR="k8s-security-audit-$(date +%Y%m%d-%H%M%S)"
NAMESPACE_FILTER=""
VERBOSE=false
EXPORT_FORMAT="text"

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_header() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

print_success() {
    echo -e "${GREEN} $1${NC}"
}

print_warning() {
    echo -e "${YELLOW} $1${NC}"
}

print_error() {
    echo -e "${RED} $1${NC}"
}

# Function to check if required tools are available
check_prerequisites() {
    print_header "Checking Prerequisites"
    
    local missing_tools=()
    
    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        missing_tools+=("kubectl")
    fi
    
    # Check jq
    if ! command -v jq &> /dev/null; then
        missing_tools+=("jq")
    fi
    
    # Check cluster connectivity
    if ! kubectl cluster-info &> /dev/null; then
        print_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        print_error "Missing required tools: ${missing_tools[*]}"
        exit 1
    fi
    
    print_success "All prerequisites met"
}

# Function to create audit directory structure
setup_audit_directory() {
    mkdir -p "$AUDIT_DIR"/{cluster,nodes,workloads,rbac,network,storage,images}
    echo "Kubernetes Security Audit - $(date)" > "$AUDIT_DIR/audit-summary.txt"
    echo "Cluster: $(kubectl config current-context)" >> "$AUDIT_DIR/audit-summary.txt"
    echo "" >> "$AUDIT_DIR/audit-summary.txt"
}

# Function to audit cluster-level security
audit_cluster_security() {
    print_header "Auditing Cluster Security"
    
    # Kubernetes version
    echo "1. Cluster Version Information" > "$AUDIT_DIR/cluster/version-info.txt"
    kubectl version --short >> "$AUDIT_DIR/cluster/version-info.txt" 2>/dev/null || \
        kubectl version >> "$AUDIT_DIR/cluster/version-info.txt" 2>/dev/null
    
    # Check for deprecated API versions
    echo "2. API Server Configuration" > "$AUDIT_DIR/cluster/api-server-config.txt"
    kubectl get --raw /api/v1 | jq -r '.resources[].name' | sort >> "$AUDIT_DIR/cluster/api-resources.txt"
    
    # Check etcd encryption
    echo "3. Checking etcd encryption status..." 
    if kubectl get secrets -A -o json | jq -e '.items[0].data' &>/dev/null; then
        print_success "Secrets appear to be encrypted"
        echo " Secrets encryption: ENABLED" >> "$AUDIT_DIR/cluster/encryption-status.txt"
    else
        print_warning "Cannot verify secret encryption"
        echo "  Secrets encryption: UNKNOWN" >> "$AUDIT_DIR/cluster/encryption-status.txt"
    fi
    
    # Admission controllers
    echo "4. Checking admission controllers..."
    kubectl get --raw /api/v1 | jq -r '.serverAddressByClientCIDRs[0].serverAddress' > "$AUDIT_DIR/cluster/server-info.txt" 2>/dev/null || echo "Server info unavailable" > "$AUDIT_DIR/cluster/server-info.txt"
    
    # Audit logging
    echo "5. Audit Policy (if accessible)..."
    kubectl get events --field-selector type=Warning -A --sort-by='.lastTimestamp' | head -20 > "$AUDIT_DIR/cluster/recent-warnings.txt"
    
    print_success "Cluster audit completed"
}

# Function to audit node security
audit_node_security() {
    print_header "Auditing Node Security"
    
    # Node information
    echo "1. Node Overview" > "$AUDIT_DIR/nodes/node-overview.txt"
    kubectl get nodes -o wide >> "$AUDIT_DIR/nodes/node-overview.txt"
    
    # Node conditions and security
    echo "2. Node Security Analysis" > "$AUDIT_DIR/nodes/node-security.txt"
    kubectl get nodes -o json | jq -r '.items[] | {
        name: .metadata.name,
        kernel: .status.nodeInfo.kernelVersion,
        os: .status.nodeInfo.osImage,
        runtime: .status.nodeInfo.containerRuntimeVersion,
        kubelet: .status.nodeInfo.kubeletVersion
    }' >> "$AUDIT_DIR/nodes/node-security.txt"
    
    # Check for node restrictions
    echo "3. Checking node taints and tolerations..."
    kubectl get nodes -o json | jq -r '.items[] | select(.spec.taints != null) | {name: .metadata.name, taints: .spec.taints}' > "$AUDIT_DIR/nodes/node-taints.txt"
    
    # Resource capacity and allocations
    echo "4. Resource Usage Analysis" > "$AUDIT_DIR/nodes/resource-usage.txt"
    kubectl describe nodes | grep -A 15 "Allocated resources:" >> "$AUDIT_DIR/nodes/resource-usage.txt"
    
    print_success "Node audit completed"
}

# Function to audit RBAC configuration
audit_rbac() {
    print_header "Auditing RBAC Configuration"
    
    # ClusterRoles with dangerous permissions
    echo "1. ClusterRoles Analysis" > "$AUDIT_DIR/rbac/dangerous-clusterroles.txt"
    kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]?.verbs[]? == "*" or .rules[]?.resources[]? == "*" or .rules[]?.apiGroups[]? == "*") | .metadata.name' >> "$AUDIT_DIR/rbac/dangerous-clusterroles.txt"
    
    # Cluster admin bindings
    echo "2. Cluster Admin Bindings" > "$AUDIT_DIR/rbac/cluster-admin-bindings.txt"
    kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name == "cluster-admin") | {binding: .metadata.name, subjects: .subjects}' >> "$AUDIT_DIR/rbac/cluster-admin-bindings.txt"
    
    # Service accounts with cluster roles
    echo "3. Service Account Privilege Analysis" > "$AUDIT_DIR/rbac/sa-privileges.txt"
    kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.subjects[]?.kind == "ServiceAccount") | {
        binding: .metadata.name,
        role: .roleRef.name,
        serviceAccounts: [.subjects[] | select(.kind == "ServiceAccount") | .name + "@" + .namespace]
    }' >> "$AUDIT_DIR/rbac/sa-privileges.txt"
    
    # Default service account permissions
    echo "4. Default Service Account Analysis" > "$AUDIT_DIR/rbac/default-sa-analysis.txt"
    kubectl get rolebindings,clusterrolebindings -A -o json | jq -r '.items[] | select(.subjects[]?.name == "default" and .subjects[]?.kind == "ServiceAccount") | {
        type: .kind,
        name: .metadata.name,
        namespace: .metadata.namespace,
        role: .roleRef.name
    }' >> "$AUDIT_DIR/rbac/default-sa-analysis.txt"
    
    # Unused service accounts
    echo "5. Unused Service Accounts" > "$AUDIT_DIR/rbac/unused-service-accounts.txt"
    comm -23 \
        <(kubectl get sa -A -o json | jq -r '.items[] | .metadata.namespace + "/" + .metadata.name' | sort) \
        <(kubectl get pods -A -o json | jq -r '.items[] | .metadata.namespace + "/" + (.spec.serviceAccountName // "default")' | sort | uniq) \
        >> "$AUDIT_DIR/rbac/unused-service-accounts.txt"
    
    print_success "RBAC audit completed"
}

# Function to audit workload security
audit_workload_security() {
    print_header "Auditing Workload Security"
    
    local namespaces
    if [ -n "$NAMESPACE_FILTER" ]; then
        namespaces="$NAMESPACE_FILTER"
    else
        namespaces=$(kubectl get namespaces -o name | cut -d'/' -f2 | tr '\n' ' ')
    fi
    
    for ns in $namespaces; do
        echo "Auditing namespace: $ns"
        mkdir -p "$AUDIT_DIR/workloads/$ns"
        
        # Pods with security issues
        echo "1. Pod Security Analysis for $ns" > "$AUDIT_DIR/workloads/$ns/pod-security.txt"
        kubectl get pods -n "$ns" -o json | jq -r '.items[] | {
            name: .metadata.name,
            runAsRoot: (.spec.securityContext.runAsUser // "not-set") == 0,
            privileged: (.spec.containers[].securityContext.privileged // false),
            allowPrivilegeEscalation: (.spec.containers[].securityContext.allowPrivilegeEscalation // true),
            readOnlyRootFilesystem: (.spec.containers[].securityContext.readOnlyRootFilesystem // false),
            capabilities: .spec.containers[].securityContext.capabilities
        }' >> "$AUDIT_DIR/workloads/$ns/pod-security.txt"
        
        # Pods running as root
        echo "2. Pods Running as Root" > "$AUDIT_DIR/workloads/$ns/root-pods.txt"
        kubectl get pods -n "$ns" -o json | jq -r '.items[] | select((.spec.securityContext.runAsUser // 0) == 0 or .spec.containers[].securityContext.runAsUser == 0) | .metadata.name' >> "$AUDIT_DIR/workloads/$ns/root-pods.txt"
        
        # Privileged pods
        echo "3. Privileged Pods" > "$AUDIT_DIR/workloads/$ns/privileged-pods.txt"
        kubectl get pods -n "$ns" -o json | jq -r '.items[] | select(.spec.containers[].securityContext.privileged == true) | .metadata.name' >> "$AUDIT_DIR/workloads/$ns/privileged-pods.txt"
        
        # Pods with host namespaces
        echo "4. Pods with Host Namespaces" > "$AUDIT_DIR/workloads/$ns/host-namespace-pods.txt"
        kubectl get pods -n "$ns" -o json | jq -r '.items[] | select(.spec.hostNetwork == true or .spec.hostPID == true or .spec.hostIPC == true) | {
            name: .metadata.name,
            hostNetwork: .spec.hostNetwork,
            hostPID: .spec.hostPID,
            hostIPC: .spec.hostIPC
        }' >> "$AUDIT_DIR/workloads/$ns/host-namespace-pods.txt"
        
        # Resource limits
        echo "5. Pods Without Resource Limits" > "$AUDIT_DIR/workloads/$ns/no-resource-limits.txt"
        kubectl get pods -n "$ns" -o json | jq -r '.items[] | select(.spec.containers[].resources.limits == null) | .metadata.name' >> "$AUDIT_DIR/workloads/$ns/no-resource-limits.txt"
        
        # Image analysis
        echo "6. Container Images" > "$AUDIT_DIR/workloads/$ns/container-images.txt"
        kubectl get pods -n "$ns" -o json | jq -r '.items[] | .spec.containers[] | {podName: .name, image: .image, pullPolicy: .imagePullPolicy}' >> "$AUDIT_DIR/workloads/$ns/container-images.txt"
    done
    
    print_success "Workload audit completed"
}

# Function to audit network security
audit_network_security() {
    print_header "Auditing Network Security"
    
    # Network policies
    echo "1. Network Policies Analysis" > "$AUDIT_DIR/network/network-policies.txt"
    kubectl get networkpolicies -A -o json | jq -r '.items[] | {
        namespace: .metadata.namespace,
        name: .metadata.name,
        podSelector: .spec.podSelector,
        ingress: .spec.ingress,
        egress: .spec.egress
    }' >> "$AUDIT_DIR/network/network-policies.txt"
    
    # Namespaces without network policies
    echo "2. Namespaces Without Network Policies" > "$AUDIT_DIR/network/namespaces-no-netpol.txt"
    comm -23 \
        <(kubectl get namespaces -o name | cut -d'/' -f2 | sort) \
        <(kubectl get networkpolicies -A -o json | jq -r '.items[].metadata.namespace' | sort | uniq) \
        >> "$AUDIT_DIR/network/namespaces-no-netpol.txt"
    
    # Services with external access
    echo "3. Services with External Access" > "$AUDIT_DIR/network/external-services.txt"
    kubectl get services -A -o json | jq -r '.items[] | select(.spec.type == "LoadBalancer" or .spec.type == "NodePort" or .spec.externalIPs != null) | {
        namespace: .metadata.namespace,
        name: .metadata.name,
        type: .spec.type,
        ports: .spec.ports,
        externalIPs: .spec.externalIPs
    }' >> "$AUDIT_DIR/network/external-services.txt"
    
    # Ingress configurations
    echo "4. Ingress Security Analysis" > "$AUDIT_DIR/network/ingress-analysis.txt"
    kubectl get ingress -A -o json | jq -r '.items[] | {
        namespace: .metadata.namespace,
        name: .metadata.name,
        tls: (.spec.tls != null),
        hosts: [.spec.rules[].host],
        annotations: .metadata.annotations
    }' >> "$AUDIT_DIR/network/ingress-analysis.txt"
    
    print_success "Network audit completed"
}

# Function to audit storage security
audit_storage_security() {
    print_header "Auditing Storage Security"
    
    # Persistent volumes without encryption
    echo "1. Persistent Volume Analysis" > "$AUDIT_DIR/storage/persistent-volumes.txt"
    kubectl get pv -o json | jq -r '.items[] | {
        name: .metadata.name,
        storageClass: .spec.storageClassName,
        accessModes: .spec.accessModes,
        capacity: .spec.capacity.storage
    }' >> "$AUDIT_DIR/storage/persistent-volumes.txt"
    
    # Storage classes
    echo "2. Storage Classes" > "$AUDIT_DIR/storage/storage-classes.txt"
    kubectl get storageclass -o json | jq -r '.items[] | {
        name: .metadata.name,
        provisioner: .provisioner,
        parameters: .parameters,
        allowVolumeExpansion: .allowVolumeExpansion
    }' >> "$AUDIT_DIR/storage/storage-classes.txt"
    
    # Pods with volume mounts
    echo "3. Volume Mounts Analysis" > "$AUDIT_DIR/storage/volume-mounts.txt"
    kubectl get pods -A -o json | jq -r '.items[] | {
        namespace: .metadata.namespace,
        name: .metadata.name,
        volumeMounts: [.spec.containers[].volumeMounts[]? | select(.mountPath == "/" or .mountPath == "/host" or .mountPath == "/var/run/docker.sock")]
    } | select(.volumeMounts != [])' >> "$AUDIT_DIR/storage/volume-mounts.txt"
    
    # Secrets and ConfigMaps
    echo "4. Secrets and ConfigMaps" > "$AUDIT_DIR/storage/secrets-configmaps.txt"
    kubectl get secrets,configmaps -A --no-headers | wc -l | awk '{print "Total secrets and configmaps: " $1}' >> "$AUDIT_DIR/storage/secrets-configmaps.txt"
    kubectl get secrets -A -o json | jq -r '.items[] | select(.metadata.name != "default-token" and .type != "kubernetes.io/service-account-token") | {
        namespace: .metadata.namespace,
        name: .metadata.name,
        type: .type
    }' >> "$AUDIT_DIR/storage/secrets-configmaps.txt"
    
    print_success "Storage audit completed"
}

# Function to audit container image security
audit_image_security() {
    print_header "Auditing Container Image Security"
    
    # Image analysis
    echo "1. Container Image Analysis" > "$AUDIT_DIR/images/image-analysis.txt"
    kubectl get pods -A -o json | jq -r '.items[] | .spec.containers[] | .image' | sort | uniq > "$AUDIT_DIR/images/unique-images.txt"
    
    # Images using latest tag
    echo "2. Images Using 'latest' Tag" > "$AUDIT_DIR/images/latest-tag-images.txt"
    kubectl get pods -A -o json | jq -r '.items[] | .spec.containers[] | select(.image | endswith(":latest") or (. | contains(":") | not)) | .image' | sort | uniq >> "$AUDIT_DIR/images/latest-tag-images.txt"
    
    # Images from public registries
    echo "3. Images from Public Registries" > "$AUDIT_DIR/images/public-registry-images.txt"
    kubectl get pods -A -o json | jq -r '.items[] | .spec.containers[] | select(.image | startswith("docker.io/") or startswith("gcr.io/") or startswith("quay.io/") or (. | contains("/") | not)) | .image' | sort | uniq >> "$AUDIT_DIR/images/public-registry-images.txt"
    
    # Image pull policies
    echo "4. Image Pull Policies" > "$AUDIT_DIR/images/pull-policies.txt"
    kubectl get pods -A -o json | jq -r '.items[] | .spec.containers[] | {
        image: .image,
        pullPolicy: .imagePullPolicy
    }' | sort | uniq >> "$AUDIT_DIR/images/pull-policies.txt"
    
    print_success "Image security audit completed"
}

# Function to generate security score
generate_security_score() {
    print_header "Generating Security Score"
    
    local total_score=100
    local deductions=0
    local recommendations=()
    
    # Check for common security issues
    if [ -s "$AUDIT_DIR/rbac/dangerous-clusterroles.txt" ]; then
        deductions=$((deductions + 15))
        recommendations+=("Review and restrict overly permissive ClusterRoles")
    fi
    
    if [ -s "$AUDIT_DIR/workloads/*/privileged-pods.txt" ]; then
        deductions=$((deductions + 20))
        recommendations+=("Remove privileged containers where possible")
    fi
    
    if [ -s "$AUDIT_DIR/network/namespaces-no-netpol.txt" ]; then
        deductions=$((deductions + 10))
        recommendations+=("Implement network policies for namespace isolation")
    fi
    
    if [ -s "$AUDIT_DIR/images/latest-tag-images.txt" ]; then
        deductions=$((deductions + 5))
        recommendations+=("Use specific image tags instead of 'latest'")
    fi
    
    local final_score=$((total_score - deductions))
    
    echo "Security Assessment Summary" > "$AUDIT_DIR/security-score.txt"
    echo "=========================" >> "$AUDIT_DIR/security-score.txt"
    echo "Overall Security Score: $final_score/100" >> "$AUDIT_DIR/security-score.txt"
    echo "" >> "$AUDIT_DIR/security-score.txt"
    echo "Recommendations:" >> "$AUDIT_DIR/security-score.txt"
    
    for rec in "${recommendations[@]}"; do
        echo "- $rec" >> "$AUDIT_DIR/security-score.txt"
    done
    
    if [ $final_score -ge 80 ]; then
        print_success "Security Score: $final_score/100 (Good)"
    elif [ $final_score -ge 60 ]; then
        print_warning "Security Score: $final_score/100 (Fair - Improvements needed)"
    else
        print_error "Security Score: $final_score/100 (Poor - Immediate attention required)"
    fi
}

# Function to create executive summary
create_executive_summary() {
    print_header "Creating Executive Summary"
    
    cat > "$AUDIT_DIR/executive-summary.txt" << EOF
Kubernetes Security Audit Executive Summary
==========================================
Date: $(date)
Cluster: $(kubectl config current-context)
Auditor: $(whoami)

Key Findings:
=============

1. RBAC Configuration:
   - ClusterRoles with excessive permissions: $([ -s "$AUDIT_DIR/rbac/dangerous-clusterroles.txt" ] && wc -l < "$AUDIT_DIR/rbac/dangerous-clusterroles.txt" || echo "0")
   - Cluster admin bindings: $(kubectl get clusterrolebindings -o json | jq '[.items[] | select(.roleRef.name == "cluster-admin")] | length')

2. Workload Security:
   - Total namespaces audited: $(kubectl get namespaces --no-headers | wc -l)
   - Privileged containers found: $(find "$AUDIT_DIR/workloads" -name "privileged-pods.txt" -exec cat {} \; | grep -v "^$" | wc -l)
   - Containers running as root: $(find "$AUDIT_DIR/workloads" -name "root-pods.txt" -exec cat {} \; | grep -v "^$" | wc -l)

3. Network Security:
   - Namespaces without network policies: $([ -s "$AUDIT_DIR/network/namespaces-no-netpol.txt" ] && wc -l < "$AUDIT_DIR/network/namespaces-no-netpol.txt" || echo "0")
   - Services with external access: $(kubectl get services -A -o json | jq '[.items[] | select(.spec.type == "LoadBalancer" or .spec.type == "NodePort")] | length')

4. Image Security:
   - Unique images in cluster: $(wc -l < "$AUDIT_DIR/images/unique-images.txt")
   - Images using 'latest' tag: $([ -s "$AUDIT_DIR/images/latest-tag-images.txt" ] && wc -l < "$AUDIT_DIR/images/latest-tag-images.txt" || echo "0")

Immediate Actions Required:
==========================
$(cat "$AUDIT_DIR/security-score.txt" | grep -A 100 "Recommendations:" | tail -n +2)

Detailed findings available in: $AUDIT_DIR/
EOF
    
    print_success "Executive summary created"
}

# Main execution function
main() {
    local start_time=$(date +%s)
    
    echo "Kubernetes Security Audit Tool"
    echo "==============================="
    echo "Start time: $(date)"
    echo ""
    
    # Run audit phases
    check_prerequisites
    setup_audit_directory
    audit_cluster_security
    audit_node_security
    audit_rbac
    audit_workload_security
    audit_network_security
    audit_storage_security
    audit_image_security
    generate_security_score
    create_executive_summary
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    print_header "Audit Complete"
    echo "Duration: ${duration} seconds"
    echo "Results saved to: $AUDIT_DIR/"
    echo ""
    echo "Key files:"
    echo "  - executive-summary.txt - High-level overview"
    echo "  - security-score.txt - Security assessment"
    echo "  - */  - Detailed findings by category"
    echo ""
    echo "Next steps:"
    echo "1. Review executive summary"
    echo "2. Address high-priority security issues"
    echo "3. Implement security hardening measures"
    echo "4. Schedule regular security audits"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--namespace)
            NAMESPACE_FILTER="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        --format)
            EXPORT_FORMAT="$2"
            shift 2
            ;;
        -h|--help)
            echo "Kubernetes Security Audit Script"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -n, --namespace NAMESPACE  Audit specific namespace only"
            echo "  -v, --verbose             Verbose output"
            echo "  --format FORMAT           Export format (text|json) [default: text]"
            echo "  -h, --help               Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                        # Audit entire cluster"
            echo "  $0 -n production          # Audit production namespace only"
            echo "  $0 -v --format json       # Verbose output with JSON format"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use -h or --help for usage information"
            exit 1
            ;;
    esac
done

# Execute main function
main