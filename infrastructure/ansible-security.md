# Ansible Security Troubleshooting Guide

This guide helps you secure Ansible automation and resolve security issues in playbooks, inventories, and deployments.


## Vault and Secrets Management

### Issue: Plaintext secrets in Ansible files

**Symptoms:**
- Passwords and keys visible in playbooks
- Unencrypted sensitive variables
- Secrets committed to version control

**Diagnosis:**
```bash
# Scan for unencrypted secrets
cat > scan-ansible-secrets.sh << 'EOF'
#!/bin/bash
echo " Ansible Secrets Security Scan " 

# Scan for plaintext secrets in playbooks
echo "1. Scanning playbooks for plaintext secrets:"
find . -name "*.yml" -o -name "*.yaml" | while read file; do
    echo "Scanning $file:"
    
    # Check for common secret patterns
    grep -n -i "password:\s*[\"'].*[\"']" "$file" && echo "    Plaintext password found"
    grep -n -i "api_key:\s*[\"'].*[\"']" "$file" && echo "    Plaintext API key found"
    grep -n -i "secret:\s*[\"'].*[\"']" "$file" && echo "    Plaintext secret found"
    grep -n -i "token:\s*[\"'].*[\"']" "$file" && echo "    Plaintext token found"
    
    # Check for private keys
    grep -n "BEGIN.*PRIVATE KEY" "$file" && echo "    Private key found"
    
    # Check for database connection strings
    grep -n -i "mysql://\|postgresql://\|mongodb://" "$file" && echo "    Database connection string found"
done

# Check for vault files without encryption
echo "2. Checking for unencrypted vault files:"
find . -name "*vault*" -o -name "group_vars/*" -o -name "host_vars/*" | while read file; do
    if [ -f "$file" ]; then
        if ! head -1 "$file" | grep -q "\$ANSIBLE_VAULT"; then
            echo "    Unencrypted vault file: $file"
        fi
    fi
done

# Check for secrets in inventory files
echo "3. Checking inventory files for secrets:"
find . -name "hosts*" -o -name "inventory*" | while read file; do
    if [ -f "$file" ]; then
        echo "Checking $file:"
        grep -n -i "ansible_ssh_pass\|ansible_become_pass" "$file" && echo "    Plaintext SSH/sudo password in inventory"
    fi
done
EOF

chmod +x scan-ansible-secrets.sh
./scan-ansible-secrets.sh
```

**Solution:**
```bash
# Implement Ansible Vault properly
cat > setup-ansible-vault.sh << 'EOF'
#!/bin/bash
echo " Setting up Ansible Vault Security "

# Create vault password file with proper permissions
echo "1. Creating vault password file..."
read -s -p "Enter vault password: " VAULT_PASS
echo "$VAULT_PASS" > .vault_pass
chmod 600 .vault_pass

# Add to .gitignore
echo ".vault_pass" >> .gitignore

# Create encrypted group variables
echo "2. Creating encrypted group variables..."
mkdir -p group_vars/all

cat > group_vars/all/vault.yml << 'VAULT_VARS'
# This file will be encrypted
vault_database_password: "supersecretpassword123"
vault_api_key: "sk-1234567890abcdef"
vault_ssl_private_key: |
  -----BEGIN PRIVATE KEY-----
  MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...
  -----END PRIVATE KEY-----
vault_service_account_key: |
  {
    "type": "service_account",
    "project_id": "my-project",
    "private_key_id": "key-id",
    "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
  }
VAULT_VARS

# Encrypt the vault file
ansible-vault encrypt group_vars/all/vault.yml --vault-password-file .vault_pass

# Create non-encrypted variables that reference vault variables
cat > group_vars/all/main.yml << 'MAIN_VARS'
# Public variables
database_host: "db.example.com"
database_port: 5432
database_name: "app_db"
database_user: "app_user"

# Reference encrypted variables
database_password: "{{ vault_database_password }}"
api_key: "{{ vault_api_key }}"
ssl_private_key: "{{ vault_ssl_private_key }}"
service_account_key: "{{ vault_service_account_key }}"

# SSL configuration
ssl_cert_path: "/etc/ssl/certs/app.crt"
ssl_key_path: "/etc/ssl/private/app.key"
MAIN_VARS

echo "3. Creating ansible.cfg with vault settings..."
cat > ansible.cfg << 'ANSIBLE_CFG'
[defaults]
vault_password_file = .vault_pass
host_key_checking = False
gather_facts = True
timeout = 30
forks = 10

# Security settings
private_key_file = ~/.ssh/ansible_key
remote_user = ansible
become = yes
become_method = sudo
become_user = root

# Logging
log_path = /var/log/ansible.log

[ssh_connection]
ssh_args = -o ControlMaster=auto -o ControlPersist=60s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
pipelining = True
ANSIBLE_CFG

echo " Ansible Vault security configured"
echo " Use 'ansible-vault edit group_vars/all/vault.yml' to modify secrets"
echo " Use 'ansible-vault view group_vars/all/vault.yml' to view secrets"
EOF

chmod +x setup-ansible-vault.sh

# Create vault management scripts
cat > vault-operations.sh << 'EOF'
#!/bin/bash
OPERATION=$1
FILE=$2

case $OPERATION in
    "create")
        if [ -z "$FILE" ]; then
            echo "Usage: $0 create <file-path>"
            exit 1
        fi
        ansible-vault create "$FILE" --vault-password-file .vault_pass
        ;;
    "edit")
        if [ -z "$FILE" ]; then
            echo "Usage: $0 edit <file-path>"
            exit 1
        fi
        ansible-vault edit "$FILE" --vault-password-file .vault_pass
        ;;
    "encrypt")
        if [ -z "$FILE" ]; then
            echo "Usage: $0 encrypt <file-path>"
            exit 1
        fi
        ansible-vault encrypt "$FILE" --vault-password-file .vault_pass
        ;;
    "decrypt")
        if [ -z "$FILE" ]; then
            echo "Usage: $0 decrypt <file-path>"
            exit 1
        fi
        ansible-vault decrypt "$FILE" --vault-password-file .vault_pass
        ;;
    "rekey")
        if [ -z "$FILE" ]; then
            echo "Usage: $0 rekey <file-path>"
            exit 1
        fi
        ansible-vault rekey "$FILE" --vault-password-file .vault_pass
        ;;
    *)
        echo "Usage: $0 {create|edit|encrypt|decrypt|rekey} <file-path>"
        exit 1
        ;;
esac
EOF

chmod +x vault-operations.sh
```

## Playbook Security

### Issue: Insecure playbook practices

**Symptoms:**
- Commands with shell injection risks
- Unsafe file permissions
- Missing input validation

**Diagnosis:**
```bash
# Audit playbook security
cat > audit-playbook-security.sh << 'EOF'
#!/bin/bash
echo "=== Ansible Playbook Security Audit ==="

# Check for shell injection vulnerabilities
echo "1. Checking for shell injection risks:"
find . -name "*.yml" -o -name "*.yaml" | while read file; do
    if grep -q "shell:\|command:" "$file"; then
        echo "Checking $file for shell injection risks:"
        
        # Check for user input in shell/command modules
        grep -n "shell:\|command:" "$file" | while IFS=: read line_num line_content; do
            if echo "$line_content" | grep -q "{{.*}}"; then
                echo "    Line $line_num: User input in shell/command - $line_content"
            fi
        done
        
        # Check for dangerous commands
        if grep -q "rm -rf\|sudo.*passwd\|wget.*|.*sh\|curl.*|.*sh" "$file"; then
            echo "    Potentially dangerous shell commands found"
        fi
    fi
done

# Check file permissions
echo "2. Checking file permissions:"
find . -name "*.yml" -o -name "*.yaml" | while read file; do
    if grep -q "mode:" "$file"; then
        echo "Checking permissions in $file:"
        
        # Check for overly permissive permissions
        if grep -q "mode:.*777\|mode:.*666" "$file"; then
            echo "    Overly permissive file permissions found"
        fi
    fi
done

# Check for unsafe downloads
echo "3. Checking for unsafe downloads:"
find . -name "*.yml" -o -name "*.yaml" | while read file; do
    if grep -q "get_url:\|uri:" "$file"; then
        echo "Checking downloads in $file:"
        
        # Check for HTTP downloads
        if grep -B5 -A5 "get_url:\|uri:" "$file" | grep -q "url:.*http://"; then
            echo "    Insecure HTTP download found"
        fi
        
        # Check for missing checksum validation
        if grep -A10 "get_url:" "$file" | grep -q "url:" && ! grep -A10 "get_url:" "$file" | grep -q "checksum:"; then
            echo "    Download without checksum validation"
        fi
    fi
done

# Check become usage
echo "4. Checking privilege escalation:"
find . -name "*.yml" -o -name "*.yaml" | while read file; do
    if grep -q "become:" "$file"; then
        echo "Checking privilege escalation in $file:"
        
        # Check for unnecessary become
        if grep -B3 -A3 "become: yes\|become: true" "$file" | grep -q "debug:\|set_fact:"; then
            echo "    Unnecessary privilege escalation for debug/set_fact"
        fi
    fi
done
EOF

chmod +x audit-playbook-security.sh
./audit-playbook-security.sh
```

**Solution:**
```bash
# Create secure playbook templates
cat > secure-playbook-examples.yml << 'EOF'
---
# Secure Ansible Playbook Examples
- name: Secure System Configuration
  hosts: all
  become: yes
  vars:
    # Use variables for repeated values
    app_user: "appuser"
    app_dir: "/opt/myapp"
    log_dir: "/var/log/myapp"
    
  tasks:
    # Secure file downloads with checksum validation
    - name: Download application binary securely
      get_url:
        url: "https://releases.example.com/myapp-v1.2.3.tar.gz"
        dest: "/tmp/myapp.tar.gz"
        mode: '0640'
        owner: root
        group: root
        # Always validate checksums for downloads
        checksum: "sha256:1234567890abcdef..."
        # Use HTTPS only
        validate_certs: yes
        timeout: 30
      register: download_result
      
    # Validate download before proceeding
    - name: Verify download completed successfully
      fail:
        msg: "Download failed or checksum mismatch"
      when: download_result.failed
      
    # Use copy instead of shell for file operations when possible
    - name: Extract application safely
      unarchive:
        src: "/tmp/myapp.tar.gz"
        dest: "{{ app_dir }}"
        remote_src: yes
        owner: "{{ app_user }}"
        group: "{{ app_user }}"
        mode: '0750'
        creates: "{{ app_dir }}/myapp"
        
    # Secure file permissions
    - name: Create application directories with proper permissions
      file:
        path: "{{ item.path }}"
        state: directory
        owner: "{{ item.owner }}"
        group: "{{ item.group }}"
        mode: "{{ item.mode }}"
      loop:
        - { path: "{{ app_dir }}", owner: "{{ app_user }}", group: "{{ app_user }}", mode: '0750' }
        - { path: "{{ log_dir }}", owner: "{{ app_user }}", group: "{{ app_user }}", mode: '0755' }
        - { path: "/etc/myapp", owner: "root", group: "{{ app_user }}", mode: '0750' }
        
    # Use template instead of shell for config generation
    - name: Generate secure configuration file
      template:
        src: myapp.conf.j2
        dest: /etc/myapp/myapp.conf
        owner: root
        group: "{{ app_user }}"
        mode: '0640'
        backup: yes
      notify: restart myapp
      
    # Validate input and use quote filter for shell commands
    - name: Configure system settings (with input validation)
      shell: |
        sysctl -w {{ item.key }}={{ item.value | quote }}
      loop:
        - { key: "net.ipv4.ip_forward", value: "0" }
        - { key: "net.ipv4.conf.all.send_redirects", value: "0" }
      when: 
        - item.key is defined
        - item.value is defined
        - item.key | regex_search('^[a-zA-Z0-9_.]+$')
      become: yes
      
    # Use service module instead of shell for service management
    - name: Ensure secure services are running
      service:
        name: "{{ item }}"
        state: started
        enabled: yes
      loop:
        - firewalld
        - auditd
        - chronyd
        
    # Secure firewall configuration
    - name: Configure firewall rules
      firewalld:
        port: "{{ item.port }}/{{ item.protocol }}"
        permanent: yes
        state: "{{ item.state }}"
        immediate: yes
      loop:
        - { port: "22", protocol: "tcp", state: "enabled" }    # SSH
        - { port: "80", protocol: "tcp", state: "enabled" }    # HTTP
        - { port: "443", protocol: "tcp", state: "enabled" }   # HTTPS
        - { port: "8080", protocol: "tcp", state: "disabled" } # Block insecure app port
      notify: reload firewalld
      
  handlers:
    - name: restart myapp
      service:
        name: myapp
        state: restarted
        
    - name: reload firewalld
      service:
        name: firewalld
        state: reloaded

# Security hardening playbook
- name: Security Hardening
  hosts: all
  become: yes
  tasks:
    # Disable unnecessary services
    - name: Disable insecure services
      service:
        name: "{{ item }}"
        state: stopped
        enabled: no
      loop:
        - telnet
        - rsh
        - rlogin
      ignore_errors: yes
      
    # Set secure file permissions on sensitive files
    - name: Secure sensitive system files
      file:
        path: "{{ item.path }}"
        owner: "{{ item.owner | default('root') }}"
        group: "{{ item.group | default('root') }}"
        mode: "{{ item.mode }}"
      loop:
        - { path: "/etc/shadow", mode: "0000" }
        - { path: "/etc/gshadow", mode: "0000" }
        - { path: "/etc/passwd", mode: "0644" }
        - { path: "/etc/group", mode: "0644" }
        - { path: "/etc/ssh/sshd_config", mode: "0600" }
        
    # Configure SSH securely
    - name: Configure secure SSH
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: "^{{ item.key }}"
        line: "{{ item.key }} {{ item.value }}"
        backup: yes
      loop:
        - { key: "Protocol", value: "2" }
        - { key: "PermitRootLogin", value: "no" }
        - { key: "PasswordAuthentication", value: "no" }
        - { key: "PermitEmptyPasswords", value: "no" }
        - { key: "X11Forwarding", value: "no" }
        - { key: "MaxAuthTries", value: "3" }
        - { key: "ClientAliveInterval", value: "300" }
        - { key: "ClientAliveCountMax", value: "2" }
      notify: restart sshd
      
  handlers:
    - name: restart sshd
      service:
        name: sshd
        state: restarted
EOF

# Create secure template example
mkdir -p templates

cat > templates/myapp.conf.j2 << 'EOF'
# Application configuration template
# Generated by Ansible - do not modify manually

[database]
host = {{ database_host }}
port = {{ database_port }}
name = {{ database_name }}
user = {{ database_user }}
# Password is retrieved from vault
password = {{ database_password }}

[security]
# Force HTTPS
force_ssl = true
ssl_cert = {{ ssl_cert_path }}
ssl_key = {{ ssl_key_path }}

# Session security
session_timeout = 3600
secure_cookies = true
http_only_cookies = true

[logging]
log_level = INFO
log_file = {{ log_dir }}/application.log
audit_log = {{ log_dir }}/audit.log

# Disable debug in production
{% if ansible_env is defined and ansible_env == 'production' %}
debug = false
{% else %}
debug = true
{% endif %}
EOF

echo " Secure playbook examples created"
```

## Connection Security

### Issue: Insecure connection configurations

**Symptoms:**
- SSH keys without passphrases
- Password authentication enabled
- Insecure connection methods

**Solution:**
```bash
# Configure secure Ansible connections
cat > configure-secure-connections.sh << 'EOF'
#!/bin/bash
echo " Configuring Secure Ansible Connections "

# Generate SSH key for Ansible with passphrase
echo "1. Generating SSH key for Ansible..."
ssh-keygen -t ed25519 -f ~/.ssh/ansible_key -C "ansible@$(hostname)" -N "$(openssl rand -base64 32)"

# Set proper permissions
chmod 600 ~/.ssh/ansible_key
chmod 644 ~/.ssh/ansible_key.pub

# Create SSH config for Ansible
echo "2. Creating SSH configuration..."
cat >> ~/.ssh/config << 'SSH_CONFIG'
# Ansible SSH Configuration
Host ansible-*
    User ansible
    IdentityFile ~/.ssh/ansible_key
    IdentitiesOnly yes
    StrictHostKeyChecking yes
    UserKnownHostsFile ~/.ssh/ansible_known_hosts
    Protocol 2
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
    MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512
    KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
    HostKeyAlgorithms ssh-ed25519,rsa-sha2-256,rsa-sha2-512
    PubkeyAuthentication yes
    PasswordAuthentication no
    ChallengeResponseAuthentication no
    GSSAPIAuthentication no
    ConnectTimeout 10
    ServerAliveInterval 60
    ServerAliveCountMax 3
SSH_CONFIG

# Create secure inventory template
echo "3. Creating secure inventory template..."
cat > inventory/production << 'INVENTORY'
# Production Inventory
[webservers]
web01 ansible_host=web01.example.com
web02 ansible_host=web02.example.com

[appservers]
app01 ansible_host=app01.example.com
app02 ansible_host=app02.example.com

[databases]
db01 ansible_host=db01.example.com

[production:children]
webservers
appservers
databases

[production:vars]
ansible_user=ansible
ansible_ssh_private_key_file=~/.ssh/ansible_key
ansible_ssh_common_args='-o StrictHostKeyChecking=yes -o UserKnownHostsFile=~/.ssh/ansible_known_hosts'
ansible_python_interpreter=/usr/bin/python3
ansible_become=yes
ansible_become_method=sudo
ansible_become_user=root
INVENTORY

# Create connection test playbook
echo "4. Creating connection test playbook..."
cat > test-connections.yml << 'TEST_PLAYBOOK'
---
- name: Test Secure Connections
  hosts: all
  gather_facts: no
  tasks:
    - name: Test connection
      ping:
      register: ping_result
      
    - name: Display connection status
      debug:
        msg: "Successfully connected to {{ inventory_hostname }}"
      when: ping_result is succeeded
      
    - name: Test privilege escalation
      command: whoami
      become: yes
      register: whoami_result
      
    - name: Verify root access
      debug:
        msg: "Privilege escalation successful: {{ whoami_result.stdout }}"
      when: whoami_result.stdout == "root"
      
    - name: Check SSH configuration
      shell: |
        grep -E "PasswordAuthentication|PermitRootLogin|Protocol" /etc/ssh/sshd_config
      register: ssh_config
      become: yes
      
    - name: Display SSH security settings
      debug:
        var: ssh_config.stdout_lines
TEST_PLAYBOOK

echo " Secure connection configuration created"
echo " Next steps:"
echo "1. Deploy SSH public key to target hosts"
echo "2. Configure sudo access for ansible user"
echo "3. Test connections with: ansible-playbook test-connections.yml -i inventory/production"
EOF

chmod +x configure-secure-connections.sh
```

## Security Hardening Playbooks

### Complete system hardening playbook

```yaml
# Create comprehensive hardening playbook
cat > hardening-playbook.yml << 'EOF'
---
- name: Linux Security Hardening
  hosts: all
  become: yes
  vars:
    # Security configuration variables
    max_log_file_size: 10
    num_logs: 5
    password_max_age: 90
    password_min_age: 1
    password_warn_age: 7
    login_retries: 3
    
  tasks:
    # System updates
    - name: Update package cache
      package:
        update_cache: yes
      when: ansible_os_family in ['Debian', 'RedHat']
      
    - name: Install security packages
      package:
        name:
          - aide              # Intrusion detection
          - auditd            # Audit daemon
          - fail2ban          # Brute force protection
          - rkhunter          # Rootkit hunter
          - chkrootkit        # Rootkit checker
          - logwatch          # Log monitoring
          - psacct            # Process accounting
        state: present
      
    # User and authentication hardening
    - name: Set password policy
      lineinfile:
        path: /etc/login.defs
        regexp: "^{{ item.key }}"
        line: "{{ item.key }}\t{{ item.value }}"
        backup: yes
      loop:
        - { key: "PASS_MAX_DAYS", value: "{{ password_max_age }}" }
        - { key: "PASS_MIN_DAYS", value: "{{ password_min_age }}" }
        - { key: "PASS_WARN_AGE", value: "{{ password_warn_age }}" }
        - { key: "LOGIN_RETRIES", value: "{{ login_retries }}" }
        - { key: "ENCRYPT_METHOD", value: "SHA512" }
        
    - name: Configure PAM password requirements
      lineinfile:
        path: /etc/pam.d/common-password
        regexp: "pam_pwquality.so"
        line: "password requisite pam_pwquality.so retry=3 minlen=12 maxrepeat=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 difok=4"
        backup: yes
      when: ansible_os_family == 'Debian'
      
    - name: Lock unused system accounts
      user:
        name: "{{ item }}"
        shell: /sbin/nologin
        lock_password: yes
      loop:
        - bin
        - daemon
        - adm
        - lp
        - sync
        - shutdown
        - halt
        - mail
        - operator
        - games
        - ftp
      ignore_errors: yes
      
    # Network security
    - name: Configure kernel security parameters
      sysctl:
        name: "{{ item.key }}"
        value: "{{ item.value }}"
        state: present
        reload: yes
        sysctl_file: /etc/sysctl.d/99-security.conf
      loop:
        # IP forwarding and redirects
        - { key: "net.ipv4.ip_forward", value: "0" }
        - { key: "net.ipv4.conf.all.send_redirects", value: "0" }
        - { key: "net.ipv4.conf.default.send_redirects", value: "0" }
        - { key: "net.ipv4.conf.all.accept_redirects", value: "0" }
        - { key: "net.ipv4.conf.default.accept_redirects", value: "0" }
        - { key: "net.ipv6.conf.all.accept_redirects", value: "0" }
        - { key: "net.ipv6.conf.default.accept_redirects", value: "0" }
        # Source routing
        - { key: "net.ipv4.conf.all.accept_source_route", value: "0" }
        - { key: "net.ipv4.conf.default.accept_source_route", value: "0" }
        - { key: "net.ipv6.conf.all.accept_source_route", value: "0" }
        - { key: "net.ipv6.conf.default.accept_source_route", value: "0" }
        # ICMP redirects
        - { key: "net.ipv4.conf.all.secure_redirects", value: "0" }
        - { key: "net.ipv4.conf.default.secure_redirects", value: "0" }
        # Log suspicious packets
        - { key: "net.ipv4.conf.all.log_martians", value: "1" }
        - { key: "net.ipv4.conf.default.log_martians", value: "1" }
        # Ignore ping requests
        - { key: "net.ipv4.icmp_echo_ignore_all", value: "1" }
        # SYN flood protection
        - { key: "net.ipv4.tcp_syncookies", value: "1" }
        - { key: "net.ipv4.tcp_max_syn_backlog", value: "2048" }
        - { key: "net.ipv4.tcp_synack_retries", value: "2" }
        - { key: "net.ipv4.tcp_syn_retries", value: "5" }
        # Memory protection
        - { key: "kernel.randomize_va_space", value: "2" }
        - { key: "kernel.kptr_restrict", value: "2" }
        - { key: "kernel.dmesg_restrict", value: "1" }
        # Process restrictions
        - { key: "fs.suid_dumpable", value: "0" }
        
    # File system security
    - name: Set file permissions on sensitive files
      file:
        path: "{{ item.path }}"
        owner: "{{ item.owner }}"
        group: "{{ item.group }}"
        mode: "{{ item.mode }}"
      loop:
        - { path: "/etc/passwd", owner: "root", group: "root", mode: "0644" }
        - { path: "/etc/shadow", owner: "root", group: "shadow", mode: "0640" }
        - { path: "/etc/group", owner: "root", group: "root", mode: "0644" }
        - { path: "/etc/gshadow", owner: "root", group: "shadow", mode: "0640" }
        - { path: "/etc/ssh/sshd_config", owner: "root", group: "root", mode: "0600" }
        - { path: "/etc/crontab", owner: "root", group: "root", mode: "0600" }
        - { path: "/etc/anacrontab", owner: "root", group: "root", mode: "0600" }
        
    # Audit configuration
    - name: Configure audit rules
      template:
        src: audit.rules.j2
        dest: /etc/audit/rules.d/security.rules
        owner: root
        group: root
        mode: '0600'
        backup: yes
      notify: restart auditd
      
    - name: Configure auditd
      lineinfile:
        path: /etc/audit/auditd.conf
        regexp: "^{{ item.key }}"
        line: "{{ item.key }} = {{ item.value }}"
        backup: yes
      loop:
        - { key: "max_log_file", value: "{{ max_log_file_size }}" }
        - { key: "num_logs", value: "{{ num_logs }}" }
        - { key: "max_log_file_action", value: "rotate" }
        - { key: "space_left_action", value: "email" }
        - { key: "admin_space_left_action", value: "halt" }
        - { key: "disk_full_action", value: "halt" }
        - { key: "disk_error_action", value: "halt" }
      notify: restart auditd
      
    # Fail2ban configuration
    - name: Configure fail2ban
      template:
        src: jail.local.j2
        dest: /etc/fail2ban/jail.local
        owner: root
        group: root
        mode: '0644'
        backup: yes
      notify: restart fail2ban
      
    # Disable unused services
    - name: Disable unnecessary services
      systemd:
        name: "{{ item }}"
        enabled: no
        state: stopped
      loop:
        - avahi-daemon
        - cups
        - rpcbind
        - nfs-server
        - ypserv
        - ypbind
        - tftp
        - talk
        - telnet
      ignore_errors: yes
      
    # File integrity monitoring
    - name: Initialize AIDE database
      command: aide --init
      args:
        creates: /var/lib/aide/aide.db.new
      register: aide_init
      
    - name: Move AIDE database
      command: mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
      when: aide_init is changed
      
    # Schedule security tasks
    - name: Schedule security scans
      cron:
        name: "{{ item.name }}"
        minute: "{{ item.minute }}"
        hour: "{{ item.hour }}"
        job: "{{ item.job }}"
        user: root
      loop:
        - name: "AIDE file integrity check"
          minute: "0"
          hour: "3"
          job: "/usr/bin/aide --check"
        - name: "Rootkit scan"
          minute: "30"
          hour: "2"
          job: "/usr/bin/rkhunter --check --sk --nocolors"
        - name: "System update check"
          minute: "0"
          hour: "6"
          job: "apt list --upgradable > /var/log/updates-available.log 2>&1"
          
  handlers:
    - name: restart auditd
      systemd:
        name: auditd
        state: restarted
        
    - name: restart fail2ban
      systemd:
        name: fail2ban
        state: restarted
        enabled: yes
EOF

# Create audit rules template
mkdir -p templates
cat > templates/audit.rules.j2 << 'EOF'
# Audit rules for security monitoring
# Generated by Ansible

# Delete all existing rules
-D

# Buffer size
-b 8192

# Failure mode (0=silent, 1=printk, 2=panic)
-f 1

# Monitor changes to audit configuration
-w /etc/audit/ -p wa -k audit-config
-w /etc/libaudit.conf -p wa -k audit-config
-w /etc/audisp/ -p wa -k audit-config

# Monitor changes to system configuration
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/hosts -p wa -k system-locale
-w /etc/hostname -p wa -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/localtime -p wa -k time-change

# Monitor login/logout events
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

# Monitor network environment
-a exit,always -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a exit,always -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

# Monitor privileged commands
-a exit,always -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a exit,always -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a exit,always -F path=/usr/bin/ssh -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Monitor file access
-a exit,always -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a exit,always -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a exit,always -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a exit,always -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# Make audit configuration immutable
-e 2
EOF

# Create fail2ban template
cat > templates/jail.local.j2 << 'EOF'
[DEFAULT]
# Ban duration (10 minutes)
bantime = 600

# Find time window (10 minutes)
findtime = 600

# Maximum number of retries
maxretry = 3

# Backend for log file monitoring
backend = systemd

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
maxretry = 5

[apache-auth]
enabled = true
port = http,https
logpath = %(apache_error_log)s

[nginx-http-auth]
enabled = true
port = http,https
logpath = %(nginx_error_log)s
EOF

echo " Security hardening playbook created"
```
