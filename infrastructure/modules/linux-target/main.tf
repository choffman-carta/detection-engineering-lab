# Linux Target Module - Ubuntu container with security tooling

resource "docker_image" "linux_target" {
  name         = var.target_image
  keep_locally = true
}

# Dockerfile for customized target with security tooling
resource "local_file" "dockerfile" {
  filename = "${path.module}/build/Dockerfile"
  content  = <<-EOT
FROM ${var.target_image}

ENV DEBIAN_FRONTEND=noninteractive

# Install base packages
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    vim \
    netcat-openbsd \
    net-tools \
    iproute2 \
    procps \
    htop \
    strace \
    ltrace \
    tcpdump \
    nmap \
    python3 \
    python3-pip \
    rsyslog \
    auditd \
    audispd-plugins \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install osquery
RUN curl -L https://pkg.osquery.io/deb/osquery_5.9.1-1.linux_amd64.deb -o /tmp/osquery.deb \
    && dpkg -i /tmp/osquery.deb \
    && rm /tmp/osquery.deb

# Install Atomic Red Team
RUN git clone --depth 1 https://github.com/redcanaryco/atomic-red-team.git /opt/atomic-red-team

# Configure rsyslog to forward to Vector
RUN echo '*.* @vector:5514' >> /etc/rsyslog.conf

# Configure auditd rules for common attack techniques
COPY auditd.rules /etc/audit/rules.d/detection-lab.rules

# Configure osquery
COPY osquery.conf /etc/osquery/osquery.conf

# Setup script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["tail", "-f", "/dev/null"]
EOT
}

resource "local_file" "auditd_rules" {
  filename = "${path.module}/build/auditd.rules"
  content  = <<-EOT
# Detection Lab Audit Rules
# Based on common MITRE ATT&CK techniques

# Log all commands executed by root
-a always,exit -F arch=b64 -F euid=0 -S execve -k root_commands
-a always,exit -F arch=b32 -F euid=0 -S execve -k root_commands

# Monitor password/shadow file access
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k identity

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Monitor cron
-w /etc/crontab -p wa -k cron
-w /etc/cron.d -p wa -k cron
-w /var/spool/cron -p wa -k cron

# Monitor network configuration
-w /etc/hosts -p wa -k hosts
-w /etc/resolv.conf -p wa -k resolv

# Monitor process injection attempts
-a always,exit -F arch=b64 -S ptrace -k process_injection
-a always,exit -F arch=b32 -S ptrace -k process_injection

# Monitor kernel module loading
-w /sbin/insmod -p x -k kernel_modules
-w /sbin/rmmod -p x -k kernel_modules
-w /sbin/modprobe -p x -k kernel_modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k kernel_modules

# Monitor suspicious binary locations
-w /tmp -p x -k tmp_exec
-w /var/tmp -p x -k tmp_exec
-w /dev/shm -p x -k tmp_exec

# Monitor successful and failed login attempts
-w /var/log/lastlog -p wa -k logins
-w /var/log/faillog -p wa -k logins

# Monitor persistence locations
-w /etc/rc.local -p wa -k persistence
-w /etc/init.d -p wa -k persistence
-w /etc/systemd -p wa -k persistence
EOT
}

resource "local_file" "osquery_conf" {
  filename = "${path.module}/build/osquery.conf"
  content  = jsonencode({
    options = {
      logger_plugin     = "filesystem"
      logger_path       = "/var/log/osquery"
      disable_logging   = false
      schedule_splay_percent = 10
    }
    schedule = {
      process_events = {
        query    = "SELECT * FROM process_events;"
        interval = 10
      }
      socket_events = {
        query    = "SELECT * FROM socket_events;"
        interval = 10
      }
      user_events = {
        query    = "SELECT * FROM user_events;"
        interval = 30
      }
      file_events = {
        query    = "SELECT * FROM file_events;"
        interval = 30
      }
      shell_history = {
        query    = "SELECT * FROM shell_history;"
        interval = 60
      }
      crontab = {
        query    = "SELECT * FROM crontab;"
        interval = 60
      }
      listening_ports = {
        query    = "SELECT * FROM listening_ports;"
        interval = 30
      }
      users = {
        query    = "SELECT * FROM users;"
        interval = 300
      }
    }
    file_paths = {
      etc = ["/etc/%%"]
      tmp = ["/tmp/%%"]
      home = ["/home/%%"]
    }
  })
}

resource "local_file" "entrypoint" {
  filename = "${path.module}/build/entrypoint.sh"
  content  = <<-EOT
#!/bin/bash
set -e

# Start rsyslog
service rsyslog start

# Start auditd
service auditd start || true

# Start osqueryd
osqueryd --config_path=/etc/osquery/osquery.conf --daemonize

echo "Linux target initialized with security tooling"
echo "- auditd: running"
echo "- osquery: running"
echo "- rsyslog: forwarding to Vector"

# Execute main command
exec "$@"
EOT
}

# Build the custom image
resource "null_resource" "build_target_image" {
  triggers = {
    dockerfile = local_file.dockerfile.content
    auditd     = local_file.auditd_rules.content
    osquery    = local_file.osquery_conf.content
    entrypoint = local_file.entrypoint.content
  }

  provisioner "local-exec" {
    command     = "cd ${path.module}/build && docker build -t ${var.project_name}-linux-target:latest ."
    interpreter = ["/bin/bash", "-c"]
  }

  depends_on = [
    local_file.dockerfile,
    local_file.auditd_rules,
    local_file.osquery_conf,
    local_file.entrypoint
  ]
}

resource "docker_container" "linux_target" {
  name  = "${var.project_name}-linux-target"
  image = "${var.project_name}-linux-target:latest"

  restart    = "unless-stopped"
  privileged = true

  networks_advanced {
    name = var.network_name
  }

  env = [
    "VECTOR_HOST=${var.vector_host}",
    "LAB_NAME=${var.project_name}"
  ]

  # Capabilities for auditd and tracing
  capabilities {
    add = ["SYS_PTRACE", "NET_RAW", "NET_ADMIN", "AUDIT_CONTROL", "AUDIT_READ"]
  }

  dynamic "labels" {
    for_each = var.labels
    content {
      label = labels.key
      value = labels.value
    }
  }

  depends_on = [null_resource.build_target_image]
}
