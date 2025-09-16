# Redis Installation Guide

Redis is a free and open-source in-memory data structure store used as database, cache, message broker, and streaming engine. Originally developed by Salvatore Sanfilippo, Redis (REmote DIctionary Server) is known for its performance, simplicity, and versatility. It serves as a FOSS alternative to commercial in-memory solutions like Amazon ElastiCache, Azure Cache for Redis, or Oracle Coherence, offering enterprise-grade features including persistence, replication, clustering, and pub/sub messaging without licensing costs.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Supported Operating Systems](#supported-operating-systems)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Service Management](#service-management)
6. [Troubleshooting](#troubleshooting)
7. [Security Considerations](#security-considerations)
8. [Performance Tuning](#performance-tuning)
9. [Backup and Restore](#backup-and-restore)
10. [System Requirements](#system-requirements)
11. [Support](#support)
12. [Contributing](#contributing)
13. [License](#license)
14. [Acknowledgments](#acknowledgments)
15. [Version History](#version-history)
16. [Appendices](#appendices)

## 1. Prerequisites

- **Hardware Requirements**:
  - CPU: 1 core minimum (2+ cores recommended for production)
  - RAM: 512MB minimum (4GB+ recommended for production)
  - Storage: 1GB minimum (SSD recommended for persistence)
  - Network: Stable connectivity for clustering and replication
- **Operating System**: 
  - Linux: Any modern distribution with kernel 3.2+
  - macOS: 10.13+ (High Sierra or newer)
  - Windows: Windows Server 2016+ or Windows 10
  - FreeBSD: 11.0+
- **Network Requirements**:
  - Port 6379 (default Redis port)
  - Port 26379 (Redis Sentinel)
  - Port 16379 (Redis Cluster bus port)
  - Additional ports for Redis instances in cluster mode
- **Dependencies**:
  - libc, libssl (usually included in distributions)
  - systemd or compatible init system (Linux)
  - Root or administrative access for installation
- **System Access**: root or sudo privileges required


## 2. Supported Operating Systems

This guide supports installation on:
- RHEL 8/9 and derivatives (CentOS Stream, Rocky Linux, AlmaLinux)
- Debian 11/12
- Ubuntu 20.04/22.04/24.04 LTS
- Arch Linux (rolling release)
- Alpine Linux 3.18+
- openSUSE Leap 15.5+ / Tumbleweed
- SUSE Linux Enterprise Server (SLES) 15+
- macOS 12+ (Monterey and later) 
- FreeBSD 13+
- Windows 10/11/Server 2019+ (where applicable)

## 3. Installation

### RHEL/CentOS/Rocky Linux/AlmaLinux

```bash
# Install EPEL repository
sudo dnf install -y epel-release

# Install Redis
sudo dnf install -y redis redis-tools

# Enable and start service
sudo systemctl enable --now redis

# Configure firewall
sudo firewall-cmd --permanent --add-port=6379/tcp
sudo firewall-cmd --reload

# Verify installation
redis-cli --version
redis-cli ping
```

### Debian/Ubuntu

```bash
# Update package index
sudo apt update

# Install Redis server and tools
sudo apt install -y redis-server redis-tools

# Enable and start service
sudo systemctl enable --now redis-server

# Configure firewall
sudo ufw allow 6379

# Verify installation
redis-cli --version
redis-cli ping
```

### Arch Linux

```bash
# Install Redis from official repositories
sudo pacman -S redis

# Enable and start service
sudo systemctl enable --now redis

# Install additional tools
sudo pacman -S redis-tools

# Configuration location: /etc/redis/redis.conf
```

### Alpine Linux

```bash
# Install Redis
apk add --no-cache redis

# Enable and start service
rc-update add redis default
rc-service redis start

# Install additional tools
apk add --no-cache redis-tools

# Configuration location: /etc/redis.conf
```

### openSUSE/SLES

```bash
# openSUSE Leap/Tumbleweed
sudo zypper install -y redis redis-tools

# SLES 15
sudo SUSEConnect -p sle-module-server-applications/15.5/x86_64
sudo zypper install -y redis

# Enable and start service
sudo systemctl enable --now redis

# Configure firewall
sudo firewall-cmd --permanent --add-port=6379/tcp
sudo firewall-cmd --reload

# Configuration location: /etc/redis/redis.conf
```

### macOS

```bash
# Using Homebrew
brew install redis

# Start Redis service
brew services start redis

# Or run manually
redis-server

# Configuration location: /usr/local/etc/redis.conf
# Alternative: /opt/homebrew/etc/redis.conf (Apple Silicon)
```

### FreeBSD

```bash
# Using pkg
pkg install redis

# Enable in rc.conf
echo 'redis_enable="YES"' >> /etc/rc.conf

# Start service
service redis start

# Configuration location: /usr/local/etc/redis.conf
```

### Windows

```bash
# Method 1: Using Chocolatey
choco install redis-64

# Method 2: Using Scoop
scoop install redis

# Method 3: Manual installation
# Download from https://github.com/microsoftarchive/redis/releases
# Extract and run redis-server.exe

# Install as Windows service using NSSM
nssm install Redis "C:\redis\redis-server.exe" "C:\redis\redis.windows.conf"
nssm start Redis

# Configuration location: C:\redis\redis.windows.conf
```

## Initial Configuration

### First-Run Setup

1. **Create redis user** (if not created by package):
```bash
# Linux systems
sudo useradd -r -d /var/lib/redis -s /sbin/nologin -c "Redis Server" redis
```

2. **Default configuration locations**:
- RHEL/CentOS/Rocky/AlmaLinux: `/etc/redis.conf` or `/etc/redis/redis.conf`
- Debian/Ubuntu: `/etc/redis/redis.conf`
- Arch Linux: `/etc/redis/redis.conf`
- Alpine Linux: `/etc/redis.conf`
- openSUSE/SLES: `/etc/redis/redis.conf`
- macOS: `/usr/local/etc/redis.conf`
- FreeBSD: `/usr/local/etc/redis.conf`
- Windows: `C:\redis\redis.windows.conf`

3. **Essential settings to change**:

```bash
# /etc/redis/redis.conf
# Network
bind 127.0.0.1
port 6379
protected-mode yes
timeout 300

# Security
requirepass SecureRedisPassword123!
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command DEBUG ""
rename-command CONFIG "CONFIG_$(openssl rand -hex 4)"

# Memory management
maxmemory 2gb
maxmemory-policy allkeys-lru
maxmemory-samples 5

# Persistence
save 900 1
save 300 10
save 60 10000
stop-writes-on-bgsave-error yes
rdbcompression yes
rdbchecksum yes
dbfilename dump.rdb
dir /var/lib/redis

# AOF persistence
appendonly yes
appendfilename "appendonly.aof"
appendfsync everysec
no-appendfsync-on-rewrite no
auto-aof-rewrite-percentage 100
auto-aof-rewrite-min-size 64mb

# Logging
loglevel notice
logfile /var/log/redis/redis-server.log
syslog-enabled yes
syslog-ident redis

# Client connections
tcp-backlog 511
tcp-keepalive 300
```

### Testing Initial Setup

```bash
# Check if Redis is running
sudo systemctl status redis

# Test connection
redis-cli ping

# Test authentication (if password set)
redis-cli -a SecureRedisPassword123! ping

# Test basic operations
redis-cli set test "Hello Redis"
redis-cli get test

# Check Redis configuration
redis-cli config get "*"
```

**WARNING:** Enable authentication and configure firewall rules immediately after installation!

## 5. Service Management

### systemd (RHEL, Debian, Ubuntu, Arch, openSUSE)

```bash
# Enable Redis to start on boot
sudo systemctl enable redis

# Start Redis
sudo systemctl start redis

# Stop Redis
sudo systemctl stop redis

# Restart Redis
sudo systemctl restart redis

# Reload configuration
sudo systemctl reload redis

# Check status
sudo systemctl status redis

# View logs
sudo journalctl -u redis -f
```

### OpenRC (Alpine Linux)

```bash
# Enable Redis to start on boot
rc-update add redis default

# Start Redis
rc-service redis start

# Stop Redis
rc-service redis stop

# Restart Redis
rc-service redis restart

# Check status
rc-service redis status

# View logs
tail -f /var/log/redis.log
```

### rc.d (FreeBSD)

```bash
# Enable in /etc/rc.conf
echo 'redis_enable="YES"' >> /etc/rc.conf

# Start Redis
service redis start

# Stop Redis
service redis stop

# Restart Redis
service redis restart

# Check status
service redis status
```

### launchd (macOS)

```bash
# Using Homebrew services
brew services start redis
brew services stop redis
brew services restart redis

# Check status
brew services list | grep redis

# Manual control
redis-server /usr/local/etc/redis.conf
```

### Windows Service Manager

```powershell
# Start Redis service
net start Redis

# Stop Redis service
net stop Redis

# Using PowerShell
Start-Service Redis
Stop-Service Redis
Restart-Service Redis

# Check status
Get-Service Redis

# Using NSSM
nssm start Redis
nssm stop Redis
nssm restart Redis
```

## Advanced Configuration

### Master-Slave Replication

```bash
# Master configuration
# /etc/redis/redis-master.conf
port 6379
bind 0.0.0.0
requirepass MasterPassword123!
masterauth MasterPassword123!

# Slave configuration
# /etc/redis/redis-slave.conf
port 6380
bind 0.0.0.0
slaveof 192.168.1.100 6379
masterauth MasterPassword123!
requirepass SlavePassword123!
slave-read-only yes
slave-serve-stale-data yes
```

### Redis Cluster Configuration

```bash
# Cluster node configuration
port 7000
cluster-enabled yes
cluster-config-file nodes-7000.conf
cluster-node-timeout 15000
appendonly yes
requirepass ClusterPassword123!
masterauth ClusterPassword123!

# Create cluster (6 nodes minimum)
redis-cli --cluster create \
  192.168.1.10:7000 192.168.1.11:7000 192.168.1.12:7000 \
  192.168.1.13:7000 192.168.1.14:7000 192.168.1.15:7000 \
  --cluster-replicas 1 -a ClusterPassword123!
```

### Redis Sentinel Configuration

```bash
# /etc/redis/sentinel.conf
port 26379
sentinel monitor mymaster 192.168.1.100 6379 2
sentinel auth-pass mymaster MasterPassword123!
sentinel down-after-milliseconds mymaster 30000
sentinel failover-timeout mymaster 180000
sentinel parallel-syncs mymaster 1

# Notification scripts
sentinel notification-script mymaster /usr/local/bin/redis-notify.sh
sentinel client-reconfig-script mymaster /usr/local/bin/redis-reconfig.sh
```

## Reverse Proxy Setup

### nginx Configuration

```nginx
# /etc/nginx/sites-available/redis-proxy
upstream redis_backend {
    server 127.0.0.1:6379 max_fails=3 fail_timeout=30s;
    server 127.0.0.1:6380 max_fails=3 fail_timeout=30s backup;
}

server {
    listen 6379;
    proxy_pass redis_backend;
    proxy_timeout 1s;
    proxy_responses 1;
    error_log /var/log/nginx/redis.log;
}
```

### HAProxy Configuration

```haproxy
# /etc/haproxy/haproxy.cfg
frontend redis_frontend
    bind *:6379
    mode tcp
    option tcplog
    default_backend redis_servers

backend redis_servers
    mode tcp
    balance first
    option redis-check
    server redis1 127.0.0.1:6379 check
    server redis2 127.0.0.1:6380 check backup
```

### Twemproxy (Redis Proxy)

```yaml
# /etc/nutcracker/nutcracker.yml
redis_cluster:
  listen: 0.0.0.0:22122
  hash: fnv1a_64
  hash_tag: "{}"
  distribution: ketama
  auto_eject_hosts: true
  timeout: 400
  redis: true
  servers:
   - 127.0.0.1:6379:1
   - 127.0.0.1:6380:1
   - 127.0.0.1:6381:1
```

## Security Configuration

### Authentication and Authorization

```bash
# Set strong password
redis-cli config set requirepass "VerySecureRedisPassword123!"

# Create ACL users (Redis 6+)
redis-cli acl setuser app-user on \
  >AppUserPassword123! \
  ~cached:* ~session:* \
  +@read +@write -@dangerous

redis-cli acl setuser readonly-user on \
  >ReadOnlyPassword123! \
  ~* +@read -@write -@admin

# Save ACL configuration
redis-cli acl save
```

### SSL/TLS Configuration

```bash
# Generate SSL certificates
sudo mkdir -p /etc/redis/ssl
sudo openssl genrsa -out /etc/redis/ssl/redis-server-key.pem 4096
sudo openssl req -new -key /etc/redis/ssl/redis-server-key.pem \
  -out /etc/redis/ssl/redis-server-cert.csr \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=redis.example.com"
sudo openssl x509 -req -in /etc/redis/ssl/redis-server-cert.csr \
  -signkey /etc/redis/ssl/redis-server-key.pem \
  -out /etc/redis/ssl/redis-server-cert.pem -days 365

# Update Redis configuration
tls-port 6380
port 0
tls-cert-file /etc/redis/ssl/redis-server-cert.pem
tls-key-file /etc/redis/ssl/redis-server-key.pem
tls-protocols "TLSv1.2 TLSv1.3"
tls-prefer-server-ciphers yes
tls-session-caching no
```

### Firewall Rules

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow from 192.168.1.0/24 to any port 6379
sudo ufw reload

# firewalld (RHEL/CentOS/openSUSE)
sudo firewall-cmd --permanent --new-zone=redis
sudo firewall-cmd --permanent --zone=redis --add-source=192.168.1.0/24
sudo firewall-cmd --permanent --zone=redis --add-port=6379/tcp
sudo firewall-cmd --reload

# iptables
sudo iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 6379 -j ACCEPT
sudo iptables-save > /etc/iptables/rules.v4

# pf (FreeBSD)
# Add to /etc/pf.conf
pass in on $ext_if proto tcp from 192.168.1.0/24 to any port 6379

# Windows Firewall
New-NetFirewallRule -DisplayName "Redis" -Direction Inbound -Protocol TCP -LocalPort 6379 -RemoteAddress 192.168.1.0/24 -Action Allow
```

## Database Setup

### Database Creation and Management

```bash
# Redis doesn't require explicit database creation
# Databases are numbered 0-15 by default

# Select database
redis-cli select 0

# Create data structures
redis-cli hset user:1000 name "John Doe" email "john@example.com"
redis-cli sadd users:active 1000 1001 1002
redis-cli zadd leaderboard 100 "player1" 200 "player2"
redis-cli lpush notifications "New message" "System update"

# Set expiration
redis-cli expire user:1000 3600
redis-cli ttl user:1000

# Pipeline operations
redis-cli --pipe <<EOF
SET key1 value1
SET key2 value2
INCR counter
EOF
```

### Data Types and Use Cases

```bash
# Strings - caching, counters
redis-cli set cache:user:1000 '{"name":"John","age":30}'
redis-cli incr page_views
redis-cli setex session:abc123 3600 "user_data"

# Hashes - objects, user profiles
redis-cli hset product:1 name "Laptop" price 999.99 stock 50
redis-cli hgetall product:1

# Lists - queues, recent items
redis-cli lpush job_queue "process_order:123"
redis-cli rpop job_queue
redis-cli lrange recent_posts 0 9

# Sets - unique collections, tags
redis-cli sadd tags:post:1 "redis" "database" "cache"
redis-cli sinter tags:post:1 tags:post:2

# Sorted Sets - leaderboards, rankings
redis-cli zadd scores 100 "alice" 200 "bob" 150 "charlie"
redis-cli zrevrange scores 0 2 withscores

# Streams - event logging, messaging
redis-cli xadd events * action "user_login" user_id 1000 timestamp 1640995200
redis-cli xread streams events 0-0
```

## Performance Optimization

### System Tuning

```bash
# Kernel parameters for Redis
sudo tee -a /etc/sysctl.conf <<EOF
# Redis performance optimizations
vm.overcommit_memory = 1
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
vm.swappiness = 1
EOF

sudo sysctl -p

# Disable Transparent Huge Pages
echo 'never' | sudo tee /sys/kernel/mm/transparent_hugepage/enabled

# Make permanent
sudo tee /etc/systemd/system/disable-thp.service <<EOF
[Unit]
Description=Disable Transparent Huge Pages
DefaultDependencies=no
After=sysinit.target local-fs.target
Before=redis.service

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo never | tee /sys/kernel/mm/transparent_hugepage/enabled > /dev/null'

[Install]
WantedBy=basic.target
EOF

sudo systemctl enable --now disable-thp
```

### Redis Performance Tuning

```bash
# High-performance Redis configuration
# Memory optimization
maxmemory 8gb
maxmemory-policy allkeys-lru
maxmemory-samples 10

# Network optimization
tcp-backlog 65535
tcp-keepalive 300
timeout 0

# Persistence optimization
save 900 1
save 300 10
save 60 10000
rdbcompression yes
rdbchecksum yes

# AOF optimization
appendonly yes
appendfsync everysec
no-appendfsync-on-rewrite no
auto-aof-rewrite-percentage 100
auto-aof-rewrite-min-size 64mb
aof-rewrite-incremental-fsync yes

# Client optimization
client-output-buffer-limit normal 0 0 0
client-output-buffer-limit replica 256mb 64mb 60
client-output-buffer-limit pubsub 32mb 8mb 60

# Threading (Redis 6+)
io-threads 4
io-threads-do-reads yes
```

### Memory Management

```bash
# Monitor memory usage
redis-cli info memory

# Analyze memory usage by key pattern
redis-cli --bigkeys
redis-cli --memkeys
redis-cli memory usage key_name

# Memory optimization commands
redis-cli memory doctor
redis-cli memory stats
redis-cli memory purge
```

## Monitoring

### Built-in Monitoring

```bash
# Server information
redis-cli info
redis-cli info server
redis-cli info memory
redis-cli info replication
redis-cli info stats

# Real-time monitoring
redis-cli monitor
redis-cli --latency
redis-cli --latency-history -i 1

# Slow query log
redis-cli config set slowlog-log-slower-than 10000
redis-cli slowlog get 10
redis-cli slowlog reset

# Client connections
redis-cli client list
redis-cli client info
redis-cli info clients
```

### External Monitoring Setup

```bash
# Install Redis Exporter for Prometheus
wget https://github.com/oliver006/redis_exporter/releases/download/v1.55.0/redis_exporter-v1.55.0.linux-amd64.tar.gz
tar xzf redis_exporter-*.tar.gz
sudo cp redis_exporter /usr/local/bin/

# Create systemd service
sudo tee /etc/systemd/system/redis_exporter.service <<EOF
[Unit]
Description=Redis Exporter
After=network.target

[Service]
Type=simple
User=redis
Environment=REDIS_ADDR=redis://localhost:6379
Environment=REDIS_PASSWORD=SecureRedisPassword123!
ExecStart=/usr/local/bin/redis_exporter
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now redis_exporter
```

### Health Check Scripts

```bash
#!/bin/bash
# redis-health-check.sh

# Check Redis service
if ! systemctl is-active redis >/dev/null 2>&1; then
    echo "CRITICAL: Redis service is not running"
    exit 2
fi

# Check connectivity
if ! redis-cli ping >/dev/null 2>&1; then
    echo "CRITICAL: Cannot connect to Redis"
    exit 2
fi

# Check memory usage
MEMORY_USED=$(redis-cli info memory | grep 'used_memory:' | cut -d: -f2 | tr -d '\r')
MEMORY_MAX=$(redis-cli config get maxmemory | tail -1)

if [ "$MEMORY_MAX" != "0" ]; then
    MEMORY_USAGE=$((MEMORY_USED * 100 / MEMORY_MAX))
    if [ $MEMORY_USAGE -gt 90 ]; then
        echo "WARNING: High memory usage: ${MEMORY_USAGE}%"
        exit 1
    fi
fi

# Check replication (if configured)
REPLICATION_INFO=$(redis-cli info replication)
if echo "$REPLICATION_INFO" | grep -q "role:slave"; then
    LINK_STATUS=$(echo "$REPLICATION_INFO" | grep "master_link_status" | cut -d: -f2 | tr -d '\r')
    if [ "$LINK_STATUS" != "up" ]; then
        echo "WARNING: Replication link is down"
        exit 1
    fi
fi

echo "OK: Redis is healthy"
exit 0
```

## 9. Backup and Restore

### Backup Procedures

```bash
#!/bin/bash
# redis-backup.sh

BACKUP_DIR="/backup/redis/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Create RDB backup
redis-cli -a SecureRedisPassword123! bgsave
sleep 5

# Wait for background save to complete
while [ "$(redis-cli -a SecureRedisPassword123! lastsave)" = "$(redis-cli -a SecureRedisPassword123! lastsave)" ]; do
    sleep 1
done

# Copy RDB file
cp /var/lib/redis/dump.rdb "$BACKUP_DIR/"

# Backup AOF file if enabled
if [ -f /var/lib/redis/appendonly.aof ]; then
    redis-cli -a SecureRedisPassword123! bgrewriteaof
    sleep 5
    cp /var/lib/redis/appendonly.aof "$BACKUP_DIR/"
fi

# Backup configuration
cp /etc/redis/redis.conf "$BACKUP_DIR/"

# Compress backup
tar czf "$BACKUP_DIR.tar.gz" -C "$(dirname "$BACKUP_DIR")" "$(basename "$BACKUP_DIR")"
rm -rf "$BACKUP_DIR"

echo "Backup completed: $BACKUP_DIR.tar.gz"
```

### Restore Procedures

```bash
#!/bin/bash
# redis-restore.sh

BACKUP_FILE="$1"
if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup-file.tar.gz>"
    exit 1
fi

# Stop Redis
sudo systemctl stop redis

# Extract backup
BACKUP_DIR="/tmp/redis-restore-$(date +%s)"
mkdir -p "$BACKUP_DIR"
tar xzf "$BACKUP_FILE" -C "$BACKUP_DIR" --strip-components=1

# Restore RDB file
if [ -f "$BACKUP_DIR/dump.rdb" ]; then
    cp "$BACKUP_DIR/dump.rdb" /var/lib/redis/
    chown redis:redis /var/lib/redis/dump.rdb
fi

# Restore AOF file
if [ -f "$BACKUP_DIR/appendonly.aof" ]; then
    cp "$BACKUP_DIR/appendonly.aof" /var/lib/redis/
    chown redis:redis /var/lib/redis/appendonly.aof
fi

# Restore configuration
if [ -f "$BACKUP_DIR/redis.conf" ]; then
    cp "$BACKUP_DIR/redis.conf" /etc/redis/
fi

# Start Redis
sudo systemctl start redis

# Cleanup
rm -rf "$BACKUP_DIR"

echo "Restore completed"
```

### Point-in-Time Recovery

```bash
#!/bin/bash
# redis-pitr.sh

RECOVERY_TIME="$1"
if [ -z "$RECOVERY_TIME" ]; then
    echo "Usage: $0 <recovery-timestamp>"
    echo "Example: $0 1640995200"
    exit 1
fi

# Find appropriate backup
BACKUP_FILE=$(find /backup/redis -name "*.tar.gz" -newer "$RECOVERY_TIME" | head -1)

if [ -z "$BACKUP_FILE" ]; then
    echo "No backup found for recovery time: $RECOVERY_TIME"
    exit 1
fi

# Restore backup
./redis-restore.sh "$BACKUP_FILE"

# Apply AOF logs from recovery point
if [ -f /var/lib/redis/appendonly.aof ]; then
    # Truncate AOF to recovery point
    redis-check-aof --fix /var/lib/redis/appendonly.aof
fi

echo "Point-in-time recovery completed to $RECOVERY_TIME"
```

## 6. Troubleshooting

### Common Issues

1. **Redis won't start**:
```bash
# Check logs
sudo journalctl -u redis -f
sudo tail -f /var/log/redis/redis-server.log

# Check disk space
df -h /var/lib/redis

# Check permissions
ls -la /var/lib/redis

# Validate configuration
redis-server --test-config
```

2. **Connection issues**:
```bash
# Check if Redis is listening
sudo ss -tlnp | grep :6379

# Test local connection
redis-cli ping
redis-cli -h 127.0.0.1 -p 6379 ping

# Check authentication
redis-cli -a SecureRedisPassword123! ping

# Check bind address
redis-cli config get bind
```

3. **Performance issues**:
```bash
# Check slow queries
redis-cli slowlog get 10

# Check memory usage
redis-cli info memory

# Check client connections
redis-cli info clients
redis-cli client list

# Monitor latency
redis-cli --latency-history -i 1
```

### Debug Mode

```bash
# Start Redis with verbose logging
redis-server /etc/redis/redis.conf --loglevel debug

# Enable command logging
redis-cli config set loglevel debug

# Monitor all commands
redis-cli monitor

# Check server info
redis-cli info all
```

## Maintenance

### Update Procedures

```bash
# RHEL/CentOS/Rocky/AlmaLinux
sudo dnf check-update redis
sudo dnf update redis

# Debian/Ubuntu
sudo apt update
sudo apt upgrade redis-server

# Arch Linux
sudo pacman -Syu redis

# Alpine Linux
apk update
apk upgrade redis

# openSUSE
sudo zypper update redis

# FreeBSD
pkg update
pkg upgrade redis

# Always backup before updates
./redis-backup.sh

# Restart after updates
sudo systemctl restart redis
```

### Maintenance Tasks

```bash
# Weekly maintenance script
#!/bin/bash
# redis-maintenance.sh

# Check memory usage
MEMORY_INFO=$(redis-cli info memory)
echo "Memory usage: $MEMORY_INFO"

# Clean up expired keys
redis-cli eval "return #redis.call('keys', ARGV[1])" 0 "*"

# Optimize RDB file
redis-cli debug restart

# Check slow queries
SLOW_QUERIES=$(redis-cli slowlog len)
if [ "$SLOW_QUERIES" -gt 0 ]; then
    echo "Found $SLOW_QUERIES slow queries"
    redis-cli slowlog get 5
fi

# Analyze key distribution
redis-cli --bigkeys

# Check replication lag (if slave)
if redis-cli info replication | grep -q "role:slave"; then
    redis-cli info replication | grep "master_last_io_seconds_ago"
fi

echo "Redis maintenance completed"
```

### Health Monitoring

```bash
# Create monitoring cron job
echo "*/5 * * * * /usr/local/bin/redis-health-check.sh" | sudo crontab -

# Log rotation
sudo tee /etc/logrotate.d/redis <<EOF
/var/log/redis/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 redis redis
    postrotate
        systemctl reload redis
    endscript
}
EOF
```

## Integration Examples

### Python Integration

```python
# Using redis-py
import redis
import json

# Connect to Redis
r = redis.Redis(
    host='localhost',
    port=6379,
    password='SecureRedisPassword123!',
    decode_responses=True
)

# Basic operations
r.set('user:1000', json.dumps({'name': 'John', 'age': 30}))
user_data = json.loads(r.get('user:1000'))

# Pipeline operations
pipe = r.pipeline()
pipe.set('key1', 'value1')
pipe.set('key2', 'value2')
pipe.incr('counter')
results = pipe.execute()

# Pub/Sub
pubsub = r.pubsub()
pubsub.subscribe('notifications')
for message in pubsub.listen():
    print(f"Received: {message['data']}")
```

### Node.js Integration

```javascript
// Using ioredis
const Redis = require('ioredis');

const redis = new Redis({
    port: 6379,
    host: 'localhost',
    password: 'SecureRedisPassword123!',
    retryDelayOnFailover: 100,
    maxRetriesPerRequest: 3,
});

// Basic operations
await redis.set('session:abc123', JSON.stringify({userId: 1000}), 'EX', 3600);
const sessionData = JSON.parse(await redis.get('session:abc123'));

// Pipeline operations
const pipeline = redis.pipeline();
pipeline.hset('user:1000', 'name', 'John');
pipeline.hset('user:1000', 'email', 'john@example.com');
pipeline.expire('user:1000', 3600);
await pipeline.exec();

// Cluster support
const cluster = new Redis.Cluster([
    { host: '127.0.0.1', port: 7000 },
    { host: '127.0.0.1', port: 7001 },
    { host: '127.0.0.1', port: 7002 }
]);
```

### PHP Integration

```php
<?php
// Using Predis
require_once 'vendor/autoload.php';

$redis = new Predis\Client([
    'scheme' => 'tcp',
    'host'   => '127.0.0.1',
    'port'   => 6379,
    'password' => 'SecureRedisPassword123!',
]);

// Basic operations
$redis->set('cache:product:1', json_encode(['name' => 'Laptop', 'price' => 999.99]));
$redis->expire('cache:product:1', 3600);
$productData = json_decode($redis->get('cache:product:1'), true);

// Transaction
$redis->multi();
$redis->incr('page_views');
$redis->lpush('recent_pages', '/products/1');
$redis->ltrim('recent_pages', 0, 99);
$results = $redis->exec();
?>
```

### Java Integration

```java
// Using Jedis
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;

// Connection pool
JedisPoolConfig poolConfig = new JedisPoolConfig();
poolConfig.setMaxTotal(50);
poolConfig.setMaxIdle(20);

JedisPool pool = new JedisPool(poolConfig, "localhost", 6379, 2000, "SecureRedisPassword123!");

// Use connection
try (Jedis jedis = pool.getResource()) {
    // Basic operations
    jedis.set("user:1000", "{\"name\":\"John\",\"age\":30}");
    jedis.expire("user:1000", 3600);
    String userData = jedis.get("user:1000");
    
    // Pipeline operations
    Pipeline pipeline = jedis.pipelined();
    pipeline.hset("product:1", "name", "Laptop");
    pipeline.hset("product:1", "price", "999.99");
    pipeline.expire("product:1", 3600);
    pipeline.sync();
}
```

## Additional Resources

- [Official Redis Documentation](https://redis.io/documentation)
- [Redis Commands Reference](https://redis.io/commands)
- [Redis Modules](https://redis.io/modules)
- [Redis Security Guidelines](https://redis.io/topics/security)
- [Redis Persistence](https://redis.io/topics/persistence)
- [Redis Replication](https://redis.io/topics/replication)
- [Redis Cluster Tutorial](https://redis.io/tutorial/redis-cluster-tutorial)
- [Redis Sentinel Documentation](https://redis.io/topics/sentinel)

---

**Note:** This guide is part of the [HowToMgr](https://howtomgr.github.io) collection. Always refer to official documentation for the most up-to-date information.