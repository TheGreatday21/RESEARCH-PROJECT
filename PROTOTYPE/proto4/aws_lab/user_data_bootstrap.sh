#!/usr/bin/env bash
# Test tooling, not part of LAPA.
# Optional EC2 user-data bootstrap script for a throwaway test instance.
# Installs nginx and python3, configures the 'lapa' nginx log format, adds the
# non-root SSH user to group 'adm', and configures logrotate with 'create 0640 ... adm'.
# Supports Ubuntu/Debian (apt-get) and Amazon Linux 2023 / RHEL (dnf).

set -euo pipefail

if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y --no-install-recommends nginx python3 logrotate
    NGINX_USER="www-data"
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y nginx python3 logrotate
    NGINX_USER="nginx"
else
    echo "Unsupported package manager (expected apt-get or dnf)." >&2
    exit 1
fi

groupadd -f adm

for candidate in ubuntu ec2-user admin forensic-acq; do
    if id "$candidate" >/dev/null 2>&1; then
        usermod -aG adm "$candidate"
    fi
done

mkdir -p /var/www/lapa/assets /var/log/nginx

cat <<'EOF' >/var/www/lapa/index.html
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>LAPA Throwaway Test Server</title></head>
<body><h1>LAPA Throwaway Test Target</h1><p>Test tooling only, not part of LAPA.</p></body></html>
EOF

cat <<'EOF' >/var/www/lapa/assets/site.css
body { font-family: sans-serif; margin: 2rem; }
EOF

cat <<EOF >/etc/nginx/nginx.conf
user ${NGINX_USER};
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 256;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    sendfile on;
    keepalive_timeout 10;

    log_format lapa '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                    '\$status \$body_bytes_sent "\$http_referer" "\$http_user_agent" '
                    'msec=\$msec request_time=\$request_time request_id=\$request_id '
                    'connection=\$connection trace_id=\$http_x_lapa_trace';
    access_log /var/log/nginx/access.log lapa;
    error_log /var/log/nginx/error.log notice;

    server {
        listen 80;
        server_name _;
        root /var/www/lapa;

        location / {
            try_files \$uri \$uri/ =404;
        }

        location = /login {
            return 204;
        }

        location /upstream/ {
            proxy_pass http://127.0.0.1:8081/;
            proxy_connect_timeout 1s;
            proxy_read_timeout 1s;
        }
    }
}
EOF

touch /var/log/nginx/access.log /var/log/nginx/error.log
chown -R "${NGINX_USER}:adm" /var/log/nginx /var/www/lapa
chmod 0750 /var/log/nginx
chmod 0640 /var/log/nginx/access.log /var/log/nginx/error.log

cat <<EOF >/etc/logrotate.d/nginx
/var/log/nginx/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 ${NGINX_USER} adm
    sharedscripts
    postrotate
        [ -s /run/nginx.pid ] && kill -USR1 \$(cat /run/nginx.pid) || true
    endscript
}
EOF

nginx -t
systemctl enable --now nginx
