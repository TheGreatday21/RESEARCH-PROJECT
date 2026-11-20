FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        cron \
        logrotate \
        nginx \
        openssh-server \
        python3 \
        supervisor \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --groups adm --shell /bin/bash forensic-acq \
    && mkdir -p /home/forensic-acq/.ssh /run/sshd /var/www/lapa/assets \
    && touch /var/log/nginx/access.log /var/log/nginx/error.log \
    && chown -R www-data:adm /var/log/nginx /var/www/lapa \
    && chmod 0750 /var/log/nginx \
    && chmod 0640 /var/log/nginx/access.log /var/log/nginx/error.log \
    && chmod 0700 /home/forensic-acq/.ssh \
    && chown -R forensic-acq:forensic-acq /home/forensic-acq/.ssh \
    && ssh-keygen -A

COPY id_ed25519.pub /home/forensic-acq/.ssh/authorized_keys
COPY nginx.conf /etc/nginx/nginx.conf
COPY sshd_lapa.conf /etc/ssh/sshd_config.d/lapa.conf
COPY supervisord.conf /etc/supervisor/conf.d/lapa.conf
COPY index.html /var/www/lapa/index.html
COPY assets.css /var/www/lapa/assets/site.css

RUN chown forensic-acq:forensic-acq /home/forensic-acq/.ssh/authorized_keys \
    && chmod 0600 /home/forensic-acq/.ssh/authorized_keys \
    && chown -R www-data:adm /var/www/lapa \
    && nginx -t \
    && sshd -t

EXPOSE 22 80

CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/conf.d/lapa.conf"]
