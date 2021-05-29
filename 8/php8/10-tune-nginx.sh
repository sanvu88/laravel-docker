#!/bin/sh
set -e

## Tune Nginx

#IPADDRESS=$(curl -s http://cyberpanel.sh/?ip)
CPU_CORES=$(grep -c "processor" /proc/cpuinfo)
MAX_CLIENT=$((CPU_CORES * 1024))
RAM_TOTAL=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
SWAP_TOTAL=$(awk '/SwapFree/ {print $2}' /proc/meminfo)
if [ -n "$SWAP_TOTAL" ]; then
   PHP_MEM=$((RAM_TOTAL+SWAP_TOTAL))
else
    PHP_MEM=$SWAP_TOTAL
fi
NGINX_PROCESSES=$(grep -c ^processor /proc/cpuinfo)
MAX_CLIENT=$((NGINX_PROCESSES * 1024))
NGINX_SERVICE_FILE="/lib/systemd/system/nginx.service"
NGINX_CONFIG_FILE="/etc/nginx/nginx.conf"
SELF_SIGNED_DIR="/etc/nginx/certs"
DOC_ROOT="/usr/share/nginx/html/public"

if [ -f $NGINX_SERVICE_FILE ]; then
    rm -rf $NGINX_SERVICE_FILE
fi

cat > "$NGINX_SERVICE_FILE" << END
[Unit]
Description=nginx - high performance web server
Documentation=https://nginx.org/en/docs/
After=network-online.target remote-fs.target nss-lookup.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/var/run/nginx.pid
ExecStart=/usr/sbin/nginx -c $NGINX_CONFIG_FILE
ExecReload=/bin/sh -c "/bin/kill -s HUP \$(/bin/cat /var/run/nginx.pid)"
ExecStop=/bin/sh -c "/bin/kill -s TERM \$(/bin/cat /var/run/nginx.pid)"
PrivateTmp=true
LimitMEMLOCK=infinity
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
END

cat > "$NGINX_CONFIG_FILE" << END
user nginx;
worker_processes auto;
worker_rlimit_nofile 260000;

error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;

load_module /etc/nginx/modules/ngx_http_brotli_filter_module.so;
load_module /etc/nginx/modules/ngx_http_brotli_static_module.so;
load_module /etc/nginx/modules/ngx_http_headers_more_filter_module.so;

events {
    worker_connections $MAX_CLIENT;
    accept_mutex off;
    accept_mutex_delay 200ms;
    use epoll;
    #multi_accept on;
}

http {
    index  index.html index.htm index.php;
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    charset utf-8;

    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                  '\$status \$body_bytes_sent "\$http_referer" '
                  '"\$http_user_agent" "\$http_x_forwarded_for"';

    access_log  off;
    server_tokens off;

    sendfile on;

    tcp_nopush on;
    tcp_nodelay off;

    types_hash_max_size 2048;
    server_names_hash_bucket_size 128;
    server_names_hash_max_size 10240;
    client_max_body_size 1024m;
    client_body_buffer_size 128k;
    client_body_in_file_only off;
    client_body_timeout 60s;
    client_header_buffer_size 256k;
    client_header_timeout  20s;
    large_client_header_buffers 8 256k;
    keepalive_timeout 15;
    keepalive_disable msie6;
    reset_timedout_connection on;
    send_timeout 60s;

    disable_symlinks if_not_owner from=\$document_root;
    server_name_in_redirect off;

    open_file_cache max=2000 inactive=20s;
    open_file_cache_valid 120s;
    open_file_cache_min_uses 2;
    open_file_cache_errors off;

    # Limit Request
    limit_req_status 403;
    # limit the number of connections per single IP
    limit_conn_zone \$binary_remote_addr zone=conn_limit_per_ip:10m;
    # limit the number of requests for a given session
    limit_req_zone \$binary_remote_addr zone=req_limit_per_ip:10m rate=1r/s;

    # Custom Response Headers
    more_set_headers 'Server: HOSTVN.NET';
    more_set_headers 'X-Content-Type-Options    "nosniff" always';
    more_set_headers 'X-XSS-Protection          "1; mode=block" always';
    more_set_headers 'Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always';

    include /etc/nginx/gzip.conf;
    include /etc/nginx/brotli.conf;
    include /etc/nginx/ssl.conf;
    include /etc/nginx/cloudflare.conf;
    include /etc/nginx/conf.d/*.conf;
}
END

cat > "/etc/nginx/cloudflare.conf" <<END
real_ip_header X-Forwarded-For;
END

for ipv4 in `curl https://www.cloudflare.com/ips-v4` ; do
        cat >>"/etc/nginx/cloudflare.conf" <<EOcf_ipv4
set_real_ip_from $ipv4;
EOcf_ipv4
    done

    for ipv6 in `curl https://www.cloudflare.com/ips-v6` ; do
        cat >>"/etc/nginx/cloudflare.conf" <<EOcf_ipv6
set_real_ip_from $ipv6;
EOcf_ipv6
    done

cat > "/etc/nginx/conf.d/default.conf" << END
upstream php-web {
    server unix:/var/run/php-fpm.sock;
}

server {
    listen 80;
    listen  [::]:80;
    error_log /usr/share/nginx/logs/error.log;
    server_name localhost;
    root $DOC_ROOT;
    index index.php index.html index.htm;
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }

    location ~ \.php {
        try_files \$uri =404;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_index index.php;
        include /etc/nginx/fastcgi_params;
        include /etc/nginx/nginx_limits.conf;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        if (-f \$request_filename) {
            fastcgi_pass php-web;
        }
    }

    location = /wp-login.php {
        limit_req zone=req_limit_per_ip burst=1 nodelay;
        include /etc/nginx/fastcgi_params;
        include /etc/nginx/nginx_limits.conf;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        if (-f \$request_filename)
        {
            fastcgi_pass php-web;
        }
    }

    include /etc/nginx/extra/staticfiles.conf;
    include /etc/nginx/extra/security.conf;
    include /etc/nginx/extra/block.conf;
}

#server {
#    listen       443 ssl http2;
#    listen  [::]:443 ssl http2;
#    server_name localhost;
#
#    ssl_certificate         $SELF_SIGNED_DIR/server.crt;
#    ssl_certificate_key     $SELF_SIGNED_DIR/server.key;
#
#    error_log /usr/share/nginx/logs/error.log;
#
#    root $DOC_ROOT;
#    index index.php index.html index.htm;
#
#    location / {
#        try_files \$uri \$uri/ /index.php?\$args;
#    }
#
#    location ~ \.php {
#        try_files \$uri =404;
#        fastcgi_split_path_info ^(.+\.php)(/.+)$;
#        fastcgi_index index.php;
#        include /etc/nginx/fastcgi_params;
#        include /etc/nginx/nginx_limits.conf;
#        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
#        if (-f \$request_filename) {
#            fastcgi_pass php-web;
#        }
#    }
#
#    location = /wp-login.php {
#        limit_req zone=req_limit_per_ip burst=1 nodelay;
#        include /etc/nginx/fastcgi_params;
#        include /etc/nginx/nginx_limits.conf;
#        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
#        if (-f \$request_filename)
#        {
#            fastcgi_pass php-web;
#        }
#    }
#
#    include /etc/nginx/extra/staticfiles.conf;
#    include /etc/nginx/extra/security.conf;
#    include /etc/nginx/extra/block.conf;
#}
END

## Tune PHP-FPM
cat >"/etc/php/8.0/fpm/conf.d/10-opcache.ini" <<EOphp_opcache
zend_extension=opcache.so
opcache.enable=1
opcache.memory_consumption=128
opcache.interned_strings_buffer=8
opcache.max_wasted_percentage=5
opcache.max_accelerated_files=65407
opcache.revalidate_freq=180
opcache.fast_shutdown=0
opcache.enable_cli=0
opcache.save_comments=1
opcache.enable_file_override=1
opcache.validate_timestamps=1
opcache.blacklist_filename=/etc/php/8.0/fpm/conf.d/opcache-default.blacklist
EOphp_opcache

cat >"/etc/php/8.0/cli/conf.d/10-opcache.ini" <<EOphp_opcache
zend_extension=opcache.so
opcache.enable=1
opcache.memory_consumption=128
opcache.interned_strings_buffer=8
opcache.max_wasted_percentage=5
opcache.max_accelerated_files=65407
opcache.revalidate_freq=180
opcache.fast_shutdown=0
opcache.enable_cli=0
opcache.save_comments=1
opcache.enable_file_override=1
opcache.validate_timestamps=1
opcache.blacklist_filename=/etc/php/8.0/fpm/conf.d/opcache-default.blacklist
EOphp_opcache

cat >"/etc/php/8.0/fpm/conf.d/opcache-default.blacklist" <<EOopcache_blacklist
/usr/share/nginx/html/wp-content/plugins/backwpup/*
/usr/share/nginx/html/wp-content/plugins/duplicator/*
/usr/share/nginx/html/wp-content/plugins/updraftplus/*
/usr/share/nginx/html/wp-content/cache/*
/usr/share/nginx/html/storage/*
EOopcache_blacklist

if [ "${CPU_CORES}" -ge 4 ] && [ "${CPU_CORES}" -lt 6 ] && [ "${RAM_TOTAL}" -gt 1049576 ] && [ "${RAM_TOTAL}" -le 2097152 ]; then
    PM_MAX_CHILDREN=$((CPU_CORES * 6))
    PM_MAX_REQUEST=2000
elif [ "${CPU_CORES}" -ge 4 ] && [ "${CPU_CORES}" -lt 6 ] && [ "${RAM_TOTAL}" -gt 2097152 ] && [ "${RAM_TOTAL}" -le 3145728 ]; then
    PM_MAX_CHILDREN=$((CPU_CORES * 6))
    PM_MAX_REQUEST=2000
elif [ "${CPU_CORES}" -ge 4 ] && [ "${CPU_CORES}" -lt 6 ] && [ "${RAM_TOTAL}" -gt 3145728 ] && [ "${RAM_TOTAL}" -le 4194304 ]; then
    PM_MAX_CHILDREN=$((CPU_CORES * 6))
    PM_MAX_REQUEST=2000
elif [ "${CPU_CORES}" -ge 4 ] && [ "${CPU_CORES}" -lt 6 ] && [ "${RAM_TOTAL}" -gt 4194304 ]; then
    PM_MAX_CHILDREN=$((CPU_CORES * 6))
    PM_MAX_REQUEST=2000
elif [ "${CPU_CORES}" -ge 6 ] && [ "${CPU_CORES}" -lt 8 ] && [ "${RAM_TOTAL}" -gt 3145728 ] && [ "${RAM_TOTAL}" -le 4194304 ]; then
    PM_MAX_CHILDREN=$((CPU_CORES * 6))
    PM_MAX_REQUEST=2000
elif [ "${CPU_CORES}" -ge 6 ] && [ "${CPU_CORES}" -lt 8 ] && [ "${RAM_TOTAL}" -gt 4194304 ]; then
    PM_MAX_CHILDREN=$((CPU_CORES * 6))
    PM_MAX_REQUEST=2000
elif [ "${CPU_CORES}" -ge 8 ] && [ "${CPU_CORES}" -lt 16 ] && [ "${RAM_TOTAL}" -gt 3145728 ] && [ "${RAM_TOTAL}" -le 4194304 ]; then
    PM_MAX_CHILDREN=$((CPU_CORES * 6))
    PM_MAX_REQUEST=2000
elif [ "${CPU_CORES}" -ge 8 ] && [ "${CPU_CORES}" -lt 12 ] && [ "${RAM_TOTAL}" -gt 4194304 ]; then
    PM_MAX_CHILDREN=$((CPU_CORES * 6))
    PM_MAX_REQUEST=2000
elif [ "${CPU_CORES}" -ge 13 ] && [ "${CPU_CORES}" -lt 16 ] && [ "${RAM_TOTAL}" -gt 4194304 ]; then
    PM_MAX_CHILDREN=$((CPU_CORES * 6))
    PM_MAX_REQUEST=2000
elif [ "${CPU_CORES}" -ge 17 ] && [ "${RAM_TOTAL}" -gt 4194304 ]; then
    PM_MAX_CHILDREN=$((CPU_CORES * 5))
    PM_MAX_REQUEST=2000
else
    PM_MAX_CHILDREN=$((CPU_CORES * 5))
    PM_MAX_REQUEST=500
fi

cat >"/etc/php/8.0/fpm/pool.d/www.conf"<<END
[www]
listen = /var/run/php-fpm.sock;
listen.allowed_clients = 127.0.0.1
listen.owner = nginx
listen.group = nginx
listen.mode = 0660
user = nginx
group = nginx
pm = ondemand
pm.max_children = ${PM_MAX_CHILDREN}
pm.max_requests = ${PM_MAX_REQUEST}
pm.process_idle_timeout = 10s
;slowlog = /var/log/php-fpm/www-slow.log
chdir = /
php_admin_value[error_log] = /var/log/php-fpm/www-error.log
php_admin_flag[log_errors] = on
php_value[session.save_handler] = files
php_value[session.save_path]    = /var/lib/php/session
php_value[soap.wsdl_cache_dir]  = /var/lib/php/wsdlcache
php_admin_value[open_basedir] = /usr/share/nginx/html/:/tmp/:/var/tmp/:/dev/urandom:/usr/share/php/:/dev/shm:/var/lib/php/sessions/
security.limit_extensions = .php
END

if [ -f "/usr/lib/systemd/system/php8.0-fpm.service" ]; then
    cat >"/usr/lib/systemd/system/php8.0-fpm.service" << END
[Unit]
Description=The PHP 8.0 FastCGI Process Manager
Documentation=man:php-fpm8.0(8)
After=network.target

[Service]
Type=notify
ExecStart=/usr/sbin/php-fpm8.0 --nodaemonize --fpm-config /etc/php/8.0/fpm/php-fpm.conf
ExecStartPost=-/usr/lib/php/php-fpm-socket-helper install /run/php/php-fpm.sock /etc/php/8.0/fpm/pool.d/www.conf 80
ExecStopPost=-/usr/lib/php/php-fpm-socket-helper remove /run/php/php-fpm.sock /etc/php/8.0/fpm/pool.d/www.conf 80
ExecReload=/bin/kill -USR2 \$MAINPID
LimitNOFILE=65535
LimitMEMLOCK=infinity
PrivateTmp=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
END
fi

if [ -f "/lib/systemd/system/php8.0-fpm.service" ]; then
    cat >"/lib/systemd/system/php8.0-fpm.service" << END
[Unit]
Description=The PHP 8.0 FastCGI Process Manager
Documentation=man:php-fpm8.0(8)
After=network.target

[Service]
Type=notify
ExecStart=/usr/sbin/php-fpm8.0 --nodaemonize --fpm-config /etc/php/8.0/fpm/php-fpm.conf
ExecStartPost=-/usr/lib/php/php-fpm-socket-helper install /run/php/php-fpm.sock /etc/php/8.0/fpm/pool.d/www.conf 80
ExecStopPost=-/usr/lib/php/php-fpm-socket-helper remove /run/php/php-fpm.sock /etc/php/8.0/fpm/pool.d/www.conf 80
ExecReload=/bin/kill -USR2 \$MAINPID
LimitNOFILE=65535
LimitMEMLOCK=infinity
PrivateTmp=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
END
fi

## Tune Redis

if [ "${PHP_MEM}" -le '262144' ]; then
    MAX_MEMORY='48'
elif [ "${PHP_MEM}" -gt '262144' ] && [ "${PHP_MEM}" -le '393216' ]; then
    MAX_MEMORY='96'
elif [ "${PHP_MEM}" -gt '393216' ] && [ "${PHP_MEM}" -le '400000' ]; then
    MAX_MEMORY='128'
elif [ "${PHP_MEM}" -gt '400000' ] && [ "${PHP_MEM}" -le '1049576' ]; then
    MAX_MEMORY='160'
elif [ "${PHP_MEM}" -gt '1049576' ] && [ "${PHP_MEM}" -le '2097152' ]; then
    MAX_MEMORY='320'
elif [ "${PHP_MEM}" -gt '2097152' ] && [ "${PHP_MEM}" -le '3145728' ]; then
    MAX_MEMORY='384'
elif [ "${PHP_MEM}" -gt '3145728' ] && [ "${PHP_MEM}" -le '4194304' ]; then
    MAX_MEMORY='512'
elif [ "${PHP_MEM}" -gt '4194304' ] && [ "${PHP_MEM}" -le '8180000' ]; then
    MAX_MEMORY='640'
elif [ "${PHP_MEM}" -gt '8180000' ] && [ "${PHP_MEM}" -le '16360000' ]; then
    MAX_MEMORY='800'
elif [ "${PHP_MEM}" -gt '16360000' ] && [ "${PHP_MEM}" -le '32400000' ]; then
    MAX_MEMORY='1024'
elif [ "${PHP_MEM}" -gt '32400000' ] && [ "${PHP_MEM}" -le '64800000' ]; then
    MAX_MEMORY='1280'
elif [ "${PHP_MEM}" -gt '64800000' ]; then
    MAX_MEMORY='2048'
else
    MAX_MEMORY='128'
fi

if [ ! -d /etc/redis ]; then
    mkdir -p "/etc/redis"
fi

cat >"/etc/redis/redis.conf" << END
bind 127.0.0.1 ::1
protected-mode yes
port 6379
tcp-backlog 511
timeout 0
tcp-keepalive 300
daemonize yes
supervised no
pidfile /var/run/redis/redis-server.pid
loglevel notice
logfile /var/log/redis/redis-server.log
databases 16
always-show-logo yes
save 900 1
save 300 10
save 60 10000
stop-writes-on-bgsave-error yes
rdbcompression yes
rdbchecksum yes
dbfilename dump.rdb
dir /var/lib/redis
slave-serve-stale-data yes
slave-read-only yes
repl-diskless-sync no
repl-diskless-sync-delay 5
repl-disable-tcp-nodelay no
slave-priority 100
maxmemory ${MAX_MEMORY}mb
maxmemory-policy allkeys-lru
lazyfree-lazy-eviction no
lazyfree-lazy-expire no
lazyfree-lazy-server-del no
slave-lazy-flush no
appendonly no
appendfilename "appendonly.aof"
appendfsync everysec
no-appendfsync-on-rewrite no
auto-aof-rewrite-percentage 100
auto-aof-rewrite-min-size 64mb
aof-load-truncated yes
aof-use-rdb-preamble no
lua-time-limit 5000
slowlog-log-slower-than 10000
slowlog-max-len 128
latency-monitor-threshold 0
notify-keyspace-events ""
hash-max-ziplist-entries 512
hash-max-ziplist-value 64
list-max-ziplist-size -2
list-compress-depth 0
set-max-intset-entries 512
zset-max-ziplist-entries 128
zset-max-ziplist-value 64
hll-sparse-max-bytes 3000
activerehashing yes
client-output-buffer-limit normal 0 0 0
client-output-buffer-limit slave 256mb 64mb 60
client-output-buffer-limit pubsub 32mb 8mb 60
hz 10
aof-rewrite-incremental-fsync yes
END

cat >"/etc/php/8.0/fpm/conf.d/30-igbinary.ini" << EOF
extension=igbinary.so
EOF
cat >"/etc/php/8.0/cli/conf.d/30-igbinary.ini" << EOF
extension=igbinary.so
EOF

cat >"/etc/php/8.0/fpm/conf.d/50-redis.ini" << EOF
extension=redis.so
EOF

cat >"/etc/php/8.0/cli/conf.d/50-redis.ini" << EOF
extension=redis.so
EOF

service php8.0-fpm start
service redis-server start
service supervisor start

exit 0
