FROM nginx:alpine

RUN apk add --no-cache bash jq coreutils ca-certificates

COPY nginx.conf /etc/nginx/nginx.conf.template
COPY entrypoint.sh watcher.sh /usr/local/bin/

RUN chmod 0755 /usr/local/bin/entrypoint.sh /usr/local/bin/watcher.sh \
    && mkdir -p /control /etc/nginx/generated /tmp/subscription-gateway /var/log/nginx \
    && chmod 0750 /control /etc/nginx/generated /var/log/nginx \
    && chmod 0700 /tmp/subscription-gateway

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
