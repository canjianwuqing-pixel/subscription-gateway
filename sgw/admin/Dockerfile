FROM php:8.3-fpm-alpine

RUN apk add --no-cache nginx sqlite-libs libsodium su-exec \
    && apk add --no-cache --virtual .build-deps sqlite-dev \
    && docker-php-ext-install pdo_sqlite \
    && apk del .build-deps \
    && php -r "exit(extension_loaded('sodium') ? 0 : 1);"

WORKDIR /app

COPY src/ /app/src/
COPY nginx.conf /etc/nginx/http.d/default.conf
COPY php-production.ini /usr/local/etc/php/conf.d/zz-production-errors.ini
COPY entrypoint.sh /usr/local/bin/subscription-gateway-admin

RUN chmod 0755 /usr/local/bin/subscription-gateway-admin \
    && mkdir -p /data /run/nginx \
    && chown -R www-data:www-data /data \
    && chmod 0750 /data /run/nginx

ENTRYPOINT ["/usr/local/bin/subscription-gateway-admin"]
