FROM php:8.3-fpm-alpine

RUN apk add --no-cache nginx sqlite-libs libsodium su-exec curl yaml \
    && apk add --no-cache --virtual .build-deps sqlite-dev curl-dev yaml-dev $PHPIZE_DEPS \
    && docker-php-ext-install pdo_sqlite curl \
    && pecl install yaml-2.2.4 \
    && docker-php-ext-enable yaml \
    && apk del .build-deps \
    && php -r "exit(extension_loaded('sodium') && extension_loaded('curl') && extension_loaded('yaml') ? 0 : 1);"

WORKDIR /app

COPY src/ /app/src/
COPY nginx.conf /etc/nginx/http.d/default.conf
COPY php-fpm-transformer.conf /usr/local/etc/php-fpm.d/zz-transformer.conf
COPY php-production.ini /usr/local/etc/php/conf.d/zz-production-errors.ini
COPY entrypoint.sh /usr/local/bin/subscription-gateway-admin

RUN chmod 0755 /usr/local/bin/subscription-gateway-admin \
    && mkdir -p /data /control /run/nginx \
    && chown -R www-data:www-data /data /control \
    && chmod 0750 /data /control /run/nginx

ENTRYPOINT ["/usr/local/bin/subscription-gateway-admin"]
