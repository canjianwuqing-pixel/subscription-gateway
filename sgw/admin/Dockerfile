FROM php:8.3-fpm-alpine

RUN apk add --no-cache nginx sqlite-libs libsodium su-exec curl yaml openssl socat ca-certificates \
    && apk add --no-cache --virtual .build-deps sqlite-dev curl-dev yaml-dev $PHPIZE_DEPS \
    && docker-php-ext-install pdo_sqlite curl \
    && pecl install yaml-2.2.4 \
    && docker-php-ext-enable yaml \
    && apk del .build-deps \
    && php -r "exit(extension_loaded('sodium') && extension_loaded('curl') && extension_loaded('yaml') ? 0 : 1);"

WORKDIR /app

# Official acme.sh 3.1.1; immutable content checksum checked at build, never installed at runtime.
RUN curl --proto '=https' --tlsv1.2 -fsSL https://codeload.github.com/acmesh-official/acme.sh/tar.gz/refs/tags/3.1.1 -o /tmp/acme.tar.gz \
    && echo 'c5d623ac0af400e83cd676aefaf045228f60e9fc597fea5db4c3a5bd7f6bfcf4  /tmp/acme.tar.gz' | sha256sum -c - \
    && mkdir -p /opt/acme && tar -xzf /tmp/acme.tar.gz --strip-components=1 -C /opt/acme \
    && rm /tmp/acme.tar.gz && chmod 0755 /opt/acme/acme.sh
COPY dns_sgw_cf.sh /opt/acme/dnsapi/dns_sgw_cf.sh

COPY src/ /app/src/
COPY nginx.conf /etc/nginx/http.d/default.conf
COPY php-fpm-transformer.conf /usr/local/etc/php-fpm.d/zz-transformer.conf
COPY php-production.ini /usr/local/etc/php/conf.d/zz-production-errors.ini
COPY entrypoint.sh /usr/local/bin/subscription-gateway-admin

RUN chmod 0755 /usr/local/bin/subscription-gateway-admin \
    && find /app/src -type d -exec chmod 0755 {} + \
    && find /app/src -type f -name '*.php' -exec chmod 0644 {} + \
    && mkdir -p /data /control /domain-certs /run/nginx \
    && chown -R www-data:www-data /data /control /domain-certs \
    && chmod 0750 /data /control /run/nginx

# PID1 is the shell supervisor, not the base image's php-fpm (which uses SIGQUIT).
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/subscription-gateway-admin"]
