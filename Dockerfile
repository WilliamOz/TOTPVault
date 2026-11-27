FROM php:8.4-apache-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends libldap2-dev \
    && docker-php-ext-configure ldap --with-libdir="lib/$(dpkg-architecture -qDEB_HOST_MULTIARCH)" \
    && docker-php-ext-install pdo_mysql ldap \
    && rm -rf /var/lib/apt/lists/* \
    && a2enmod rewrite headers

COPY docker/000-default.conf /etc/apache2/sites-available/000-default.conf
COPY index.php .htaccess favicon.png /var/www/html/
COPY config/ /var/www/html/config/
COPY assets/ /var/www/html/assets/
COPY src/ /var/www/html/src/
COPY templates/ /var/www/html/templates/
COPY tools/ /var/www/html/tools/
COPY sessions/.htaccess /var/www/html/sessions/.htaccess

RUN chown www-data:www-data /var/www/html/sessions \
    && chmod 750 /var/www/html/sessions \
    && printf '%s\n' 'display_errors = Off' 'log_errors = On' 'error_log = /dev/stderr' \
        'session.save_path = /var/www/html/sessions' 'session.gc_maxlifetime = 28800' \
        'expose_php = Off' 'post_max_size = 128K' 'zend.exception_ignore_args = On' \
        > /usr/local/etc/php/conf.d/totpvault.ini

EXPOSE 80
