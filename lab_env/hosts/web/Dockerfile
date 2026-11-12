# DMZ web server. Apache httpd 2.4.58 -> CPE apache:http_server (CVE-2024-38476, CVE-2024-27316, ...)
FROM httpd:2.4.58
ARG WAZUH_VERSION=4.9.2
COPY common/ /lab/
RUN sed -i 's/\r$//' /lab/*.sh && chmod +x /lab/*.sh && /lab/install-wazuh-agent.sh "$WAZUH_VERSION"
COPY hosts/web/htdocs/ /usr/local/apache2/htdocs/
# Access/error logs to files for the Wazuh agent (combined format = Wazuh's apache decoder), access log also to stdout.
RUN sed -i \
      -e 's|^\s*CustomLog .*|CustomLog "logs/access_log" combined\nCustomLog /proc/self/fd/1 common|' \
      -e 's|^ErrorLog .*|ErrorLog "logs/error_log"|' \
      /usr/local/apache2/conf/httpd.conf \
 && grep -nE '^(ErrorLog|\s*CustomLog)' /usr/local/apache2/conf/httpd.conf
# Web -> API dependency: /api/* is served by the API (mod_proxy), so /api/users needs the API and,
# behind it, PostgreSQL.
COPY hosts/web/proxy-api.conf /usr/local/apache2/conf/extra/proxy-api.conf
RUN sed -i -e 's|^#LoadModule proxy_module |LoadModule proxy_module |' \
           -e 's|^#LoadModule proxy_http_module |LoadModule proxy_http_module |' \
           /usr/local/apache2/conf/httpd.conf \
 && echo 'Include conf/extra/proxy-api.conf' >> /usr/local/apache2/conf/httpd.conf \
 && grep -nE '^LoadModule proxy(_http)?_module|proxy-api' /usr/local/apache2/conf/httpd.conf
ENTRYPOINT ["/lab/entrypoint.sh"]
CMD ["httpd-foreground"]
