# DMZ reverse proxy. nginx 1.25.3 -> CPE f5:nginx_open_source (CVE-2024-24989, CVE-2024-7347, ...)
FROM nginx:1.25.3
ARG WAZUH_VERSION=4.9.2
COPY common/ /lab/
RUN sed -i 's/\r$//' /lab/*.sh && chmod +x /lab/*.sh && /lab/install-wazuh-agent.sh "$WAZUH_VERSION"
RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/* \
 && openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -subj "/CN=nginx.lab.local" \
        -keyout /etc/nginx/lab.key -out /etc/nginx/lab.crt
COPY hosts/nginx/default.conf /etc/nginx/conf.d/default.conf
ENTRYPOINT ["/lab/entrypoint.sh", "/docker-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
