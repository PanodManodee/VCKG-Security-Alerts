# DATA database. PostgreSQL 15.5 -> CPE postgresql:postgresql (CVE-2024-0985)
FROM postgres:15.5
ARG WAZUH_VERSION=4.9.2
COPY common/ /lab/
RUN sed -i 's/\r$//' /lab/*.sh && chmod +x /lab/*.sh && /lab/install-wazuh-agent.sh "$WAZUH_VERSION"
COPY hosts/postgresql/init.sql /docker-entrypoint-initdb.d/10-dummy.sql
RUN mkdir -p /var/log/postgresql && chown postgres:postgres /var/log/postgresql
ENTRYPOINT ["/lab/entrypoint.sh", "docker-entrypoint.sh"]
# Log to a file the Wazuh agent reads (log_format postgresql_log): connections, disconnections and
# failed logins, with the "[timestamp] host:db" prefix Wazuh's PostgreSQL decoder expects.
CMD ["postgres", \
     "-c", "logging_collector=on", \
     "-c", "log_directory=/var/log/postgresql", \
     "-c", "log_filename=postgresql.log", \
     "-c", "log_connections=on", \
     "-c", "log_disconnections=on", \
     "-c", "log_line_prefix=[%m] %h:%d "]
