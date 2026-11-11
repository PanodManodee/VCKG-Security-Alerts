# Network IDS (paper §III.A.2): Suricata inspects all traffic between zones and writes EVE JSON alerts,
# which the Wazuh agent (agent name `ids`) forwards to the manager. Runs in the firewall's network namespace
# (docker-compose.yml: network_mode service:firewall).
FROM debian:bookworm-20240311
ARG WAZUH_VERSION=4.9.2
COPY common/ /lab/
RUN sed -i 's/\r$//' /lab/*.sh && chmod +x /lab/*.sh && /lab/install-wazuh-agent.sh "$WAZUH_VERSION"
# Suricata is not in Debian 12's main archive; bookworm-backports carries Suricata 7.
RUN echo "deb http://deb.debian.org/debian bookworm-backports main" > /etc/apt/sources.list.d/backports.list \
 && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        -t bookworm-backports suricata suricata-update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3-yaml ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY ids/configure.py ids/start.sh ids/local.rules /lab/ids/
RUN sed -i 's/\r$//' /lab/ids/* && chmod +x /lab/ids/start.sh \
 && python3 /lab/ids/configure.py /etc/suricata/suricata.yaml \
 && mkdir -p /var/lib/suricata/rules \
 && (suricata-update --no-test --local /lab/ids/local.rules \
     || echo "suricata-update failed (no internet at build?): start.sh falls back to the lab rules only")
ENTRYPOINT ["/lab/entrypoint.sh"]
CMD ["/lab/ids/start.sh"]
