# DATA file server. Samba 4.17.x from Debian 12 -> CPE samba:samba (CVE-2026-2340, ...)
# Note: Debian backports security fixes without changing 4.17.x, so NVD ranges may over-report here
# (the distro-backport issue in docs/PLAN.md section 3).
FROM debian:bookworm-20240311
ARG WAZUH_VERSION=4.9.2
COPY common/ /lab/
RUN sed -i 's/\r$//' /lab/*.sh && chmod +x /lab/*.sh && /lab/install-wazuh-agent.sh "$WAZUH_VERSION"
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends samba \
 && rm -rf /var/lib/apt/lists/*
COPY hosts/files-smb/smb.conf /etc/samba/smb.conf
COPY hosts/files-smb/start.sh /lab/start.sh
COPY hosts/files-smb/share/ /srv/
RUN sed -i 's/\r$//' /lab/start.sh && chmod +x /lab/start.sh && chmod -R a+rwX /srv
ENTRYPOINT ["/lab/entrypoint.sh"]
CMD ["/lab/start.sh"]
