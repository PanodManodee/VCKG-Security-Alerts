# APP api server. Node.js 21.6.1 -> CPE nodejs:node.js (CVE-2024-21891, CVE-2024-22019, ...)
# (Node 20.11 has no matching 2024+ CVE range in the CTI graph, so 21.6.1 is used.)
FROM node:21.6.1-bookworm-slim
ARG WAZUH_VERSION=4.9.2
COPY common/ /lab/
RUN sed -i 's/\r$//' /lab/*.sh && chmod +x /lab/*.sh && /lab/install-wazuh-agent.sh "$WAZUH_VERSION"
COPY hosts/api/server.js /app/server.js
EXPOSE 3000
ENTRYPOINT ["/lab/entrypoint.sh"]
CMD ["node", "/app/server.js"]
