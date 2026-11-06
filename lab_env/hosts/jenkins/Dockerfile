# APP ci/cd. Jenkins 2.441 -> CPE jenkins:jenkins (CVE-2024-23897 in CISA KEV, CVE-2024-43044, ...)
# Runs as root so the entrypoint can set the route and start the Wazuh agent (lab only).
FROM jenkins/jenkins:2.441-jdk17
USER root
ARG WAZUH_VERSION=4.9.2
COPY common/ /lab/
RUN sed -i 's/\r$//' /lab/*.sh && chmod +x /lab/*.sh && /lab/install-wazuh-agent.sh "$WAZUH_VERSION"
# No setup wizard: Jenkins starts unauthenticated, as a neglected internal CI server would.
ENV JAVA_OPTS="-Djenkins.install.runSetupWizard=false -Xmx512m"
ENTRYPOINT ["/lab/entrypoint.sh", "/usr/bin/tini", "--", "/usr/local/bin/jenkins.sh"]
