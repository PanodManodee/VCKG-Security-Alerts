#!/bin/sh
# Install the Wazuh agent on a Debian/Ubuntu image at build time.
#   install-wazuh-agent.sh <wazuh version, e.g. 4.9.2>
# Also installs iproute2 (entrypoint.sh needs `ip` to route through the firewall).
# Only adds packages; never runs `apt-get upgrade`, so the pinned service version stays as it is.
set -eu
VERSION="$1"
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends ca-certificates curl gnupg iproute2 procps rsyslog
# rsyslog writes /var/log/auth.log and /var/log/syslog for the agent; containers have no kernel log.
sed -i 's/^module(load="imklog"/#&/' /etc/rsyslog.conf
curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list
apt-get update
WAZUH_MANAGER=10.10.90.10 apt-get install -y --no-install-recommends "wazuh-agent=${VERSION}-1"
rm -f /etc/apt/sources.list.d/wazuh.list   # keep later apt-get runs from upgrading the agent
rm -rf /var/lib/apt/lists/*
