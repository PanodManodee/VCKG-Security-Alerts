#!/bin/sh
# Entrypoint shared by every lab host:
#   1. send traffic for other zones through the firewall (LAB_GATEWAY = firewall IP in this zone),
#   2. start rsyslog (auth.log / syslog) and tell the Wazuh agent which log files to read,
#   3. start the Wazuh agent (it enrolls with the manager under the container hostname),
#   4. run the image's own entrypoint/command ("$@").
#
# LAB_LOGFILES: extra files for the agent, as "<log_format>:<path>" separated by spaces, e.g.
#   LAB_LOGFILES="apache:/var/log/nginx/lab_access.log syslog:/var/log/nginx/lab_error.log"
set -eu

if [ -n "${LAB_GATEWAY:-}" ]; then
    ip route replace default via "$LAB_GATEWAY"
fi

if command -v rsyslogd >/dev/null 2>&1; then
    rm -f /run/rsyslogd.pid
    rsyslogd
    # rsyslog creates auth.log / syslog on the first message; create them now so the agent,
    # which starts next, finds them (a file that appears later is picked up only after a delay).
    logger -p auth.info "lab: $(hostname) started"
    logger -p user.info "lab: $(hostname) started"
    for _ in 1 2 3 4 5; do
        [ -f /var/log/auth.log ] && [ -f /var/log/syslog ] && break
        sleep 1
    done
fi

OSSEC_CONF=/var/ossec/etc/ossec.conf
add_localfile() {   # add_localfile <log_format> <path>   (idempotent)
    grep -q "<location>$2</location>" "$OSSEC_CONF" && return 0
    mkdir -p "$(dirname "$2")"   # the service creates the file itself; the agent waits for it
    cat >> "$OSSEC_CONF" <<EOF
<ossec_config>
  <localfile>
    <log_format>$1</log_format>
    <location>$2</location>
  </localfile>
</ossec_config>
EOF
}

if [ "${WAZUH_ENABLED:-1}" = "1" ] && [ -x /var/ossec/bin/wazuh-control ]; then
    sed -i "s|<address>.*</address>|<address>${WAZUH_MANAGER:-10.10.90.10}</address>|" "$OSSEC_CONF"
    add_localfile syslog /var/log/auth.log
    add_localfile syslog /var/log/syslog
    for entry in ${LAB_LOGFILES:-}; do
        file="${entry#*:}"
        add_localfile "${entry%%:*}" "$file"
        # Create service logs now (same owner as their directory, e.g. postgres), so the agent can
        # read them from the start instead of picking them up after a delay.
        if [ ! -e "$file" ]; then
            touch "$file"
            chown --reference="$(dirname "$file")" "$file"
        fi
    done
    /var/ossec/bin/wazuh-control start >/dev/null 2>&1 \
        || echo "lab: wazuh agent did not start cleanly (manager not ready yet?); it keeps retrying"
fi

exec "$@"
