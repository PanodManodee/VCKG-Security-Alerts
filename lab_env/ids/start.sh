#!/bin/sh
# Start Suricata. IDS_MODE=nfq (default): read the packets the firewall queues with NFQUEUE (each forwarded
# packet once). IDS_MODE=pcap: sniff every interface of the firewall namespace (fallback if the kernel has no
# NFQUEUE; a flow is then seen on its way in and out, so alerts can appear twice).
set -eu
RULES=/var/lib/suricata/rules/suricata.rules
mkdir -p /var/log/suricata "$(dirname "$RULES")"
if [ ! -s "$RULES" ]; then
    echo "ids: no ET Open rules (suricata-update failed at build); using the lab rules only"
    cp /lab/ids/local.rules "$RULES"
fi
echo "ids: $(grep -c '^alert' "$RULES") rules loaded, mode ${IDS_MODE:-nfq}"
if [ "${IDS_MODE:-nfq}" = "pcap" ]; then
    exec suricata -c /etc/suricata/suricata.yaml -i any
fi
exec suricata -c /etc/suricata/suricata.yaml -q 0
