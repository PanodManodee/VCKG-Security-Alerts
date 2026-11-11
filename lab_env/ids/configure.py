"""Adapt Debian's default suricata.yaml to the lab (run once at image build).

  HOME_NET     the lab subnets; EXTERNAL_NET any, so traffic between internal zones is inspected too
  rules        /var/lib/suricata/rules/suricata.rules (ET Open + lab rules, written by suricata-update)
  outputs      EVE JSON with alerts only (with rule metadata, where ET rules carry their CVE ids);
               every other output off, so the Wazuh agent forwards alerts and nothing else
  nfq          accept mode: Suricata only observes, the firewall's filter rules still decide
"""
import sys

import yaml

path = sys.argv[1]
cfg = yaml.safe_load(open(path, encoding="utf-8"))

groups = cfg["vars"]["address-groups"]
groups["HOME_NET"] = "[10.10.0.0/16]"
groups["EXTERNAL_NET"] = "any"
ports = cfg["vars"]["port-groups"]
ports["HTTP_PORTS"] = "[80,443,3000,8080]"

cfg["default-rule-path"] = "/var/lib/suricata/rules"
cfg["rule-files"] = ["suricata.rules"]

for output in cfg.get("outputs", []):
    for name, conf in output.items():
        if not isinstance(conf, dict):
            continue
        if name == "eve-log":
            conf.update({"enabled": "yes", "filetype": "regular", "filename": "eve.json",
                         "types": [{"alert": {"metadata": "yes", "tagged-packets": "no"}}]})
        else:
            conf["enabled"] = "no"

nfq = cfg.get("nfq") or {}            # present but empty (null) in Debian's default file
nfq["mode"] = "accept"
cfg["nfq"] = nfq

with open(path, "w", encoding="utf-8") as fh:
    fh.write("%YAML 1.1\n---\n")
    yaml.safe_dump(cfg, fh, sort_keys=False)
print(f"configured {path}")
