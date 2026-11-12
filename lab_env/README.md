# Lab environment (Docker)

A Docker version of `lab_network.pdf`: an attacker, a firewall, four zones with eight hosts, and a
Wazuh server. Each host is one container that behaves like a small VM: it runs real software at a
pinned, vulnerable version, serves dummy data, and has a Wazuh agent.

This compose project is separate from the Neo4j one at the repository root (`docker-compose.yml`).
Its only link to the knowledge graph is `lab/*.csv`, which describe these same hosts.

**Lab only.** The software is deliberately vulnerable and the passwords are weak. Do not publish
ports other than the ones below, and do not connect the lab networks to a real network.

## Topology

| Zone (network) | Subnet | Host | IP | Software (pinned) | CPE in the CTI graph |
|---|---|---|---|---|---|
| internet | 172.30.0.0/24 | kali | .10 | Kali rolling + nmap | |
| DMZ | 10.10.10.0/24 | nginx | .11 | nginx 1.25.3 (80, 443 → Web) | f5:nginx_open_source |
| | | web | .12 | Apache httpd 2.4.58 (80) | apache:http_server |
| APP | 10.10.20.0/24 | api | .21 | Node.js 21.6.1 (3000) | nodejs:node.js |
| | | jenkins | .22 | Jenkins 2.441 (8080) | jenkins:jenkins |
| DATA | 10.10.30.0/24 | postgresql | .31 | PostgreSQL 15.5 (5432) | postgresql:postgresql |
| | | files-smb | .32 | Samba 4.17 / Debian 12 (445) | samba:samba |
| Office | 10.10.40.0/24 | admin-pc | .41 | Ubuntu 22.04, OpenSSH 8.9p1 (22) | openbsd:openssh |
| | | dep-pc | .42 | Ubuntu 22.04, OpenSSH 8.9p1 (22) | openbsd:openssh |
| sec | 10.10.90.0/24 | wazuh.manager / .indexer / .dashboard | .10 / .11 / .12 | Wazuh 4.9.2 | |

The firewall has address `.254` in every subnet. Each host's default route points at it, so traffic
between zones only passes where `firewall/rules.sh` allows it. The rules match
`lab/zone_edges.csv`:

- Internet → DMZ, DMZ → APP, APP → DATA, Office → DATA (any port; replies are allowed)
- every zone → Wazuh manager on 1514/1515
- everything else is dropped

Dummy data: a shop page on Web, `/users` and `/orders` on the API, `customers` and `orders`
tables in PostgreSQL, `public` (guest) and `finance` shares on Files-SMB, and a user with
documents on each workstation. Credentials are in `.env`.

## Requirements

- Docker Desktop with at least 8 GB of memory (Wazuh indexer 1 GB heap, Jenkins 512 MB, the rest small).
- Before the first start, raise the indexer's memory map limit in the Docker VM. This resets when Docker restarts:
  ```powershell
  wsl -d docker-desktop sysctl -w vm.max_map_count=262144
  ```
- The subnets 10.10.0.0/16 and 172.30.0.0/24 must not clash with your own network.

## Run

```bash
cd lab_env
cp .env.example .env                                              # once
docker compose -f wazuh/generate-indexer-certs.yml run --rm generator   # once: Wazuh TLS certificates
docker compose up -d --build
```

The certificate step runs once. A second run prints `cp: cannot create regular file ... Permission denied`
because the existing certificates are read-only. This is harmless: the old certificates stay in
`wazuh/config/wazuh_indexer_ssl_certs/`. To make new ones, run `docker compose down`, delete that
folder, run the generator again, then `docker compose up -d`.

- Wazuh dashboard: https://localhost:8443 (`admin` / `SecretPassword`). The agents show up 1–2 minutes after the manager starts.
- Wazuh API: https://localhost:55500 (host port 55500, because Windows/Hyper-V can reserve 55000) (`wazuh-wui` / `MyS3cr37P450r.*-`)
- Wazuh indexer: https://localhost:9200 (`admin` / `SecretPassword`)
- Stop: `docker compose down`. Delete all data as well: `docker compose down -v`.

The Wazuh passwords are the defaults from the official `wazuh-docker` single-node setup. Changing
them means following Wazuh's password-change procedure, not just editing this file.

## Check that it works

These commands work in both PowerShell and bash. In Windows PowerShell 5.1, `||` cannot be used
outside the container, so the test runs inside the container with `sh -c "..."`.

```bash
# Attacker view: only the DMZ answers
docker compose exec kali nmap -sV -Pn -p 22,80,443,445,3000,5432,8080 10.10.10.11 10.10.10.12 10.10.20.21 10.10.30.31

# Allowed flows
docker compose exec web curl -s http://10.10.20.21:3000/users                                                # DMZ -> APP
docker compose exec -e PGPASSWORD=Passw0rd! dep-pc psql -h 10.10.30.31 -U postgres -c "select * from customers"   # Office -> DATA
docker compose exec admin-pc smbclient -N -L //10.10.30.32                                                   # Office -> DATA

# Blocked flow: prints "blocked" after about 5 seconds
docker compose exec dep-pc sh -c "curl -s -m 5 http://10.10.20.22:8080 || echo blocked"

# Firewall counters per rule
docker compose exec firewall iptables -vnL FORWARD
```

## Log collection (what Wazuh sees)

Every host runs rsyslog. Its agent reads `/var/log/auth.log` and `/var/log/syslog`, plus the service logs
named in `LAB_LOGFILES` in `docker-compose.yml`. `common/entrypoint.sh` adds them to the agent's `ossec.conf`.

| Host | Log | Wazuh format | Example alerts (rule id) |
|---|---|---|---|
| all | auth.log, syslog | syslog | user added 5902 (T1136), PAM / sudo |
| nginx | `/var/log/nginx/lab_access.log`, `lab_error.log` | apache / syslog | web 4xx 31101, web attack rules 311xx |
| web | Apache `logs/access_log`, `logs/error_log` (combined) | apache | same as nginx |
| api | `/var/log/api/access.log` (combined, written by server.js) | apache | same as nginx |
| postgresql | `/var/log/postgresql/postgresql.log` | postgresql_log | auth failure 50512 |
| files-smb | smbd auth audit → syslog | syslog | lab rules 100110 failed / 100111 success login (T1110, T1078) |
| admin-pc, dep-pc | sshd → auth.log | syslog | 5760 failed / 5715 success (T1110.001, T1021.004) |
| jenkins | auth.log, syslog only | syslog | no Wazuh decoder for Jenkins' own logs |

The manager has two lab-specific files, both mounted from `wazuh/config/wazuh_cluster/`:

- `local_decoder.xml` reads the Samba auth-audit line (user, status, client IP). It also reads the client IP from the PostgreSQL log prefix, which the stock decoder skips.
- `local_rules.xml` has rules 100110/100111 for Samba logins. The stock ruleset has none, so these events used to fall to level 2 and produced no alert.

After editing either file, run `docker compose restart wazuh.manager`. The agents restart on their
own when the manager does, so wait about a minute before generating events.

Check one log line without generating it in the lab:
`echo '<line>' | docker compose exec -T wazuh.manager /var/ossec/bin/wazuh-logtest`.

Known gap: requests that pass through nginx show nginx (10.10.10.11) as the client in Web's log. The real
client is only in nginx's own log (and in the `X-Forwarded-For` header nginx adds).

## Network IDS (Suricata)

The `ids` container runs Suricata inside the firewall's network namespace (`network_mode: service:firewall`),
so it sees all traffic between zones. The firewall hands each forwarded packet to it through
`NFQUEUE 0` in the `mangle` table:

- Suricata only observes. The filter rules still decide what passes.
- `--queue-bypass` keeps traffic flowing while Suricata is down.

Rules: ET Open is fetched by `suricata-update` when the image is built, plus the lab rules in
`ids/local.rules`. Alerts go to `/var/log/suricata/eve.json` (alerts only, with rule metadata). The Wazuh agent
`ids` forwards them, and Wazuh rule 86601 raises them as "Suricata: Alert - …". `alert_kg` maps each alert to the
asset with the alert's destination IP, and takes the CVE from the rule's `metadata: cve …` or from the
signature text. This gives the vulnerability instance (a, c) that the EVS scores.

```bash
docker compose up -d --build firewall ids
docker compose logs ids | head                            # "ids: N rules loaded, mode nfq"

# Lab test signature (sid 9000001): a harmless request to the Jenkins CLI endpoint (the surface of CVE-2024-23897)
docker compose exec web curl -s -o /dev/null http://10.10.20.22:8080/cli
docker compose exec ids tail -1 /var/log/suricata/eve.json
```

If the firewall log says NFQUEUE is not available in the kernel, start the IDS with `IDS_MODE=pcap`. It then
sniffs every interface, so one flow can raise two alerts (on its way in and on its way out).

## From the lab to the asset graph

`lab/assets.csv` and `lab/services.csv` already list these IPs, versions and CPE pairs. If you change a
version in a Dockerfile, change the CSV too, then reload from the repository root:

```bash
python -m asset_kg all --wipe
```

Where to read versions inside the lab:

| Source | Command |
|---|---|
| nmap (network view) | `docker compose exec kali nmap -sV <ip>` |
| Wazuh syscollector (installed packages) | dashboard → Agents → Inventory, or `GET /syscollector/{agent_id}/packages` on the API |
| the host itself | e.g. `docker compose exec files-smb smbd --version` |

Known gaps:

- **Node.js and Jenkins** are installed from tarballs and WAR files, not from `.deb` packages, so Wazuh's package inventory does not list them. Use nmap or the host itself for these.
- **Samba and OpenSSH** come from distribution packages. Distributions backport fixes without changing the upstream version, so the NVD ranges may list CVEs that are already fixed (see `docs/PLAN.md` §3). OpenSSH is pinned to Ubuntu's original 1:8.9p1-3 build, which has no backports.
