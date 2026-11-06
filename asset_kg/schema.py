"""Asset graph schema: node labels with their key property, and allowed edge types.

Mirrors cti_kg/schema.py. CPE and Vulnerability belong to the CTI graph (cti_kg); the asset
graph only attaches to them and never creates or edits those nodes.
"""

NODE_KEYS = {
    "Zone": "name",          # DMZ
    "Asset": "hostname",     # PostgreSQL
    "Service": "id",         # PostgreSQL:5432/tcp
    "Software": "id",        # postgresql 15.4
}

# Owned by cti_kg. Key properties as defined in cti_kg/schema.py.
SHARED_NODE_KEYS = {"CPE": "cpe23", "Vulnerability": "cve_id", "Platform": "name"}

# (edge type, source label, target label)
EDGE_TYPES = {
    ("IN_ZONE", "Asset", "Zone"),
    ("ALLOWED_TO_REACH", "Zone", "Zone"),
    ("CONNECTS_TO", "Asset", "Asset"),
    ("RUNS", "Asset", "Service"),
    ("IMPLEMENTED_BY", "Service", "Software"),
    ("IDENTIFIED_AS", "Software", "CPE"),
    # Derived by `link`: only CVEs whose version range contains the installed version.
    ("HAS_VULNERABILITY", "Software", "Vulnerability"),
    # Derived by `link`: OS family -> ATT&CK/CWE platform (lab/os_platforms.csv).
    ("RUNS_ON", "Asset", "Platform"),
    # Derived by `link`: who can open a connection to which service (same zone, or zone ALLOWED_TO_REACH zone).
    ("CAN_REACH", "Asset", "Service"),
    ("CAN_REACH", "Zone", "Service"),    # only zones without assets, i.e. the Internet
}

LEVELS = {"L", "M", "H"}   # CVSS v3.1 security requirements (CR / IR / AR)
