"""Look up CPE vendor / product names in the CTI graph, to fill cpe_vendor / cpe_product in lab/services.csv.

    python -m asset_kg.find_cpe nginx                       vendor:product pairs containing "nginx"
    python -m asset_kg.find_cpe --versions f5 nginx         sample versions stored for that pair
"""
import sys

from .db import driver


def main() -> None:
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)
    with driver(10) as drv, drv.session() as s:
        if args[0] == "--versions" and len(args) == 3:
            rows = s.run("MATCH (c:CPE {vendor: $v, product: $p}) RETURN DISTINCT c.version AS version "
                         "ORDER BY version LIMIT 40", v=args[1], p=args[2])
            print(", ".join(str(r["version"]) for r in rows) or "no CPE for that vendor:product")
        else:
            term = args[0].lower()
            rows = s.run("MATCH (c:CPE) WHERE c.vendor CONTAINS $t OR c.product CONTAINS $t "
                         "RETURN c.vendor AS vendor, c.product AS product, count(*) AS cpe_nodes "
                         "ORDER BY cpe_nodes DESC LIMIT 25", t=term)
            found = False
            for r in rows:
                found = True
                print(f"{r['vendor']}:{r['product']}   ({r['cpe_nodes']} CPE nodes)")
            if not found:
                print("no match (is the CVE year range loaded in the CTI graph?)")


if __name__ == "__main__":
    main()
