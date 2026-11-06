"""Neo4j connection helper (waits for the database, which needs time to start in Docker)."""
import sys
import time

from neo4j import GraphDatabase
from neo4j.exceptions import AuthError

from . import config


def driver(wait: int = 60):
    drv = GraphDatabase.driver(config.NEO4J_URI, auth=(config.NEO4J_USER, config.NEO4J_PASSWORD))
    deadline = time.time() + wait
    while True:
        try:
            drv.verify_connectivity()
            return drv
        except AuthError:
            sys.exit("Neo4j rejected the username/password (check NEO4J_USER / NEO4J_PASSWORD in .env)")
        except Exception as exc:
            if time.time() > deadline:
                sys.exit(f"Cannot reach Neo4j at {config.NEO4J_URI}: {exc}")
            print("waiting for Neo4j ...")
            time.sleep(3)
