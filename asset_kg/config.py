"""Paths and Neo4j settings for the asset graph.

Uses the same environment variables as cti_kg (NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD) and the
same .env file at the repository root, so both packages talk to the same database.
"""
import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

LAB = Path(os.getenv("ASSET_LAB_DIR", ROOT / "lab"))   # input CSVs (not 'data/': that folder is git-ignored)

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "change-me-please")

SOURCE = "asset_kg"   # value put in every `sources` list this package writes
