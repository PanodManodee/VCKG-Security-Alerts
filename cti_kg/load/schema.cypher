// Uniqueness constraints (also create the lookup indexes MERGE relies on).
CREATE CONSTRAINT weakness_id IF NOT EXISTS FOR (n:Weakness) REQUIRE n.cwe_id IS UNIQUE;
CREATE CONSTRAINT vulnerability_id IF NOT EXISTS FOR (n:Vulnerability) REQUIRE n.cve_id IS UNIQUE;
CREATE CONSTRAINT attackpattern_id IF NOT EXISTS FOR (n:AttackPattern) REQUIRE n.capec_id IS UNIQUE;
CREATE CONSTRAINT technique_id IF NOT EXISTS FOR (n:Technique) REQUIRE n.attack_id IS UNIQUE;
CREATE CONSTRAINT tactic_id IF NOT EXISTS FOR (n:Tactic) REQUIRE n.attack_id IS UNIQUE;
CREATE CONSTRAINT group_id IF NOT EXISTS FOR (n:Group) REQUIRE n.attack_id IS UNIQUE;
CREATE CONSTRAINT mitigation_id IF NOT EXISTS FOR (n:Mitigation) REQUIRE n.mit_id IS UNIQUE;
CREATE CONSTRAINT detectionmethod_id IF NOT EXISTS FOR (n:DetectionMethod) REQUIRE n.name IS UNIQUE;
CREATE CONSTRAINT platform_id IF NOT EXISTS FOR (n:Platform) REQUIRE n.name IS UNIQUE;
CREATE CONSTRAINT cpe_id IF NOT EXISTS FOR (n:CPE) REQUIRE n.cpe23 IS UNIQUE;

// Lookup indexes for later stages (asset linking by vendor/product, alert lookup by name).
CREATE INDEX cpe_vendor_product IF NOT EXISTS FOR (n:CPE) ON (n.vendor, n.product);
CREATE INDEX technique_name IF NOT EXISTS FOR (n:Technique) ON (n.name);
CREATE INDEX vulnerability_cvss3 IF NOT EXISTS FOR (n:Vulnerability) ON (n.cvss3_score);
