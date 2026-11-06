// Uniqueness constraints for the asset labels (they also create the lookup indexes MERGE relies on).
CREATE CONSTRAINT zone_name IF NOT EXISTS FOR (n:Zone) REQUIRE n.name IS UNIQUE;
CREATE CONSTRAINT asset_hostname IF NOT EXISTS FOR (n:Asset) REQUIRE n.hostname IS UNIQUE;
CREATE CONSTRAINT service_id IF NOT EXISTS FOR (n:Service) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT software_id IF NOT EXISTS FOR (n:Software) REQUIRE n.id IS UNIQUE;
