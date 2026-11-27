-- Run once on an existing upstream database, while the old app is stopped.
-- Back up the database and old encryption key first. See README.md.
ALTER TABLE users
  ADD COLUMN ad_guid CHAR(32) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  ADD COLUMN ad_username VARCHAR(255) DEFAULT NULL,
  ADD COLUMN disabled_at DATETIME DEFAULT NULL,
  ADD COLUMN auth_version INT UNSIGNED NOT NULL DEFAULT 0,
  ADD UNIQUE KEY uniq_users_ad_guid (ad_guid);

DROP TABLE IF EXISTS profile_shares;
DROP TABLE IF EXISTS magic_links;
DROP TABLE IF EXISTS oauth_identities;

ALTER TABLE users
  DROP COLUMN email,
  DROP COLUMN avatar_url,
  DROP COLUMN google_id,
  DROP COLUMN microsoft_id,
  DROP COLUMN github_id;

-- Next apply schema.sql to create the rate limit and audit tables. Existing
-- users and token IDs remain intact. Link each legacy user explicitly.
