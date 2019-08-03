--
-- Table for tracking hash (e.g., SHA-2) usage counts.
--
CREATE TABLE IF NOT EXISTS secure_hashing.hash_usage_counts
(
    used_hash           varchar(64)     NOT NULL, -- unsalted (SHA-256) hash
    usage_count         int             NOT NULL    DEFAULT 1,
    created_at          timestamp       NOT NULL    DEFAULT now(),
    last_updated_at     timestamp       NOT NULL    DEFAULT now(),
    CONSTRAINT hash_usage_counts_pk     PRIMARY KEY (used_hash)
);
