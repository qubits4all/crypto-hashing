--
-- Table for tracking generated salted hashes, to help ensure every salted hash is used only once (to maintain
-- indistinguishability).
--
CREATE TABLE IF NOT EXISTS secure_hashing.used_distinct_hashes
(
    used_hash       varchar(97)     NOT NULL, -- salted SHA-256 hash hex. encoded [salt:saltedHash]
    created_at      timestamp       NOT NULL    DEFAULT now(),
    CONSTRAINT used_distinct_hashes_pk  PRIMARY KEY (used_hash)
);
