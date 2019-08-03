--
-- Table for tracking salted hashes (SHA-256) that have been "orphaned" due to an UPDATE or DELETE operation.
-- This table is useful for filtering out no longer in-use salted hashes, when determining the set of salted hashes
-- for a given sensitive value (e.g., e-mail address of DOB).
--
CREATE TABLE IF NOT EXISTS secure_hashing.hash_orphans_graveyard (
    orphaned_hash       varchar(97)         NOT NULL, -- salted hash (SHA-256) orphaned due to UPDATE or DELETE.
    created_at          timestamp           NOT NULL    DEFAULT now(),
    CONSTRAINT hash_orphans_graveyard_pk    PRIMARY KEY (orphaned_hash)
);
