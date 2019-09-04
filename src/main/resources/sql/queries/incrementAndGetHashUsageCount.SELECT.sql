--
-- Increments the hash usage count for a cleartext value given its unsalted hash, returning the new count.
-- If no entry yet exists for this unsalted hash, then a new entry with a count of 1 is inserted.
--
INSERT INTO secure_hashing.hash_usage_counts
    (used_hash)
    VALUES (:hash)
ON CONFLICT (used_hash) DO
    UPDATE SET (usage_count, last_updated_at) =
        (SELECT usage_count + 1, now()
         FROM secure_hashing.hash_usage_counts
            WHERE used_hash = :hash
         FOR UPDATE)
    RETURNING usage_count
;
