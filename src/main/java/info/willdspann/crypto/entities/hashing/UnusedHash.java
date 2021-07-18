package info.willdspann.crypto.entities.hashing;

import java.sql.Timestamp;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

/**
 * JPA entity for entries in a DB table that keeps track of no longer used salted hashes.
 */
@Entity
@Table(name = "secure_hashing.hash_graveyard")
public class UnusedHash {

    @Id
    @NotNull
    @Size(min = 64, max = 97)
    private String unusedHash;

    @NotNull
    private Timestamp createdAt;

    /** No-argument constructor needed by JPA. */
    UnusedHash() { }

    public String getUnusedHash() {
        return unusedHash;
    }

    public void setUnusedHash(String unusedHash) {
        this.unusedHash = unusedHash;
    }

    public Timestamp getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Timestamp createdAt) {
        this.createdAt = createdAt;
    }
}
