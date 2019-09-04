package info.willdspann.crypto.entities.hashing;

import java.sql.Timestamp;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

/**
 * JPA entity for entries in a DB table that keeps track of the number of used salted hashes for a given cleartext
 * value, indexed by its unsalted hash.
 */
@Entity
@Table(name = "secure_hashing.hash_usage_counts")
public class HashUsageCount {

    @Id
    @NotNull
    @Size(min = 64, max = 64)
    private String usedHash;

    private int usageCount;

    @NotNull
    private Timestamp createdAt;

    @NotNull
    private Timestamp lastUpdatedAt;

    /** No-argument constructor needed by JPA. */
    private HashUsageCount() { }

    public String getUsedHash() {
        return usedHash;
    }

    public void setUsedHash(String usedHash) {
        this.usedHash = usedHash;
    }

    public int getUsageCount() {
        return usageCount;
    }

    public void setUsageCount(int usageCount) {
        this.usageCount = usageCount;
    }

    public Timestamp getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Timestamp createdAt) {
        this.createdAt = createdAt;
    }

    public Timestamp getLastUpdatedAt() {
        return lastUpdatedAt;
    }

    public void setLastUpdatedAt(Timestamp lastUpdatedAt) {
        this.lastUpdatedAt = lastUpdatedAt;
    }
}
