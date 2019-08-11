package info.willdspann.crypto.entities.hashing;

import java.sql.Timestamp;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

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

    public int getUsageCount() {
        return usageCount;
    }

    public Timestamp getCreatedAt() {
        return createdAt;
    }

    public Timestamp getLastUpdatedAt() {
        return lastUpdatedAt;
    }
}