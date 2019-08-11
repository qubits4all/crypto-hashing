package info.willdspann.crypto.entities.hashing;

import java.sql.Timestamp;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Entity
@Table(name = "secure_hashing.used_distinct_hashes")
public class UsedDistinctHash {

    @Id
    @NotNull
    @Size(min = 64, max = 97)
    private String usedHash;

    @NotNull
    private Timestamp createdAt;

    /**
     * No-argument constructor needed by JPA.
     */
    UsedDistinctHash() { }

    public String getUsedHash() {
        return usedHash;
    }

    public Timestamp getCreatedAt() {
        return createdAt;
    }
}
