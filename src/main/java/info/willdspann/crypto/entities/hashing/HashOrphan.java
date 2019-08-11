package info.willdspann.crypto.entities.hashing;

import java.sql.Timestamp;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Entity
@Table(name = "secure_hashing.hash_orphans_graveyard")
public class HashOrphan {

    @Id
    @NotNull
    @Size(min = 64, max = 97)
    private String orphanedHash;

    @NotNull
    private Timestamp createdAt;

    /** No-argument constructor needed by JPA. */
    HashOrphan() { }

    public String getOrphanedHash() {
        return orphanedHash;
    }

    public Timestamp getCreatedAt() {
        return createdAt;
    }
}
