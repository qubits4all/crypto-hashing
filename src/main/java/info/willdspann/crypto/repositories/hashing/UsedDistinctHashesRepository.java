package info.willdspann.crypto.repositories.hashing;

import javax.validation.constraints.NotNull;

import org.springframework.data.repository.NoRepositoryBean;

import info.willdspann.crypto.entities.hashing.UsedDistinctHash;
import info.willdspann.crypto.repositories.BaseRepository;

@NoRepositoryBean
public interface UsedDistinctHashesRepository extends BaseRepository<UsedDistinctHash, String> {

    /**
     * Saves a used hash to the {@code UsedDistinctHash} entity's backing DB table,
     * and returns whether the given hash is distinct or a duplicate.
     *
     * @param usedHash a salted hash to save to the {@code UsedDistinctHash} entity's backing DB table.
     * @return whether the given hash is distinct or a duplicate.
     */
    boolean saveUsedHash(@NotNull final UsedDistinctHash usedHash);

    /**
     * Returns whether the given hash has been used (i.e., whether it exists in the {@code UsedDistinctHash}
     * entity's backing DB table).
     *
     * @param hash a salted hash for which to check for existence.
     * @return whether the given hash has been used.
     */
    default boolean hashExists(@NotNull final String hash) {
        return existsById(hash);
    }
}
