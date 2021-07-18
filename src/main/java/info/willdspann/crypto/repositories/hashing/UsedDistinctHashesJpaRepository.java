package info.willdspann.crypto.repositories.hashing;

import javax.persistence.PersistenceException;
import javax.validation.constraints.NotNull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import info.willdspann.crypto.entities.hashing.UsedDistinctHash;

@Repository
public interface UsedDistinctHashesJpaRepository extends UsedDistinctHashesRepository, JpaRepository<UsedDistinctHash, String> {
    Logger logger = LoggerFactory.getLogger(UsedDistinctHashesJpaRepository.class);

    @Override
    default boolean saveUsedHash(@NotNull UsedDistinctHash usedHash) {
        try {
            save(usedHash);
            return true;
        } catch (PersistenceException pe) {
            logger.warn("Unable to save duplicate used hash: {}", usedHash.getUsedHash());
            return false;
        }
    }
}
