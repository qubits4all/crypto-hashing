package info.willdspann.crypto.repositories.hashing;

import javax.validation.constraints.NotNull;

import org.springframework.stereotype.Repository;

import info.willdspann.crypto.entities.hashing.UsedDistinctHash;
import info.willdspann.crypto.repositories.MapInMemoryRepository;

@Repository
public class UsedDistinctHashesTestRepository extends MapInMemoryRepository<UsedDistinctHash, String>
        implements UsedDistinctHashesRepository
{
    public UsedDistinctHashesTestRepository() {
        super(UsedDistinctHash::getUsedHash);
    }

    @Override
    public boolean saveUsedHash(@NotNull UsedDistinctHash usedHash) {
        return saveIfAbsent(usedHash);
    }
}
