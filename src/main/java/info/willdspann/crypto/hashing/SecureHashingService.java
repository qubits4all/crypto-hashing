package info.willdspann.crypto.hashing;

import java.util.Set;

public interface SecureHashingService {

    String generateSaltedHash(final String cleartext);

    Set<String> getSaltedHashes(final String cleartext);

}
