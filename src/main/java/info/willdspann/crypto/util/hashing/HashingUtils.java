package info.willdspann.crypto.util.hashing;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

import javax.annotation.Nullable;
import javax.validation.constraints.NotNull;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;

import info.willdspann.crypto.util.MemoryUtils;
import info.willdspann.crypto.valueobjects.SaltedHash;

public final class HashingUtils {
    static final String NULL_STRING_MARKER = "";

    // Enforce noninstantiability of this utility class.
    private HashingUtils() {}

    public static byte[] unsaltedHash(@NotNull final byte[] cleartextBytes) {
        return calculateHash(cleartextBytes);
    }

    public static String unsaltedHashHex(@Nullable final String cleartext) {
        final byte[] cleartextBytes = Objects.requireNonNullElse(cleartext, NULL_STRING_MARKER)
                .getBytes(StandardCharsets.UTF_8);

        return calculateHashToHex(cleartextBytes);
    }

    /**
     * <p>Generates a salted hash for the given cleartext and salt value.</p>
     * <p>
     * Treating the public but unpredictable salt value like the secret value in a seeded-hash, we apply the secret-
     * suffix design for creating a seeded hash resistant to length-extension attacks, as follows.</p>
     * <pre>
     *     sha256( cleartext | salt )
     * </pre>
     *
     * @param cleartextBytes cleartext byte array for which to generate a salted hash.
     * @param saltBytes salt value as a byte array to be concatenated with the cleartext prior to hash generation.
     * @return a salted hash for the given cleartext and salt value.
     */
    public static SaltedHash saltedHash(@NotNull final byte[] cleartextBytes, @NotNull final byte[] saltBytes) {
        final byte[] buffer = MemoryUtils.concatenateBuffers(cleartextBytes, saltBytes);
        final byte[] saltedHash = DigestUtils.sha256(buffer);
        MemoryUtils.clearBuffer(buffer);

        return new SaltedHash(saltedHash, saltBytes);
    }

    /**
     * <p>Generates a salted hash for the given cleartext and salt value.</p>
     * <p>
     * Treating the public but unpredictable salt value like the secret value in a seeded-hash, we apply the secret-
     * suffix design for creating a seeded hash resistant to length-extension attacks, as follows.</p>
     * <pre>
     *     sha256( cleartext | salt )
     * </pre>
     *
     * @param cleartext cleartext string for which to generate a salted hash.
     * @param saltHex salt value (hex. encoded) to be concatenated with the cleartext prior to hash generation.
     * @return a salted hash for the given cleartext and salt value.
     */
    public static SaltedHash saltedHash(@Nullable final String cleartext,
                                        @NotNull final String saltHex) throws DecoderException
    {
        final byte[] cleartextBytes = Objects.requireNonNullElse(cleartext, NULL_STRING_MARKER)
                .getBytes(StandardCharsets.UTF_8);
        final byte[] saltBytes = Hex.decodeHex(saltHex);

        return saltedHash(cleartextBytes, saltBytes);
    }

    private static byte[] calculateHash(@NotNull final byte[] cleartextBytes) {
        return DigestUtils.sha256(cleartextBytes);
    }

    private static String calculateHashToHex(@NotNull final byte[] cleartextBytes) {
        return DigestUtils.sha256Hex(cleartextBytes);
    }
}
