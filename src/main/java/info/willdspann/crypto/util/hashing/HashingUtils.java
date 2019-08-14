package info.willdspann.crypto.util.hashing;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

import javax.validation.constraints.NotNull;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.lang.Nullable;

import info.willdspann.crypto.util.MemoryUtils;
import info.willdspann.crypto.valueobjects.SaltedHash;

public final class HashingUtils {
    static final String NULL_STRING_MARKER = "";

    // Enforce noninstantiability of this utility class.
    private HashingUtils() {}

    public static byte[] unsaltedHash(@NotNull final byte[] cleartextBytes) {
        return DigestUtils.sha256(cleartextBytes);
    }

    public static String unsaltedHashHex(@Nullable final String cleartext) {
        final byte[] cleartextBytes = Objects.requireNonNullElse(cleartext, NULL_STRING_MARKER)
                .getBytes(StandardCharsets.UTF_8);

        return DigestUtils.sha256Hex(cleartextBytes);
    }

    /**
     * Treating the public but unpredictable salt value like the secret value in a seeded-hash, we apply the secret-
     * suffix design for creating a seeded hash resistance to length-extension attacks, as follows.
     *   {@code sha256( cleartext | salt ) }
     *
     * @param cleartextBytes
     * @param saltBytes
     * @return
     */
    public static SaltedHash saltedHash(@NotNull final byte[] cleartextBytes, @NotNull final byte[] saltBytes) {
        final byte[] buffer = MemoryUtils.concatenateBuffers(cleartextBytes, saltBytes);
        final byte[] saltedHash = DigestUtils.sha256(buffer);
        MemoryUtils.clearBuffer(buffer);

        return new SaltedHash(saltedHash, saltBytes);
    }

    public static SaltedHash saltedHash(@Nullable final String cleartext,
                                        @NotNull final String saltHex) throws DecoderException
    {
        final byte[] cleartextBytes = Objects.requireNonNullElse(cleartext, NULL_STRING_MARKER)
                .getBytes(StandardCharsets.UTF_8);
        final byte[] saltBytes = Hex.decodeHex(saltHex);

        return saltedHash(cleartextBytes, saltBytes);
    }
}
