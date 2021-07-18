package info.willdspann.crypto.hashing;

import java.nio.charset.StandardCharsets;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;

import info.willdspann.crypto.util.MemoryUtils;

/**
 * Utility class that generates associated seed values, which use a secret seed value to produce a specially-constructed
 * seeded hash of a given piece of associated data. This associated seed can be used for generating a reproducible yet
 * unpredictable sequence of associated salt values, by using it to seed a Deterministic Random Bit Generator (DRBG).
 *
 * @see ReproducibleSaltGenerator
 * @see SaltedHashGenerator
 */
public class ReproducibleSeedGenerator {
    public static final String NULL_STRING_MARKER = "";

    /**
     * <p>
     * Generates a reproducible yet unpredictable seed value (64 B) associated with the given {@code associatedValue}
     * and seeded with the given {@code secretSeed} value. </p>
     * <p>
     * This method uses a secret-suffix seeded hash (SHA-512) to generate the associated seed value, where '|'
     * represents concatenation. Secret-suffix seeded hashing is resistant to length-extension attacks, in contrast
     * to secret-prefix seeded hashing that is vulnerable.
     * <pre>
     *     sha512( sha512( associatedValue ) | secretSeed )
     * </pre>
     * </p>
     *
     * @param associatedValue value to which the generated seed will be associated.
     * @param secretSeed secret seed value used to ensure the generated associated seed is unpredictable.
     * @return a reproducible yet unpredictable seed value (64 B) associated with the given {@code associatedValue}
     *   and secret seed value.
     */
    public static byte[] generateSeedForValue(byte[] associatedValue, byte[] secretSeed) {
        final byte[] unsaltedHash = DigestUtils.sha512(associatedValue);
        final byte[] unsaltedHashAndSeed = MemoryUtils.concatenateBuffers(unsaltedHash, secretSeed);

        return DigestUtils.sha512(unsaltedHashAndSeed);
    }

    /**
     * <p>
     * Generates a reproducible yet unpredictable seed value (64 B) associated with the given {@code associatedValue}
     * and seeded with the given {@code secretSeedHex} secret seed value, and returns this associated seed value
     * hex. encoded. </p>
     * <p>
     * This method uses a secret-suffix seeded hash (SHA-512) to generate the associated seed value, where '|'
     * represents concatenation. Secret-suffix seeded hashing is resistant to length-extension attacks, in contrast
     * to secret-prefix seeded hashing that is vulnerable.
     * <pre>
     *     sha512( sha512( associatedValue ) | secretSeed )
     * </pre>
     * </p>
     *
     * @param associatedValue value to which the generated seed will be associated.
     * @param secretSeedHex secret seed value (hex. encoded) used to ensure the generated associated seed is
     *                      unpredictable.
     * @return a reproducible yet unpredictable seed value (64 B) hex. encoded, which is associated with the given
     *   {@code associatedValue} and secret seed value.
     */
    public static String generateSeedForValue(final String associatedValue,
                                              final String secretSeedHex) throws DecoderException
    {
        byte[] associatedBytes = null;
        if (associatedValue != null) {
            associatedBytes = associatedValue.getBytes(StandardCharsets.UTF_8);
        } else {
            associatedBytes = NULL_STRING_MARKER.getBytes(StandardCharsets.UTF_8);
        }

        final byte[] secretSeed = Hex.decodeHex(secretSeedHex);
        final byte[] associatedSeed = generateSeedForValue(associatedBytes, secretSeed);

        return Hex.encodeHexString(associatedSeed);
    }
}
