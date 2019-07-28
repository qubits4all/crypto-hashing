package info.willdspann.crypto.hashing;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;

public class ReproducibleSeedGenerator {
    public static final String NULL_STRING_MARKER = "";

    /**
     * Generates a reproducible but unpredictable seed value (64 B) associated with the given {@code associatedValue}
     * and seeded with the given {@code secretSeed} value.
     *
     * @param associatedValue
     * @param secretSeed
     * @return
     */
    public static byte[] generateSeedForValue(byte[] associatedValue, byte[] secretSeed) {
        final byte[] unsaltedHash = DigestUtils.sha512(associatedValue);
        final ByteArrayOutputStream baos = new ByteArrayOutputStream(secretSeed.length + unsaltedHash.length);
        baos.writeBytes(secretSeed);
        baos.writeBytes(unsaltedHash);

        return DigestUtils.sha512(baos.toByteArray());
    }

    public static String generateSeedForValue(final String associatedValue, final String secretSeedHex) throws DecoderException {
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
