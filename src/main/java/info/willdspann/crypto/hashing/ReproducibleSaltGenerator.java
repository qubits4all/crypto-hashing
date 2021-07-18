package info.willdspann.crypto.hashing;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.annotation.Nullable;
import javax.validation.constraints.NotNull;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.prng.BasicEntropySourceProvider;
import org.bouncycastle.crypto.prng.EntropySourceProvider;
import org.bouncycastle.crypto.prng.FixedSecureRandom;
import org.bouncycastle.crypto.prng.drbg.HashSP800DRBG;
import org.bouncycastle.crypto.prng.drbg.SP80090DRBG;

import static info.willdspann.crypto.hashing.ReproducibleSeedGenerator.NULL_STRING_MARKER;

/**
 * Utility class that supports generating a reproducible yet unpredictable sequence of salt values associated with a
 * given cleartext value and secret seed.
 *
 * @see ReproducibleSeedGenerator
 * @see SaltedHashGenerator
 */
public final class ReproducibleSaltGenerator {
    static final int DEFAULT_SALT_LENGTH = 16;     // bytes
    private static final String DRBG_ALGORITHM = "DRBG";
    private static final int DRBG_SECURITY_STRENGTH = 256; // highest security strength (should be >= the largest random value requested at a time)

    private ReproducibleSaltGenerator() { }

    public static byte[] generateSaltForValue(@NotNull final byte[] associatedBytes, @NotNull final byte[] secretSeed, int saltIndex) {
        assert saltIndex >= 0;

        final Iterator<byte[]> saltIter = iteratorForValue(associatedBytes, secretSeed);

        byte[] salt = null;
        for (int i = 0; i <= saltIndex; ++i) {
            salt = saltIter.next();
        }
        return salt;
    }

    public static String generateSaltForValue(@Nullable final String associatedValue,
                                              @NotNull final String secretSeedHex,
                                              int saltIndex) throws DecoderException {
        assert saltIndex >= 0;

        final Iterator<String> saltIter = iteratorForValue(associatedValue, secretSeedHex);

        String saltHex = null;
        for (int i = 0; i <= saltIndex; ++i) {
            saltHex = saltIter.next();
        }
        return saltHex;
    }

    /**
     * Calculates the first {@code count} salt values for the given associated data value and secret seed.
     *
     * @param associatedBytes
     * @param secretSeedBytes
     * @param count
     * @return
     */
    public static List<byte[]> generateSaltsForValue(@NotNull final byte[] associatedBytes,
                                                     @NotNull final byte[] secretSeedBytes,
                                                     int count) {
        assert count > 0;

        final Iterator<byte[]> saltIter = iteratorForValue(associatedBytes, secretSeedBytes);
        final List<byte[]> salts = new ArrayList<>(count);

        for (int i = 0; i < count; ++i) {
            salts.add(saltIter.next());
        }
        return salts;
    }

    /**
     * Calculates the first {@code count} salt values for the given associated data value and secret seed, returning
     * them in hexadecimal encoding.
     *
     * @param associatedValue
     * @param secretSeedHex
     * @param count
     * @return
     * @throws DecoderException
     */
    public static List<String> generateSaltsForValue(@Nullable final String associatedValue,
                                                     @NotNull final String secretSeedHex,
                                                     int count) throws DecoderException {
        assert count > 0;

        final Iterator<String> saltIter = iteratorForValue(associatedValue, secretSeedHex);
        final List<String> salts = new ArrayList<>(count);

        for (int i = 0; i < count; ++i) {
            salts.add(saltIter.next());
        }
        return salts;
    }

    public static Iterator<byte[]> iteratorForValue(@NotNull final byte[] associatedBytes,
                                                    @NotNull final byte[] secretSeedBytes
    ) {
        final byte[] associatedSeed = ReproducibleSeedGenerator.generateSeedForValue(associatedBytes, secretSeedBytes);

        return new SaltIterator(associatedSeed);
    }

    public static Iterator<String> iteratorForValue(@Nullable final String associatedValue, @NotNull final String secretSeedHex) throws DecoderException {
        byte[] associatedBytes;
        if (associatedValue != null) {
            associatedBytes = associatedValue.getBytes(StandardCharsets.UTF_8);
        } else {
            associatedBytes = NULL_STRING_MARKER.getBytes(StandardCharsets.UTF_8);
        }

        final byte[] secretSeedBytes = Hex.decodeHex(secretSeedHex);
        final byte[] associatedSeed = ReproducibleSeedGenerator.generateSeedForValue(associatedBytes, secretSeedBytes);

        return new HexSaltIterator(associatedSeed);
    }

    /**
     * Creates a Deterministic Random Bit Generator (DRBG), used to generate a reproducible yet unpredictable sequence
     * of salt values, from the given starting seed value.
     *
     * @param seedBytes
     * @return
     */
    private static SP80090DRBG initDRBG(byte[] seedBytes) {
        final SecureRandom preSeededFixedPRNG = new FixedSecureRandom(true, seedBytes);
        final EntropySourceProvider seedSource = new BasicEntropySourceProvider(preSeededFixedPRNG, false);

        return new HashSP800DRBG(
                new SHA256Digest(),
                DRBG_SECURITY_STRENGTH,
                seedSource.get(DRBG_SECURITY_STRENGTH),
                null,
                null
        );
    }


    private static class HexSaltIterator implements Iterator<String> {
        private SaltIterator iter;

        private HexSaltIterator(@NotNull final byte[] associatedSeed) {
            this.iter = new SaltIterator(associatedSeed);
        }

        private HexSaltIterator(@NotNull final SaltIterator saltIterator) {
            this.iter = saltIterator;
        }

        @Override
        public boolean hasNext() {
            return true;
        }

        @Override
        public String next() {
            return Hex.encodeHexString(iter.next());
        }
    }

    /**
     * An iterator that produces each pseudo-random salt value for a given associated data value's associated seed,
     * which should be generated via {@code ReproducibleSeedGenerator} from a common secret seed and the associated
     * data value.
     */
    private static class SaltIterator implements Iterator<byte[]> {
        private SP80090DRBG drbg;

        /**
         * Construct a salt iterator given a DRBG and an associated data value's associated seed.
         *
         * @param associatedSeed seed value from which to initialize the DRBG, generated via
         *                       {@code ReproducibleSeedGenerator} from a common secret seed and the associated data
         *                       value for which salts will be generated.
         */
        private SaltIterator(@NotNull final byte[] associatedSeed) {
            this.drbg = initDRBG(associatedSeed);
        }

        @Override
        public boolean hasNext() {
            return true;
        }

        @Override
        public byte[] next() {
            final byte[] nextSalt = new byte[DEFAULT_SALT_LENGTH];
            drbg.generate(nextSalt, null, false);

            return nextSalt;
        }
    }
}
