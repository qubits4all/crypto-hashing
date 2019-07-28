package info.willdspann.crypto.hashing;

import java.nio.charset.StandardCharsets;
import java.security.DrbgParameters;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import static info.willdspann.crypto.hashing.ReproducibleSeedGenerator.NULL_STRING_MARKER;

public final class ReproducibleSaltGenerator {
    private static final String DRBG_ALGORITHM = "DRBG";
    private static final int DEFAULT_SALT_LENGTH = 16;  // bytes

    private ReproducibleSaltGenerator() { }

    public static byte[] generateSaltForValue(final byte[] associatedBytes, final byte[] secretSeed, int saltIndex) {
        assert saltIndex >= 0;

        final Iterator<byte[]> saltIter = iteratorForValue(associatedBytes, secretSeed);

        byte[] salt = null;
        for (int i = 0; i <= saltIndex; ++i) {
            salt = saltIter.next();
        }
        return salt;
    }

    public static String generateSaltForValue(final String associatedValue,
                                              final String secretSeedHex,
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
    public static List<byte[]> generateSaltsForValue(final byte[] associatedBytes,
                                                     final byte[] secretSeedBytes,
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
    public static List<String> generateSaltsForValue(final String associatedValue,
                                                     final String secretSeedHex,
                                                     int count) throws DecoderException {
        assert count > 0;

        final Iterator<String> saltIter = iteratorForValue(associatedValue, secretSeedHex);
        final List<String> salts = new ArrayList<>(count);

        for (int i = 0; i < count; ++i) {
            salts.add(saltIter.next());
        }
        return salts;
    }

    public static Iterator<byte[]> iteratorForValue(final byte[] associatedBytes, final byte[] secretSeedBytes) {
        final SecureRandom drbg = initDRBG();
        final byte[] associatedSeed = ReproducibleSeedGenerator.generateSeedForValue(associatedBytes, secretSeedBytes);

        return new SaltIterator(drbg, associatedSeed);
    }

    public static Iterator<String> iteratorForValue(final String associatedValue, final String secretSeedHex) throws DecoderException {
        final SecureRandom drbg = initDRBG();

        byte[] associatedBytes;
        if (associatedValue != null) {
            associatedBytes = associatedValue.getBytes(StandardCharsets.UTF_8);
        } else {
            associatedBytes = NULL_STRING_MARKER.getBytes(StandardCharsets.UTF_8);
        }

        final byte[] secretSeedBytes = Hex.decodeHex(secretSeedHex);
        final byte[] associatedSeed = ReproducibleSeedGenerator.generateSeedForValue(associatedBytes, secretSeedBytes);

        return new HexSaltIterator(drbg, associatedSeed);
    }

    private static SecureRandom initDRBG() {
        SecureRandom drbg;
        try {
            drbg = SecureRandom.getInstance("DRBG",
                    DrbgParameters.instantiation(
                            256,
                            DrbgParameters.Capability.RESEED_ONLY,
                            null)
            );
        } catch (NoSuchAlgorithmException nsae) {
            throw new IllegalStateException(String.format("Unable to instantiate SecureRandom with the following PRNG" +
                    " algorithm: %s", DRBG_ALGORITHM));
        }
        return drbg;
    }


    private static class HexSaltIterator implements Iterator<String> {
        private SaltIterator iter;

        private HexSaltIterator(final SecureRandom drbg, final byte[] associatedSeed) {
            this.iter = new SaltIterator(drbg, associatedSeed);
        }

        private HexSaltIterator(final SaltIterator saltIterator) {
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
        private SecureRandom drbg;

        /**
         * Construct a salt iterator given a DRBG and an associated data value's associated seed.
         *
         * @param drbg a Deterministic Random Bit Generator (DRBG) used to generate a reproducible yet unpredictable
         *             sequence of salt values, from the given starting seed value.
         * @param associatedSeed seed value from which to initialize the DRBG, generated via
         *                       {@code ReproducibleSeedGenerator} from a common secret seed and the associated data
         *                       value for which salts will be generated.
         */
        private SaltIterator(final SecureRandom drbg, final byte[] associatedSeed) {
            this.drbg = drbg;
            this.drbg.setSeed(associatedSeed);
        }

        @Override
        public boolean hasNext() {
            return true;
        }

        @Override
        public byte[] next() {
            final byte[] nextSalt = new byte[DEFAULT_SALT_LENGTH];
            drbg.nextBytes(nextSalt);

            return nextSalt;
        }
    }
}
