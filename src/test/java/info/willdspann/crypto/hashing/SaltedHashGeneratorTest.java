package info.willdspann.crypto.hashing;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//import org.springframework.data.util.StreamUtils;

import org.springframework.data.util.StreamUtils;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import info.willdspann.crypto.util.hashing.HashingUtils;
import info.willdspann.crypto.valueobjects.SaltedHash;

import static java.util.stream.Collectors.toList;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

@Test
public class SaltedHashGeneratorTest {
    private static final int HASH_LEN = HashingUtils.DEFAULT_HASH_ALGORITHM.getDigestLength() / 8;  // 32 B for SHA-256
    private static final int SALT_LEN = ReproducibleSaltGenerator.DEFAULT_SALT_LENGTH;
    private static final Logger log = LoggerFactory.getLogger(SaltedHashGeneratorTest.class);

    private byte[] secureSeed;

    @BeforeClass
    public void init() {
        SecureRandom secureRandom;
        try {
            secureRandom = SecureRandom.getInstance("NativePRNG");
        } catch (NoSuchAlgorithmException nsae) {
            log.warn("Unable to create SecureRandom using 'NativePRNG' algorithm -- falling back to default");
            secureRandom = new SecureRandom();
        }
        this.secureSeed = secureRandom.generateSeed(SaltedHashGenerator.DEFAULT_SEED_LEN);
    }

    @Test
    public void zerothSaltedHashOfStringIsReproducible() {
        final SaltedHashGenerator hashGen1 = new SaltedHashGenerator(Arrays.copyOf(this.secureSeed, secureSeed.length));
        final byte[] providedStringBytes = "spamandeggs".getBytes(StandardCharsets.UTF_8);

        final SaltedHash saltedHash = hashGen1.getNthSaltedHash(providedStringBytes, 0);

        assertThat(saltedHash.getSaltedHash().length, is(HASH_LEN));
        assertThat(saltedHash.getSalt().length, is(SALT_LEN));

        final SaltedHashGenerator hashGen2 = new SaltedHashGenerator(Arrays.copyOf(this.secureSeed, secureSeed.length));
        final SaltedHash reproducedSaltedHash = hashGen2.getNthSaltedHash(providedStringBytes, 0);

        assertThat(reproducedSaltedHash.getSaltedHash().length, is(HASH_LEN));
        assertThat(reproducedSaltedHash.getSalt().length, is(SALT_LEN));
        assertThat(reproducedSaltedHash, equalTo(saltedHash));
    }

    @Test
    public void streamOfSaltedHashesIsReproducible() {
        final SaltedHashGenerator hashGen1 = new SaltedHashGenerator(Arrays.copyOf(this.secureSeed, secureSeed.length));
        final byte[] providedStringBytes = "spamandeggs".getBytes(StandardCharsets.UTF_8);

        final Iterator<SaltedHash> hashIter = hashGen1.saltedHashIterator(providedStringBytes);
        final List<SaltedHash> saltedHashes = streamFromIterator(hashIter)
                .limit(3)
                .peek( saltedHash -> {
                    assertThat(saltedHash.getSaltedHash().length, is(HASH_LEN));
                    assertThat(saltedHash.getSalt().length, is(SALT_LEN));
                })
                .collect(toList());

        final SaltedHashGenerator reproducedHashGen = new SaltedHashGenerator(Arrays.copyOf(this.secureSeed, secureSeed.length));
        final Iterator<SaltedHash> reproducedHashIter = reproducedHashGen.saltedHashIterator(providedStringBytes);
        final List<SaltedHash> reproducedSaltedHashes = streamFromIterator(reproducedHashIter)
                .limit(3)
                .peek( saltedHash -> {
                    assertThat(saltedHash.getSaltedHash().length, is(HASH_LEN));
                    assertThat(saltedHash.getSalt().length, is(SALT_LEN));
                })
                .collect(toList());

        assertThat(reproducedSaltedHashes, equalTo(saltedHashes));
    }

    private <T> Stream<T> streamFromIterator(Iterator<T> iterator) {
        return StreamSupport.stream(
                Spliterators.spliterator(iterator, Integer.MAX_VALUE, Spliterator.ORDERED),
                false);
    }
}
