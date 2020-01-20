package info.willdspann.crypto.hashing;

import java.util.Arrays;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Set;

import javax.security.auth.Destroyable;
import javax.validation.constraints.NotNull;

import org.springframework.data.util.StreamUtils;

import info.willdspann.crypto.util.MemoryUtils;
import info.willdspann.crypto.util.hashing.HashingUtils;
import info.willdspann.crypto.valueobjects.SaltedHash;

import static java.util.stream.Collectors.toSet;

/**
 * This salted hash generator creates a reproducible yet unpredictable sequence of seed values associated to a given
 * cleartext value. It uses an associated seed generator to seed a Deterministic Random Bit Generator (DRBG), which is
 * used to produce the sequence of associated salt values each of which is used to produce a salted (SHA-256) hash.
 */
public class SaltedHashGenerator implements Destroyable {
    static final int DEFAULT_SEED_LEN = 64;  // bytes

    private final byte[] secretSeed;
    private boolean destroyed = false;

    public SaltedHashGenerator(@NotNull final byte[] secretSeed) {
        this.secretSeed = Arrays.copyOf(secretSeed, secretSeed.length);
    }

    public Iterator<SaltedHash> saltedHashIterator(@NotNull final byte[] cleartextBytes) {
        if (!destroyed) {
            return new SaltedHashIterator(cleartextBytes);
        }
        else {
            throw new IllegalStateException(
                    "Unable to create salted hash iterator -- Secret seed has been cleared with destroy()."
            );
        }
    }

    public SaltedHash getNthSaltedHash(@NotNull final byte[] cleartextBytes, int saltIndex) {
        if (!destroyed) {
            final byte[] salt = ReproducibleSaltGenerator.generateSaltForValue(cleartextBytes, secretSeed, saltIndex);
            return HashingUtils.saltedHash(cleartextBytes, salt);
        }
        else {
            throw new IllegalStateException(
                    "Unable to create salted hash -- Secret seed has been cleared with destroy()."
            );
        }
    }

    public Set<SaltedHash> getSaltedHashes(@NotNull final byte[] cleartextBytes, int count) {
        if (!destroyed) {
            final Iterator<SaltedHash> iter = new SaltedHashIterator(cleartextBytes);
            return StreamUtils.createStreamFromIterator(iter)
                    .limit(count)
                    .collect(toSet());
        }
        else {
            throw new IllegalStateException(
                    "Unable to create salted hashes -- Secret seed has been cleared with destroy()."
            );
        }
    }

    @Override
    public void destroy() {
        MemoryUtils.clearBuffer(this.secretSeed);
        this.destroyed = true;
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }


    private class SaltedHashIterator implements Iterator<SaltedHash>, Destroyable {
        private final byte[] cleartext;
        private final Iterator<byte[]> saltIter;
        private boolean destroyed = false;

        private SaltedHashIterator(@NotNull final byte[] cleartextBytes) {
            this.cleartext = Arrays.copyOf(cleartextBytes, cleartextBytes.length);
            this.saltIter = ReproducibleSaltGenerator.iteratorForValue(cleartextBytes, secretSeed);
        }

        @Override
        public boolean hasNext() {
            return !destroyed;
        }

        @Override
        public SaltedHash next() {
            if (!destroyed) {
                final byte[] nextSalt = saltIter.next();
                return HashingUtils.saltedHash(cleartext, nextSalt);
            }
            else {
                throw new NoSuchElementException(
                        "No more salted hashes may be generated -- Associated sensitive cleartext value has been " +
                        "cleared via destroy()."
                );
            }
        }

        @Override
        public void destroy() {
            MemoryUtils.clearBuffer(this.cleartext);
            this.destroyed = true;
        }

        @Override
        public boolean isDestroyed() {
            return destroyed;
        }
    }
}
