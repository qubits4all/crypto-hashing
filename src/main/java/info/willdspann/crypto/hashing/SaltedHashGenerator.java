package info.willdspann.crypto.hashing;

import java.util.Arrays;
import java.util.Iterator;
import java.util.NoSuchElementException;

import javax.security.auth.Destroyable;
import javax.validation.constraints.NotNull;

import info.willdspann.crypto.util.MemoryUtils;
import info.willdspann.crypto.util.hashing.HashingUtils;
import info.willdspann.crypto.valueobjects.SaltedHash;

public class SaltedHashGenerator implements Destroyable {
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
