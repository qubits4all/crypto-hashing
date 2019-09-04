package info.willdspann.crypto.valueobjects;

import java.util.Arrays;

import javax.validation.constraints.NotNull;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import info.willdspann.crypto.enums.CryptoHashAlgorithm;

/**
 * Value object representing a salted hash and its associated salt value.
 */
public final class SaltedHash {
    public static final CryptoHashAlgorithm DEFAULT_HASH_ALGORITHM = CryptoHashAlgorithm.SHA_256;

    private final byte[] hash;
    private final byte[] salt;
    private final CryptoHashAlgorithm hashAlgorithm;

    public SaltedHash(@NotNull final byte[] saltedHashBytes,
                      @NotNull final byte[] saltBytes,
                      @NotNull final CryptoHashAlgorithm hashAlgorithm)
    {
        this.hash = Arrays.copyOf(saltedHashBytes, saltedHashBytes.length);
        this.salt = Arrays.copyOf(saltBytes, saltBytes.length);
        this.hashAlgorithm = hashAlgorithm;
    }

    public SaltedHash(@NotNull final byte[] saltedHashBytes, @NotNull final byte[] saltBytes) {
        this(saltedHashBytes, saltBytes, DEFAULT_HASH_ALGORITHM);
    }

    public SaltedHash(@NotNull final String saltedHashHex,
                      @NotNull final String saltHex,
                      @NotNull final CryptoHashAlgorithm hashAlgorithm) throws DecoderException
    {
        this(Hex.decodeHex(saltedHashHex), Hex.decodeHex(saltHex), hashAlgorithm);
    }

    public SaltedHash(@NotNull final String saltedHashHex, @NotNull final String saltHex) throws DecoderException {
        this(saltedHashHex, saltHex, DEFAULT_HASH_ALGORITHM);
    }

    public byte[] getSaltedHash() {
        return Arrays.copyOf(hash, hash.length);
    }

    public String getSaltedHashHex() {
        return Hex.encodeHexString(hash);
    }

    public byte[] getSalt() {
        return Arrays.copyOf(salt, salt.length);
    }

    public String getSaltHex() {
        return Hex.encodeHexString(salt);
    }

    public CryptoHashAlgorithm getHashAlgorithm() {
        return hashAlgorithm;
    }

    @Override
    public String toString() {
        return String.format("%s:%s", getSaltHex(), getSaltedHashHex());
    }
}
