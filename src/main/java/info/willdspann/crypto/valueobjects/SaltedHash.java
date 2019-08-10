package info.willdspann.crypto.valueobjects;

import java.util.Arrays;

import javax.validation.constraints.NotNull;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public final class SaltedHash {
    private final byte[] hash;
    private final byte[] salt;

    public SaltedHash(@NotNull final byte[] saltedHashBytes, @NotNull final byte[] saltBytes) {
        this.hash = Arrays.copyOf(saltedHashBytes, saltedHashBytes.length);
        this.salt = Arrays.copyOf(saltBytes, saltBytes.length);
    }

    public SaltedHash(@NotNull final String saltedHashHex, @NotNull final String saltHex) throws DecoderException {
        this(Hex.decodeHex(saltedHashHex), Hex.decodeHex(saltHex));
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

    @Override
    public String toString() {
        return String.format("%s:%s", getSaltHex(), getSaltedHashHex());
    }
}
