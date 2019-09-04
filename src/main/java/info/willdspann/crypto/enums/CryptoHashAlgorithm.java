package info.willdspann.crypto.enums;

/**
 * Enumerated type representing a cryptographic hash algorithm, including its short algorithm name, digest length in
 * bits, and a summary description.
 */
public enum CryptoHashAlgorithm {
    MD5("MD5", 128, "MD5 Message-Digest Algorithm 128-bit digest"),
    MD6("MD6", -1, "MD6 Message-Digest Algorithm variable-length (1-512 bits) digest"),
    SHA_1("SHA-1", 160, "Secure Hash Algorithm 1 (SHA-1) 160-bit digest"),
    SHA_224("SHA-224", 224, "Secure Hash Algorithm 2 (SHA-2) 224-bit digest"),
    SHA_256("SHA-256", 256, "Secure Hash Algorithm 2 (SHA-2) 256-bit digest"),
    SHA_384("SHA-384", 384, "Secure Hash Algorithm 2 (SHA-2) 384-bit digest"),
    SHA_512("SHA-512", 512, "Secure Hash Algorithm 2 (SHA-2) 512-bit digest"),
    SHA_512_224("SHA-512/224", 224, "Secure Hash Algorithm 2 (SHA-2) truncated 224-bit SHA-512 digest"),
    SHA_512_256("SHA-512/256", 256, "Secure Hash Algorithm 2 (SHA-2) truncated 256-bit SHA-512 digest"),
    SHA3_224("SHA3-224", 224, "Secure Hash Algorithm 3 (SHA-3) Keccak-based (Keccak[448]) 224-bit digest"),
    SHA3_256("SHA3-256", 256, "Secure Hash Algorithm 3 (SHA-3) Keccak-based (Keccak[512]) 256-bit digest"),
    SHA3_384("SHA3-384", 384, "Secure Hash Algorithm 3 (SHA-3) Keccak-based (Keccak[768]) 384-bit digest"),
    SHA3_512("SHA3-512", 512, "Secure Hash Algorithm 3 (SHA-3) Keccak-based (Keccak[1024]) 512-bit digest"),
    SHAKE_128("SHAKE128", -1, "Secure Hash Algorithm 3 (SHA-3) Keccak-based (Keccak[256]) arbitrary-length digest"),
    SHAKE_256("SHAKE256", -1, "Secure Hash Algorithm 3 (SHA-3) Keccak-based (Keccak[512]) arbitrary-length digest"),
    KANGAROO_TWELVE("KangarooTwelve", -1, "Keccak-p based (Keccak-p[1600, 12]) arbitrary-length digest"),
    MARSUPILAMI_FOURTEEN("MarsupilamiFourteen", -1, "Keccak-p based (Keccak-p[1600, 14]) arbitrary-length digest"),
    RIPEMD_128("RIPEMD-128", 128, "RIPE Message Digest (RIPEMD) 128-bit digest"),
    RIPEMD_256("RIPEMD-256", 256, "RIPE Message Digest (RIPEMD) 256-bit digest"),
    RIPEMD_160("RIPEMD-160", 160, "RIPE Message Digest (RIPEMD) 160-bit digest"),
    RIPEMD_320("RIPEMD-320", 320, "RIPE Message Digest (RIPEMD) 320-bit digest"),
    BLAKE_224("BLAKE-224", 224, "BLAKE 224-bit digest"),
    BLAKE_256("BLAKE-256", 256, "BLAKE 256-bit digest"),
    BLAKE_384("BLAKE-384", 384, "BLAKE 384-bit digest"),
    BLAKE_512("BLAKE-512", 512, "BLAKE 512-bit digest"),
    BLAKE2S_224("BLAKE2s-224", 224, "BLAKE2s 224-bit digest"),
    BLAKE2S_256("BLAKE2s-256", 256, "BLAKE2s 256-bit digest"),
    BLAKE2B_384("BLAKE2b-384", 384, "BLAKE2b 384-bit digest"),
    BLAKE2B_512("BLAKE2b-512", 512, "BLAKE2b 512-bit digest"),
    WHIRLPOOL("Whirlpool", 512, "Whirlpool 512-bit digest"),
    TIGER_128("Tiger-128", 128, "Tiger 128-bit digest"),
    TIGER_160("Tiger-160", 160, "Tiger 160-bit digest"),
    TIGER_192("Tiger-192", 192, "Tiger 192-bit digest"),
    STREEBOG_256("GOST3411_2012_256Digest", 256, "GOST R 34.11-2012 (Streebog) 256-bit digest"),
    STREEBOG_512("GOST3411_2012_256Digest", 512, "GOST R 34.11-2012 (Streebog) 512-bit digest");

    private final String algorithm;
    private final int digestLength;  // digest length (bits)
    private final String description;

    public static final int CUSTOM_LENGTH = -1;

    CryptoHashAlgorithm(String algorithm, int digestLength, String description) {
        this.algorithm = algorithm;
        this.digestLength = digestLength;
        this.description = description;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * Returns the digest's length in bits.
     * @return the digest's length in bits.
     */
    public int getDigestLength() {
        return digestLength;
    }

    public String getDescription() {
        return description;
    }
}
