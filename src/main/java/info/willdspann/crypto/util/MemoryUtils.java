package info.willdspann.crypto.util;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

/**
 * Utility class providing memory and in-memory I/O helper functions.
 */
public final class MemoryUtils {

    private MemoryUtils() {}

    /**
     * Concatenates the given byte-array buffers, returning a new single byte-array.
     *
     * @param buffers byte-array buffers to be concatenated.
     * @return a new byte-array containing the contents of each byte-array buffer concatenated in the order given.
     */
    public static byte[] concatenateBuffers(final byte[]... buffers) {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (byte[] buffer : buffers) {
            baos.writeBytes(buffer);
        }
        return baos.toByteArray();
    }

    /**
     * Clears a sensitive byte-array buffer, by filling it with zero bytes.
     *
     * @param sensitiveBuffer sensitive byte-array buffer to be cleared.
     */
    public static void clearBuffer(final byte[] sensitiveBuffer) {
        Arrays.fill(sensitiveBuffer, (byte) 0);
    }
}
