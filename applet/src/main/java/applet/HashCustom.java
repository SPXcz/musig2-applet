package applet;

import javacard.security.MessageDigest;

public class HashCustom {

    //TODO: Delka koeficientu?
    public static final byte[] NONCE_AGG = {(byte) 0x00, (byte) 0x01, (byte) 0xAA};
    public static final byte[] NONCE_NON = {(byte) 0x05, (byte) 0xA1, (byte) 0xAE};
    public static final byte[] NONCE_SIG = {(byte) 0x75, (byte) 0xB6, (byte) 0xCC};
    public static final byte[] NONCE_HASH_KEYS = {(byte) 0x66, (byte) 0x77, (byte) 0x99};
    public static final byte[] NONCE_KEYAGG_COEF = {(byte) 0xAA, (byte) 0xBB, (byte) 0xBB};
    public static final byte[] NONCE_NONCEGEN = {(byte) 0x6B, (byte) 0xC6, (byte) 0xF4};
    public static final byte[] NONCE_NONCECOEF = {(byte) 0x0B, (byte) 0x74, (byte) 0xF1};

    private MessageDigest digest;

    //TODO: Koeficienty, které by diferencovaly hashovaci funkce nejsou v BIP definovany
    public HashCustom () {
        digest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    }

    public void update (byte[] inBuffer, short offset, short length) {
        digest.update(inBuffer, offset, length);
    }

    public void doFinal (byte[] inBuffer,
                         short offset,
                         short length,
                         byte[] outBuffer,
                         short outOffset,
                         byte[] nonce) {
        digest.update(nonce, (short) 0, (short) nonce.length);
        digest.doFinal(inBuffer, offset, length, outBuffer, outOffset);
        digest.reset();
    }
}
