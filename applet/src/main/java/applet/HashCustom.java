package applet;

import javacard.framework.ISOException;
import javacard.security.MessageDigest;

public class HashCustom {

    //Hash function specific constants

    public static byte[] MUSIG_NONCE = new byte[] {(byte) 0xf8, (byte) 0xc1, (byte) 0xc, (byte) 0xbc, (byte) 0x61,
            (byte) 0x4e, (byte) 0xd1, (byte) 0xa0, (byte) 0x84, (byte) 0xb4, (byte) 0x37, (byte) 0x5, (byte) 0x2b,
            (byte) 0x5d, (byte) 0x2c, (byte) 0x4b, (byte) 0x50, (byte) 0x1a, (byte) 0x9d, (byte) 0xe7, (byte) 0xaa,
            (byte) 0xfb, (byte) 0xe3, (byte) 0x48, (byte) 0xac, (byte) 0xe8, (byte) 0x2, (byte) 0x6c, (byte) 0xa7,
            (byte) 0xfc, (byte) 0xb1, (byte) 0x7b};

    public static byte[] MUSIG_NONCECOEF = new byte[] {(byte) 90, (byte) 109, (byte) 69, (byte) 246, (byte) 218, (byte) 41,
            (byte) 230, (byte) 81, (byte) 203, (byte) 27, (byte) 162, (byte) 184, (byte) 172, (byte) 44, (byte) 221, (byte) 78,
            (byte) 188, (byte) 21, (byte) 194, (byte) 251, (byte) 178, (byte) 137, (byte) 240, (byte) 204, (byte) 130, (byte) 27,
            (byte) 191, (byte) 10, (byte) 52, (byte) 9, (byte) 95, (byte) 50};

    public static byte[] BIP_CHALLENGE = new byte[] {(byte) 123, (byte) 181, (byte) 45, (byte) 122, (byte) 159, (byte) 239,
            (byte) 88, (byte) 50, (byte) 62, (byte) 177, (byte) 191, (byte) 122, (byte) 64, (byte) 125, (byte) 179, (byte) 130,
            (byte) 210, (byte) 243, (byte) 242, (byte) 216, (byte) 27, (byte) 177, (byte) 34, (byte) 79, (byte) 73, (byte) 254,
            (byte) 81, (byte) 143, (byte) 109, (byte) 72, (byte) 211, (byte) 124};

    private MessageDigest digest;
    private static boolean firstDigest = true;

    public HashCustom () {
        digest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    }

    public void init (byte[] nonce) {

        if (firstDigest && nonce != null) {
            digest.update(nonce, (short) 0x00, Constants.HASH_LEN);
            digest.update(nonce, (short) 0x00, Constants.HASH_LEN);
            firstDigest = false;
        } else {
            ISOException.throwIt(Constants.E_HASHER_UNINITIALIZED);
        }
    }

    public void update (byte[] inBuffer, short offset, short length) {

        if (firstDigest) {
            ISOException.throwIt(Constants.E_HASHER_UNINITIALIZED);
        }

        digest.update(inBuffer, offset, length);
    }

    public void doFinal (byte[] inBuffer,
                         short offset,
                         short length,
                         byte[] outBuffer,
                         short outOffset) {

        if (firstDigest) {
            ISOException.throwIt(Constants.E_HASHER_UNINITIALIZED);
        }

        digest.doFinal(inBuffer, offset, length, outBuffer, outOffset);
        firstDigest = true;
    }
}
