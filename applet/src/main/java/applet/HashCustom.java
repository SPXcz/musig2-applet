package applet;

import javacard.framework.ISOException;
import javacard.security.MessageDigest;

public class HashCustom {

    //Hash function specific constants
    public static byte[] KEYAGG_LIST = new byte[] {(byte) 72, (byte) 28, (byte) 151, (byte) 28, (byte) 60, (byte) 11, (byte) 70,
            (byte) 215, (byte) 240, (byte) 178, (byte) 117, (byte) 174, (byte) 89, (byte) 141, (byte) 78, (byte) 44, (byte) 126,
            (byte) 215, (byte) 49, (byte) 156, (byte) 89, (byte) 74, (byte) 92, (byte) 110, (byte) 199, (byte) 158, (byte) 160,
            (byte) 212, (byte) 153, (byte) 2, (byte) 148, (byte) 240};

    public static byte[] KEYAGG_COEF = new byte[] {(byte) 191, (byte) 201, (byte) 4, (byte) 3, (byte) 77, (byte) 28, (byte) 136,
            (byte) 232, (byte) 200, (byte) 14, (byte) 34, (byte) 229, (byte) 61, (byte) 36, (byte) 86, (byte) 109, (byte) 100,
            (byte) 130, (byte) 78, (byte) 214, (byte) 66, (byte) 114, (byte) 129, (byte) 192, (byte) 145, (byte) 0, (byte) 249,
            (byte) 77, (byte) 205, (byte) 82, (byte) 201, (byte) 129};

    public static byte[] MUSIG_AUX = new byte[] {(byte) 64, (byte) 143, (byte) 140, (byte) 31, (byte) 41, (byte) 36, (byte) 33,
            (byte) 181, (byte) 86, (byte) 158, (byte) 188, (byte) 108, (byte) 181, (byte) 242, (byte) 226, (byte) 12, (byte) 241,
            (byte) 227, (byte) 132, (byte) 27, (byte) 71, (byte) 67, (byte) 159, (byte) 204, (byte) 88, (byte) 125, (byte) 32,
            (byte) 227, (byte) 193, (byte) 127, (byte) 8, (byte) 55};

    public static byte[] MUSIG_NONCE = new byte[] {(byte) 248, (byte) 193, (byte) 12, (byte) 188, (byte) 97, (byte) 78, (byte) 209,
            (byte) 160, (byte) 132, (byte) 180, (byte) 55, (byte) 5, (byte) 43, (byte) 93, (byte) 44, (byte) 75, (byte) 80, (byte) 26,
            (byte) 157, (byte) 231, (byte) 170, (byte) 251, (byte) 227, (byte) 72, (byte) 172, (byte) 232, (byte) 2, (byte) 108, (byte) 167,
            (byte) 252, (byte) 177, (byte) 123};

    public static byte[] MUSIG_NONCECOEF = new byte[] {(byte) 90, (byte) 109, (byte) 69, (byte) 246, (byte) 218, (byte) 41,
            (byte) 230, (byte) 81, (byte) 203, (byte) 27, (byte) 162, (byte) 184, (byte) 172, (byte) 44, (byte) 221, (byte) 78,
            (byte) 188, (byte) 21, (byte) 194, (byte) 251, (byte) 178, (byte) 137, (byte) 240, (byte) 204, (byte) 130, (byte) 27,
            (byte) 191, (byte) 10, (byte) 52, (byte) 9, (byte) 95, (byte) 50};

    public static byte[] BIP_CHALLENGE = new byte[] {(byte) 123, (byte) 181, (byte) 45, (byte) 122, (byte) 159, (byte) 239,
            (byte) 88, (byte) 50, (byte) 62, (byte) 177, (byte) 191, (byte) 122, (byte) 64, (byte) 125, (byte) 179, (byte) 130,
            (byte) 210, (byte) 243, (byte) 242, (byte) 216, (byte) 27, (byte) 177, (byte) 34, (byte) 79, (byte) 73, (byte) 254,
            (byte) 81, (byte) 143, (byte) 109, (byte) 72, (byte) 211, (byte) 124};

    public static byte[] MUSIG_DETER_NONCE = new byte[] {(byte) 189, (byte) 0, (byte) 136, (byte) 93, (byte) 236, (byte) 85,
            (byte) 28, (byte) 133, (byte) 144, (byte) 153, (byte) 34, (byte) 106, (byte) 174, (byte) 140, (byte) 132, (byte) 150,
            (byte) 158, (byte) 76, (byte) 19, (byte) 21, (byte) 210, (byte) 163, (byte) 161, (byte) 203, (byte) 105, (byte) 145,
            (byte) 238, (byte) 254, (byte) 37, (byte) 103, (byte) 197, (byte) 138};

    private MessageDigest digest;
    private static boolean firstDigest = true;

    //TODO: Koeficienty, které by diferencovaly hashovaci funkce nejsou v BIP definovany
    public HashCustom () {
        digest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    }

    public void init (byte[] nonce) {

        if (firstDigest && nonce != null) {
            digest.update(nonce, (short) 0x00, Constants.HASH_LEN);
            digest.update(nonce, (short) 0x00, Constants.HASH_LEN);
            firstDigest = false;
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
        digest.reset();
        firstDigest = true;
    }
}
