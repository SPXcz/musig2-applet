package applet;

public class Constants {

    // Other
    public static final short MAX_PARTICIPATS = (short) 3; // Should be higher in the future

    // Settings
    public static final short V = (short) 2; // Musig 2 attribute. Either 2 or 4. V = 4 currently isn't fully supported.
    public static final short FULL_LEN = (short) 256;
    public static final short HASH_LEN = (short) 32;
    public static final short SHARE_LEN = (short) 32; //32
    public static final short POINT_LEN = (short) 65;
    public static final short XCORD_LEN = (short) 33;
    public static final short MAX_PSHARE_LIST_LEN = (short) (MAX_PARTICIPATS * POINT_LEN);
    public static final short MAX_MESSAGE_LEN = (short) 255;

    // Class
    public static final byte CLA_MUSIG2 = (byte) 0xA6;

    // Instruction
    public static final byte INS_GENERATE_KEYS = (byte) 0xBB;
    public static final byte INS_COMBINE_SHARES = (byte) 0x4D;
    public static final byte INS_GET_PKEY_SHARE = (byte) 0x70;
    public static final byte INS_GET_PNONCE_SHARE = (byte) 0x35;
    public static final byte INS_GENERATE_NONCES = (byte) 0x5E;
    public static final byte INS_COMBINE_NONCES = (byte) 0x6F;
    public static final byte INS_SIGN = (byte) 0x49;

    // States
    public static final byte STATE_TRUE = (byte) 0xF4;
    public static final byte STATE_FALSE = (byte) 0x2C;

    // Err
    public static final byte E_TOO_FEW_PARTICIPANTS = (byte) 0x7F;
    public static final byte E_TOO_MANY_PARTICIPANTS = (byte) 0x4F;
    public static final byte E_BUFFER_OVERLOW = (byte) 0xCA;
    public static final byte E_CRYPTO_EXCEPTION = (byte) 0x77;
    public static final byte E_MESSAGE_TOO_LONG = (byte) 0x88;
    public static final byte E_WRONG_XCORD_LEN = (byte) 0x99;
    public static final byte E_ALL_PUBKEYSHARES_SAME = (byte) 0xAA;
    public static final byte E_TWEAK_TOO_LONG = (byte) 0xBB;

    // Testing

}
