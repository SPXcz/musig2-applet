package applet;

public class Constants {

    // Settings
    //public final static short CARD_TYPE = jcmathlib.OperationSupport.SIMULATOR;
    public final static short CARD_TYPE = jcmathlib.OperationSupport.JCOP4_P71;
    public static final short V = (short) 2; // Musig 2 attribute. Either 2 or 4. V = 4 currently isn't fully supported.
    public static final short FULL_LEN = (short) 256;
    public static final short HASH_LEN = (short) 32;
    public static final short SHARE_LEN = (short) 32; //32
    public static final short POINT_LEN = (short) 65;
    public static final short XCORD_LEN = (short) 33;
    public static final short MAX_MESSAGE_LEN = (short) 999999; //255; // Still only 16 bytes instead of 32 bytes as specified in BIP
    public static final short MAX_JC_BUFFER_LEN = (short) 32766;

    // Class
    public static final byte CLA_MUSIG2 = (byte) 0xA6;

    // Instruction
    public static final byte INS_GENERATE_KEYS = (byte) 0xBB;
    public static final byte INS_COMBINE_SHARES = (byte) 0x4D;
    public static final byte INS_GET_XONLY_PUBKEY = (byte) 0x8B;
    public static final byte INS_GET_PLAIN_PUBKEY = (byte) 0x5A;
    public static final byte INS_SET_AGG_PUBKEY = (byte) 0x76;
    public static final byte INS_SET_AGG_NONCES = (byte) 0x9A;
    public static final byte INS_GET_PNONCE_SHARE = (byte) 0x35;
    public static final byte INS_GENERATE_NONCES = (byte) 0x5E;
    public static final byte INS_COMBINE_NONCES = (byte) 0x6F;
    public static final byte INS_SIGN = (byte) 0x49;
    public static final byte INS_RESET = (byte) 0x65;
    public static final byte INS_SETUP_TEST_DATA = (byte) 0x67;

    // States
    public static final byte STATE_TRUE = (byte) 0xF4;
    public static final byte STATE_FALSE = (byte) 0x2C;

    // Err
    public static final short E_TOO_FEW_PARTICIPANTS = (byte) 0xFF7F;
    public static final short E_TOO_MANY_PARTICIPANTS = (byte) 0xFF4F;
    public static final short E_BUFFER_OVERLOW = (byte) 0xFFCA;
    public static final short E_CRYPTO_EXCEPTION = (byte) 0xFF77;
    public static final short E_MESSAGE_TOO_LONG = (byte) 0xFF88;
    public static final short E_NO_MESSAGE = (byte) 0xFF89;
    public static final short E_WRONG_XCORD_LEN = (byte) 0xFF99;
    public static final short E_ALL_PUBKEYSHARES_SAME = (byte) 0xFFAA;
    public static final short E_TWEAK_TOO_LONG = (byte) 0xFFBB;
    public static final short E_HASHER_UNINITIALIZED = (byte) 0xFFCC;
    public static final short E_POSSIBLE_SECNONCE_REUSE = (byte) 0xFFCD;

    // Generic err
    // Taken from jcfrost.Consts
    public static final short SW_Exception = (short) 0xff01;
    public static final short SW_ArrayIndexOutOfBoundsException = (short) 0xff02;
    public static final short SW_ArithmeticException = (short) 0xff03;
    public static final short SW_ArrayStoreException = (short) 0xff04;
    public static final short SW_NullPointerException = (short) 0xff05;
    public static final short SW_NegativeArraySizeException = (short) 0xff06;
    public static final short SW_CryptoException_prefix = (short) 0xf100;
    public static final short SW_SystemException_prefix = (short) 0xf200;
    public static final short SW_PINException_prefix = (short) 0xf300;
    public static final short SW_TransactionException_prefix = (short) 0xf400;
    public static final short SW_CardRuntimeException_prefix = (short) 0xf500;

    // Testing
    // IMPORTANT: Must be set to FALSE state in production
    // Tests won't pass if set to FALSE
    public static final byte DEBUG = Constants.STATE_TRUE;
    //public static final byte[] RAND_TEST = UtilMusig.hexStringToByteArray("0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F");
    public static byte[] RAND_TEST = new byte[] {(byte) 15, (byte) 15, (byte) 15, (byte) 15, (byte) 15, (byte) 15,
            (byte) 15, (byte) 15, (byte) 15, (byte) 15, (byte) 15, (byte) 15, (byte) 15, (byte) 15, (byte) 15,
            (byte) 15, (byte) 15, (byte) 15, (byte) 15, (byte) 15, (byte) 15, (byte) 15, (byte) 15, (byte) 15,
            (byte) 15, (byte) 15, (byte) 15, (byte) 15, (byte) 15, (byte) 15, (byte) 15, (byte) 15};

}
