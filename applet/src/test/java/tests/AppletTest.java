package tests;

import applet.Constants;
import cz.muni.fi.crocs.rcard.client.CardType;
import org.junit.jupiter.api.*;
import org.testng.Assert;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.ArrayList;
import java.util.HashMap;

/**
 * Example test class for the applet
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author xsvenda, Dusan Klinec (ph4r05)
 */
public class AppletTest extends BaseTest {

    private static final int NO_OF_PARTICIPANTS = 3;
    private static final int V = 2;
    private static ArrayList<byte[]> privateKeyShares = new ArrayList<>();
    private static ArrayList<byte[]> publicKeyShares = new ArrayList<>();
    private static byte[] aggregatePublicKey = new byte[V];
    private static ArrayList<byte[][]> outNonce = new ArrayList<>();
    private static ArrayList<byte[][]> stateNonce = new ArrayList<>();
    private static ArrayList<byte[]> aggregateOutNonce = new ArrayList<>();

    public AppletTest() {
        // Change card type here if you want to use physical card

        // setCardType(CardType.PHYSICAL);
        // setCardType(CardType.REMOTE);
        setCardType(CardType.JCARDSIMLOCAL);
        setSimulateStateful(true);
    }

    @BeforeAll
    public static void setUpClass() throws Exception {

    }


    @AfterAll
    public static void tearDownClass() throws Exception {
    }

    @BeforeEach
    public void setUpMethod() throws Exception {
    }

    @AfterEach
    public void tearDownMethod() throws Exception {

    }

    // Example test
    @Test
    public void testKeygenExecutes() throws Exception {
        final CommandAPDU cmd = new CommandAPDU(Constants.CLA_MUSIG2, Constants.INS_GENERATE_KEYS, 0, 0);
        final ResponseAPDU responseAPDU = connect().transmit(cmd);
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(0x9000, responseAPDU.getSW());
        Assert.assertNotNull(responseAPDU.getBytes());
    }

    @Test
    public void testKeygenValues1() throws Exception {

        HashMap<String, byte[]> data = new HashMap<>();
        data.put("settings", new byte[] {Constants.STATE_TRUE, Constants.STATE_FALSE, Constants.STATE_FALSE, Constants.STATE_FALSE, Constants.STATE_FALSE});
        data.put("privateKey", new byte[]{(byte) 0x2, (byte) 0x44, (byte) 0xef, (byte) 0xcd, (byte) 0x3c, (byte) 0xf2,
                (byte) 0xba, (byte) 0x48, (byte) 0x54, (byte) 0x70, (byte) 0x1c, (byte) 0x5f, (byte) 0x52, (byte) 0x4d,
                (byte) 0xc1, (byte) 0x48, (byte) 0x34, (byte) 0x9b, (byte) 0x4c, (byte) 0x45, (byte) 0x64, (byte) 0x23,
                (byte) 0x4e, (byte) 0x66, (byte) 0xb8, (byte) 0x15, (byte) 0x67, (byte) 0x24, (byte) 0xd, (byte) 0x6b,
                (byte) 0x74, (byte) 0xde});

        data.put("publicKeyOut", new byte[]{(byte) 0x8c, (byte) 0x44, (byte) 0xdc, (byte) 0x5c, (byte) 0x18,
                (byte) 0xa6, (byte) 0xcb, (byte) 0x72, (byte) 0x40, (byte) 0xfe, (byte) 0xee, (byte) 0x31, (byte) 0x32,
                (byte) 0x82, (byte) 0x7a, (byte) 0x9e, (byte) 0x9d, (byte) 0x43, (byte) 0x1a, (byte) 0x6c, (byte) 0xa1,
                (byte) 0x58, (byte) 0xff, (byte) 0xef, (byte) 0xf7, (byte) 0x49, (byte) 0x21, (byte) 0xd5, (byte) 0x6e,
                (byte) 0x91, (byte) 0x29, (byte) 0x83});

        byte[] dataBytes = concatenateDeter(data);

        final CommandAPDU cmd = new CommandAPDU(Constants.CLA_MUSIG2, Constants.INS_GENERATE_KEYS, 0, 0, dataBytes);
        final ResponseAPDU responseAPDU = connect().transmit(cmd);
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(0x9000, responseAPDU.getSW());

        CommandAPDU cmd2 = new CommandAPDU(Constants.CLA_MUSIG2, Constants.INS_GET_XONLY_PUBKEY, 0, 0);
        ResponseAPDU responseAPDU2 = connect().transmit(cmd2);

        Assert.assertNotNull(responseAPDU2);
        Assert.assertEquals(0x9000, responseAPDU2.getSW());
        Assert.assertEquals(responseAPDU2.getData(), data.get("publicKeyOut"));
    }

    @Test
    public void testKeygenValues2() throws Exception {

        HashMap<String, byte[]> data = new HashMap<>();
        data.put("settings", new byte[] {Constants.STATE_TRUE, Constants.STATE_FALSE, Constants.STATE_FALSE, Constants.STATE_FALSE, Constants.STATE_FALSE});
        data.put("privateKey", new byte[]{(byte) 0x74, (byte) 0x4a, (byte) 0x32, (byte) 0x98, (byte) 0x65, (byte) 0x26,
                (byte) 0x62, (byte) 0x58, (byte) 0xd, (byte) 0x19, (byte) 0x62, (byte) 0x92, (byte) 0x85, (byte) 0x3,
                (byte) 0x32, (byte) 0x64, (byte) 0x1d, (byte) 0x6c, (byte) 0xa5, (byte) 0xe8, (byte) 0x1e, (byte) 0xaf,
                (byte) 0x61, (byte) 0xb0, (byte) 0x20, (byte) 0x45, (byte) 0x2e, (byte) 0xac, (byte) 0x8f, (byte) 0x31,
                (byte) 0x7f, (byte) 0x8});

        data.put("publicKeyOut", new byte[]{(byte) 0x3, (byte) 0xc0, (byte) 0x60, (byte) 0xce, (byte) 0x18, (byte) 0xaf,
                (byte) 0xe3, (byte) 0x3d, (byte) 0x2c, (byte) 0x6d, (byte) 0xb9, (byte) 0x68, (byte) 0xfb, (byte) 0x2d,
                (byte) 0x96, (byte) 0xf8, (byte) 0x2f, (byte) 0xdd, (byte) 0x8c, (byte) 0x9a, (byte) 0x5a, (byte) 0x62,
                (byte) 0xb1, (byte) 0xbb, (byte) 0x95, (byte) 0x77, (byte) 0x11, (byte) 0xe6, (byte) 0xe9, (byte) 0xaf,
                (byte) 0xca, (byte) 0x2b, (byte) 0x14});

        byte[] dataBytes = concatenateDeter(data);

        final CommandAPDU cmd = new CommandAPDU(Constants.CLA_MUSIG2, Constants.INS_GENERATE_KEYS, 0, 0, dataBytes);
        final ResponseAPDU responseAPDU = connect().transmit(cmd);
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(0x9000, responseAPDU.getSW());

        CommandAPDU cmd2 = new CommandAPDU(Constants.CLA_MUSIG2, Constants.INS_GET_PLAIN_PUBKEY, 0, 0);
        ResponseAPDU responseAPDU2 = connect().transmit(cmd2);

        Assert.assertNotNull(responseAPDU2);
        Assert.assertEquals(0x9000, responseAPDU2.getSW());
        Assert.assertEquals(responseAPDU2.getData(), data.get("publicKeyOut"));
    }

    @Test
    public void testNonceGen1 () throws Exception {

        HashMap<String, byte[]> data = new HashMap<>();
        data.put("settings", new byte[] {Constants.STATE_FALSE, Constants.STATE_TRUE, Constants.STATE_FALSE, Constants.STATE_FALSE, Constants.STATE_FALSE});
        data.put("publicKey", UtilMusig.hexStringToByteArray("02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"));
        data.put("expectedSecNonce", UtilMusig.hexStringToByteArray("89BDD787D0284E5E4D5FC572E49E316BAB7E21E3B1830DE37DFE80156FA41A6D0B17AE8D024C53679699A6FD7944D9C4A366B514BAF43088E0708B1023DD289702F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"));
        data.put("expectedPubNonce", UtilMusig.hexStringToByteArray("02C96E7CB1E8AA5DAC64D872947914198F607D90ECDE5200DE52978AD5DED63C000299EC5117C2D29EDEE8A2092587C3909BE694D5CFF0667D6C02EA4059F7CD9786"));

        byte[] dataBytes = concatenateDeter(data);

        CommandAPDU cmd = new CommandAPDU(Constants.CLA_MUSIG2, Constants.INS_GENERATE_NONCES, 0, 0, dataBytes);
        ResponseAPDU responseAPDU = connect().transmit(cmd);

        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(responseAPDU.getSW(), 0x9000);

        CommandAPDU cmd2 = new CommandAPDU(Constants.CLA_MUSIG2, Constants.INS_GET_PNONCE_SHARE, 0, 0);
        ResponseAPDU responseAPDU2 = connect().transmit(cmd2);

        Assert.assertNotNull(responseAPDU2);
        Assert.assertEquals(responseAPDU2.getSW(), 0x9000);

        byte[] pubNonce = responseAPDU2.getData();

        Assert.assertEquals(pubNonce, data.get("expectedPubNonce"));
    }

    @Test
    public void testSign1 () throws Exception {
        HashMap<String, byte[]> data = new HashMap<>();
        data.put("settings", new byte[] {Constants.STATE_TRUE, Constants.STATE_FALSE, Constants.STATE_FALSE, Constants.STATE_TRUE, Constants.STATE_TRUE});
        data.put("privateKey", UtilMusig.hexStringToByteArray("7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671"));
        data.put("aggnonce", UtilMusig.hexStringToByteArray("028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9"));
        data.put("secnonce", UtilMusig.hexStringToByteArray( "508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9"));
        data.put("secnonce2", UtilMusig.hexStringToByteArray("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9"));
        data.put("coefA", UtilMusig.hexStringToByteArray("7D6E3F4F742A6339631446AA2243F656FD1FE3FBE2693C745EC12DFE9AEAA084"));
        data.put("tacc", UtilMusig.hexStringToByteArray("0000000000000000000000000000000000000000000000000000000000000000"));
        data.put("gacc", UtilMusig.hexStringToByteArray("0000000000000000000000000000000000000000000000000000000000000001"));
        data.put("aggregatePublicKeyTest", UtilMusig.hexStringToByteArray("02ECF5759B1627A7E2CFFB9C55EB630454A187691596D46B80F6C7F5E35BABC831"));
        data.put("expectedSignature", UtilMusig.hexStringToByteArray("012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB"));
        byte[] msg = UtilMusig.hexStringToByteArray("F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF");

        byte[] dataSetUpPubKey = concatenate(data.get("aggregatePublicKeyTest"), data.get("gacc"));
        dataSetUpPubKey = concatenate(dataSetUpPubKey, data.get("tacc"));
        dataSetUpPubKey = concatenate(dataSetUpPubKey, data.get("coefA"));

        CommandAPDU cmdSetUp = new CommandAPDU(Constants.CLA_MUSIG2, Constants.INS_SET_AGG_PUBKEY, 0, 0, dataSetUpPubKey);
        ResponseAPDU responseAPDUSetUp = connect().transmit(cmdSetUp);

        Assert.assertNotNull(responseAPDUSetUp);
        Assert.assertEquals(responseAPDUSetUp.getSW(), 0x9000);

        byte[] dataBytes = concatenateDeter(data);
        dataBytes = concatenate(dataBytes, msg);

        CommandAPDU cmd = new CommandAPDU(Constants.CLA_MUSIG2, Constants.INS_SIGN, 0, 0, dataBytes);
        ResponseAPDU responseAPDU = connect().transmit(cmd);

        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(responseAPDU.getSW(), 0x9000);
        Assert.assertEquals(responseAPDU.getData(), data.get("expectedSignature"));
    }

    // Generated by GitHub Copilot
    private static byte[] concatenate(byte[] array1, byte[] array2) {
        byte[] result = new byte[array1.length + array2.length];
        System.arraycopy(array1, 0, result, 0, array1.length);
        System.arraycopy(array2, 0, result, array1.length, array2.length);
        return result;
    }

    private static byte[] concatenateDeter (HashMap<String, byte[]> data) {
        byte[] dataBytes = new byte[]{};

        dataBytes = concatenate(dataBytes, data.get("settings"));

        if (data.get("settings")[0] == Constants.STATE_TRUE) {
            dataBytes = concatenate(dataBytes, data.get("privateKey"));
        }

        if (data.get("settings")[1] == Constants.STATE_TRUE) {
            dataBytes = concatenate(dataBytes, data.get("publicKey"));
        }

        if (data.get("settings")[2] == Constants.STATE_TRUE) {
            dataBytes = concatenate(dataBytes, data.get("aggregatePublicKey"));
        }

        if (data.get("settings")[3] == Constants.STATE_TRUE) {
            dataBytes = concatenate(dataBytes, data.get("aggnonce"));
        }

        if (data.get("settings")[4] == Constants.STATE_TRUE) {
            dataBytes = concatenate(dataBytes, data.get("secnonce"));
        }

        return dataBytes;
    }
}
