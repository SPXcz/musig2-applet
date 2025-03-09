package tests;

import applet.Constants;
import org.junit.jupiter.api.*;
import org.testng.Assert;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.*;

/**
 * Example test class for the applet
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author xsvenda, Dusan Klinec (ph4r05)
 */

@Tag("unit")
public class AppletTest extends MusigTest {

    @BeforeEach
    public void setUpMethod() throws Exception {
        reset();
    }

    @AfterEach
    public void tearDownMethod() throws Exception {
        reset();
    }

    // Sanity check
    @Test
    public void testKeygenExecutes() throws Exception {
        final CommandAPDU cmd = new CommandAPDU(Constants.CLA_MUSIG2, Constants.INS_GENERATE_KEYS, 0, 0);
        final ResponseAPDU responseAPDU = connect().transmit(cmd);
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(responseAPDU.getSW(), 0x9000);
        Assert.assertNotNull(responseAPDU.getBytes());
    }

    // Parameter loading adds cca. 500ms to total computation time
    @Test
    public void testNonceGenBIPReferenceData () throws Exception {

        HashMap<String, byte[]> data = new HashMap<>();
        data.put("settings", new byte[] {Constants.STATE_FALSE, Constants.STATE_TRUE, Constants.STATE_FALSE, Constants.STATE_FALSE, Constants.STATE_FALSE});
        data.put("publicKey", UtilMusig.hexStringToByteArray("02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"));
        data.put("expectedSecNonce", UtilMusig.hexStringToByteArray("89BDD787D0284E5E4D5FC572E49E316BAB7E21E3B1830DE37DFE80156FA41A6D0B17AE8D024C53679699A6FD7944D9C4A366B514BAF43088E0708B1023DD289702F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"));
        data.put("expectedPubNonce", UtilMusig.hexStringToByteArray("02C96E7CB1E8AA5DAC64D872947914198F607D90ECDE5200DE52978AD5DED63C000299EC5117C2D29EDEE8A2092587C3909BE694D5CFF0667D6C02EA4059F7CD9786"));

        byte[] dataBytes = UtilMusig.concatenateDeter(data);

        CommandAPDU cmd = new CommandAPDU(Constants.CLA_MUSIG2, Constants.INS_SETUP_TEST_DATA, 0, 0, dataBytes);
        ResponseAPDU responseAPDU = connect().transmit(cmd);

        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(responseAPDU.getSW(), 0x9000);

        cmd = new CommandAPDU(Constants.CLA_MUSIG2, Constants.INS_GENERATE_NONCES, 0, 0);
        responseAPDU = connect().transmit(cmd);

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
    public void testKeygenCustomVectors () throws Exception {
        String csvSource = "/keygen_test.csv";
        List<byte[]> apduDataArray = UtilMusig.csvToApdus(csvSource, AppletTest.class);
        List<byte[]> pks = UtilMusig.individualColumn(csvSource, "publicKeyOut");
        assert apduDataArray.size() == pks.size();

        for (int i = 0; i < apduDataArray.size(); i++) {
            final CommandAPDU cmd = new CommandAPDU(Constants.CLA_MUSIG2, Constants.INS_GENERATE_KEYS, 0, 0, apduDataArray.get(i));
            final ResponseAPDU responseAPDU = connect().transmit(cmd);
            Assert.assertNotNull(responseAPDU);
            Assert.assertEquals(responseAPDU.getSW(), 0x9000);

            CommandAPDU cmd2 = new CommandAPDU(Constants.CLA_MUSIG2, Constants.INS_GET_PLAIN_PUBKEY, 0, 0);
            ResponseAPDU responseAPDU2 = connect().transmit(cmd2);

            Assert.assertNotNull(responseAPDU2);
            Assert.assertEquals(responseAPDU2.getSW(), 0x9000);
            Assert.assertEquals(responseAPDU2.getData(), pks.get(i));
            reset();
        }
    }

    @Test
    public void testNoncegenCustomVectors () throws Exception {
        String csvSource = "/noncegen_test.csv";
        List<byte[]> apduDataArray = UtilMusig.csvToApdus(csvSource, AppletTest.class);
        List<byte[]> pubnonces = UtilMusig.individualColumn(csvSource, "expectedPubNonce");
        assert apduDataArray.size() == pubnonces.size();

        for (int i = 0; i < apduDataArray.size(); i++) {

            CommandAPDU cmd = new CommandAPDU(Constants.CLA_MUSIG2, Constants.INS_SETUP_TEST_DATA, 0, 0, apduDataArray.get(i));
            ResponseAPDU responseAPDU = connect().transmit(cmd);

            Assert.assertNotNull(responseAPDU);
            Assert.assertEquals(responseAPDU.getSW(), 0x9000);

            cmd = new CommandAPDU(Constants.CLA_MUSIG2, Constants.INS_GENERATE_NONCES, 0, 0);
            responseAPDU = connect().transmit(cmd);

            Assert.assertNotNull(responseAPDU);
            Assert.assertEquals(responseAPDU.getSW(), 0x9000);

            CommandAPDU cmd2 = new CommandAPDU(Constants.CLA_MUSIG2, Constants.INS_GET_PNONCE_SHARE, 0, 0);
            ResponseAPDU responseAPDU2 = connect().transmit(cmd2);

            Assert.assertNotNull(responseAPDU2);
            Assert.assertEquals(responseAPDU2.getSW(), 0x9000);

            byte[] pubNonce = responseAPDU2.getData();

            Assert.assertEquals(pubNonce, pubnonces.get(i));
            reset();
        }
    }

    @Test
    public void testSignCustomVectors () throws Exception {
        String csvSource = "/sign_test.csv";
        signTestBase(csvSource, false, false);
    }

    @Test
    public void testSignReferenceVectors () throws Exception {
        String csvSource = "/sign_test_ref.csv";
        signTestBase(csvSource, false, false);
    }

    @Test
    public void testFailSign () throws Exception {
        String csvSource = "/sign_fail_test.csv";
        signTestBase(csvSource, true, false);
    }

    @Test
    public void testFailLoadSignData () throws Exception {
        String csvSource = "/load_data_fail_test.csv";

        List<byte[]> setUpTestData = UtilMusig.csvToApdus(csvSource, AppletTest.class);
        List<byte[]> aggkeys = UtilMusig.individualColumn(csvSource, "aggregatePublicKeyTest");
        List<byte[]> coefAs = UtilMusig.individualColumn(csvSource, "coefA");
        assert aggkeys.size() == coefAs.size();
        assert setUpTestData.size() == coefAs.size();

        for (byte[] setUpTestDatum : setUpTestData) {

            CommandAPDU cmdSetUp = new CommandAPDU(Constants.CLA_MUSIG2, Constants.INS_SETUP_TEST_DATA, 0, 0, setUpTestDatum);
            ResponseAPDU responseAPDUSetUp = connect().transmit(cmdSetUp);

            Assert.assertNotNull(responseAPDUSetUp);
            Assert.assertNotEquals(responseAPDUSetUp.getSW(), 0x9000);
        }
    }
}
