package tests;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.List;

import applet.Constants;
import applet.jcmathlib;
import cz.muni.fi.crocs.rcard.client.CardType;
import cz.muni.fi.crocs.rcard.client.Util;
import org.junit.jupiter.api.*;
import org.testng.Assert;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * Taken from JCMint repository.
 * <p>
 * GitHub: <a href="https://github.com/crocs-muni/JCMint">JCMint</a>
 */
public class PerformanceTest extends MusigTest {
    private final long REPEAT = 100;

    public PerformanceTest() {
        // Change card type in
        if (Constants.CARD_TYPE == jcmathlib.OperationSupport.JCOP4_P71) {
            setCardType(CardType.PHYSICAL);
        } else if (Constants.CARD_TYPE == jcmathlib.OperationSupport.SIMULATOR) {
            setCardType(CardType.JCARDSIMLOCAL);
        }
        setSimulateStateful(true);
    }

    @BeforeEach
    public void setUpMethod() throws Exception {
        reset();
    }

    @AfterEach
    public void tearDownMethod() throws Exception {
        reset();
    }

    @Test
    public void measureKeygen() throws Exception {
        keygen();
    }

    @Test
    public void measureNoncegen() throws Exception {
        noncegen();
    }

    @Test
    public void measureSign() throws Exception {
        signTestBase("/sign_perf_test.csv", false, true);
    }

    public void keygen () throws Exception {
        String fileName = "keygen_perf_result.csv";
        PrintWriter file = new PrintWriter(new FileWriter(fileName, false));

        for (int i = 0; i < REPEAT; ++i) {
            final CommandAPDU cmd = new CommandAPDU(Constants.CLA_MUSIG2, Constants.INS_GENERATE_KEYS, 0, 0);
            final ResponseAPDU responseAPDU = connect().transmit(cmd);
            Assert.assertEquals(responseAPDU.getSW(), 0x9000);
            file.printf("%d%n", statefulCard.getLastTransmitTime());
        }
        file.close();
    }

    public void noncegen () throws Exception {
        String fileName = "noncegen_perf_result.csv";
        String csvSource = "/noncegen_perf_test.csv";
        List<byte[]> apduDataArray = UtilMusig.csvToApdus(csvSource, PerformanceTest.class);
        PrintWriter file = new PrintWriter(new FileWriter(fileName, false));

        for (byte[] apduSetupData : apduDataArray) {
            CommandAPDU cmd = new CommandAPDU(Constants.CLA_MUSIG2, Constants.INS_SETUP_TEST_DATA, 0, 0, apduSetupData);
            ResponseAPDU responseAPDU = connect().transmit(cmd);
            Assert.assertEquals(responseAPDU.getSW(), 0x9000);

            cmd = new CommandAPDU(Constants.CLA_MUSIG2, Constants.INS_GENERATE_NONCES, 0, 0);
            responseAPDU = connect().transmit(cmd);

            Assert.assertNotNull(responseAPDU);
            Assert.assertEquals(responseAPDU.getSW(), 0x9000);
            file.printf("%d,", statefulCard.getLastTransmitTime());

            CommandAPDU cmd2 = new CommandAPDU(Constants.CLA_MUSIG2, Constants.INS_GET_PNONCE_SHARE, 0, 0);
            ResponseAPDU responseAPDU2 = connect().transmit(cmd2);

            Assert.assertNotNull(responseAPDU2);
            Assert.assertEquals(responseAPDU2.getSW(), 0x9000);

            file.printf("%d%n", statefulCard.getLastTransmitTime());
        }
        file.close();
    }


}
