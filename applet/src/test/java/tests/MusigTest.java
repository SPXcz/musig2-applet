package tests;

import applet.Constants;
import applet.jcmathlib;
import cz.muni.fi.crocs.rcard.client.CardType;
import org.testng.Assert;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public abstract class MusigTest extends BaseTest {

    public MusigTest() {

        // Change card type in
        if (Constants.CARD_TYPE == jcmathlib.OperationSupport.JCOP4_P71) {
            setCardType(CardType.PHYSICAL);
        } else if (Constants.CARD_TYPE == jcmathlib.OperationSupport.SIMULATOR) {
            setCardType(CardType.JCARDSIMLOCAL);
        }
        setSimulateStateful(true);
    }

    public void reset () throws Exception {
        final CommandAPDU cmd = new CommandAPDU(Constants.CLA_MUSIG2, Constants.INS_RESET, 0, 0);
        final ResponseAPDU responseAPDU = connect().transmit(cmd);
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(responseAPDU.getSW(), 0x9000);
    }

    public void signTestBase (String csvSource, boolean fail, boolean performanceTest)
            throws Exception  {

        String perfFileName = "sign_perf_result.csv";
        PrintWriter filePerfOut = new PrintWriter(new FileWriter(perfFileName, false));
        List<byte[]> setUpTestData = UtilMusig.csvToApdus(csvSource, MusigTest.class);
        List<byte[]> signatures = UtilMusig.individualColumn(csvSource, "expectedSignature");
        assert setUpTestData.size() == signatures.size();

        List<byte[]> aggkeys = UtilMusig.individualColumn(csvSource, "aggregatePublicKeyTest");
        List<byte[]> coefAs = UtilMusig.individualColumn(csvSource, "coefA");
        List<byte[]> messages = UtilMusig.individualColumn(csvSource, "messages");
        assert aggkeys.size() == coefAs.size();
        assert aggkeys.size() == signatures.size();
        assert messages.size() == signatures.size();
        List<byte[]> firstRoundData = new ArrayList<>();

        for (int i = 0; i < aggkeys.size(); i++) {
            byte[] apduBytes = aggkeys.get(i);
            apduBytes = UtilMusig.concatenate(apduBytes, coefAs.get(i));
            firstRoundData.add(apduBytes);
        }

        for (int i = 0; i < setUpTestData.size(); i++) {

            CommandAPDU cmdSetUp = new CommandAPDU(Constants.CLA_MUSIG2, Constants.INS_SETUP_TEST_DATA, 0, 0, setUpTestData.get(i));
            ResponseAPDU responseAPDUSetUp = connect().transmit(cmdSetUp);

            Assert.assertNotNull(responseAPDUSetUp);
            Assert.assertEquals(responseAPDUSetUp.getSW(), 0x9000);

            cmdSetUp = new CommandAPDU(Constants.CLA_MUSIG2, Constants.INS_SET_AGG_PUBKEY, 0, 0, firstRoundData.get(i));
            responseAPDUSetUp = connect().transmit(cmdSetUp);

            if (performanceTest) {
                filePerfOut.printf("%d,", statefulCard.getLastTransmitTime());
            }

            Assert.assertNotNull(responseAPDUSetUp);
            Assert.assertEquals(responseAPDUSetUp.getSW(), 0x9000);

            CommandAPDU cmd = new CommandAPDU(Constants.CLA_MUSIG2, Constants.INS_SIGN, 0, 0, messages.get(i));
            ResponseAPDU responseAPDU = connect().transmit(cmd);

            if (performanceTest) {
                Long transmitTime = statefulCard.getLastTransmitTime();
                filePerfOut.printf("%d\n", transmitTime);
            }

            Assert.assertNotNull(responseAPDU);

            if (fail) {
                if (i == 0) {
                    Assert.assertNotEquals(responseAPDU.getSW(), 0x9000);
                } else {
                    Assert.assertNotEquals(responseAPDU.getData(), signatures.get(i));
                }
            } else {
                Assert.assertEquals(responseAPDU.getSW(), 0x9000);
                Assert.assertEquals(responseAPDU.getData(), signatures.get(i));
            }

            reset();
        }

        filePerfOut.close();
    }
}
