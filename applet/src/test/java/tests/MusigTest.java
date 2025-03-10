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

            ResponseAPDU signResponse;

            sendCorrectApdu(Constants.INS_SETUP_TEST_DATA, setUpTestData.get(i));
            sendCorrectApdu(Constants.INS_SET_AGG_PUBKEY, firstRoundData.get(i));

            if (fail) {
                if (i == 0) {
                    signResponse = sendMusigApdu(Constants.INS_SIGN, messages.get(i));
                    Assert.assertNotEquals(signResponse.getSW(), 0x9000);
                } else {
                    signResponse = sendMusigApdu(Constants.INS_SIGN, messages.get(i));
                    Assert.assertEquals(signResponse.getSW(), 0x9000);
                    Assert.assertNotEquals(signResponse.getData(), signatures.get(i));
                }
            } else {
                signResponse = sendCorrectApdu(Constants.INS_SIGN, messages.get(i));
                Assert.assertEquals(signResponse.getData(), signatures.get(i));
            }

            if (performanceTest) {
                Long transmitTime = statefulCard.getLastTransmitTime();
                filePerfOut.printf("%d%n", transmitTime);
            }

            reset();
        }

        filePerfOut.close();
    }

    protected ResponseAPDU sendCorrectApdu (byte ins, byte[] payload) throws Exception {
        ResponseAPDU responseAPDU = sendMusigApdu(ins, payload);
        Assert.assertEquals(responseAPDU.getSW(), 0x9000);

        return responseAPDU;
    }

    protected ResponseAPDU sendMusigApdu (byte ins, byte[] payload) throws Exception {

        CommandAPDU cmdSetUp;

        if (payload == null) {
            cmdSetUp = new CommandAPDU(Constants.CLA_MUSIG2, ins, 0, 0);
        } else {
            cmdSetUp = new CommandAPDU(Constants.CLA_MUSIG2, ins, 0, 0, payload);
        }

        ResponseAPDU responseAPDU = connect().transmit(cmdSetUp);

        Assert.assertNotNull(responseAPDU);

        return responseAPDU;
    }
}
