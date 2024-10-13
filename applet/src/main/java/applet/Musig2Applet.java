package applet;

import javacard.framework.*;
import applet.jcmathlib.*;
import applet.jcmathlib.SecP256k1;
import javacard.security.CryptoException;

public class Musig2Applet extends Applet {

    public final static short CARD_TYPE = OperationSupport.SIMULATOR;

    // Utils
    private boolean initialized = false;
    private ResourceManager rm;
    private byte[] publicShareList;

    // Crypto args
    private ECCurve curve;
    private Musig2 musig2;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Musig2Applet(bArray, bOffset, bLength);
    }

    public Musig2Applet(byte[] bArray, short bOffset, byte bLength) {
        OperationSupport.getInstance().setCard(CARD_TYPE);
        if(!OperationSupport.getInstance().DEFERRED_INITIALIZATION) {
            initialize();
        }
        register();
    }

    public void initialize() {
        if (initialized) {
            return;
        }

        // Helper attributes
        rm = new ResourceManager(Constants.FULL_LEN);
        curve = new ECCurve(SecP256k1.p, SecP256k1.a, SecP256k1.b, SecP256k1.G, SecP256k1.r, rm);
        musig2 = new Musig2(curve, rm);

        initialized = true;
    }

    public void generateKeys (APDU apdu) {
        musig2.individualPubkey(apdu.getBuffer(), ISO7816.OFFSET_CDATA);

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    private void nonceGen (APDU apdu) {

        byte[] apduBuffer = apdu.getBuffer();

        if (Constants.DEBUG == Constants.STATE_TRUE) {
            musig2.setTestingValues(apduBuffer, ISO7816.OFFSET_CDATA);
        }

        musig2.nonceGen();
    }

    private void getXonlyPubkey (APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        musig2.getXonlyPubKey(apduBuffer, ISO7816.OFFSET_CDATA);

        apdu.setOutgoing();
        apdu.setOutgoingLength((short) (Constants.XCORD_LEN - 1));
        apdu.sendBytesLong(apduBuffer, ISO7816.OFFSET_CDATA, (short) (Constants.XCORD_LEN - 1));
    }

    private void getPlainPubkey (APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        musig2.getPlainPubKey(apduBuffer, ISO7816.OFFSET_CDATA);

        apdu.setOutgoing();
        apdu.setOutgoingLength(Constants.XCORD_LEN);
        apdu.sendBytesLong(apduBuffer, ISO7816.OFFSET_CDATA, Constants.XCORD_LEN);
    }

    private void getPublicNonceShare (APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        musig2.getPublicNonceShare(apduBuffer, ISO7816.OFFSET_CDATA);

        apdu.setOutgoing();
        apdu.setOutgoingLength((short) (Constants.POINT_LEN * Constants.V));
        apdu.sendBytesLong(apduBuffer, ISO7816.OFFSET_CDATA, (short) (Constants.XCORD_LEN * Constants.V));
    }

    private void setAggPubKey (APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        musig2.setGroupPubKey(apduBuffer, ISO7816.OFFSET_CDATA);
    }

    private void setPublicNonce (APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        musig2.setNonceAggregate(apduBuffer, ISO7816.OFFSET_CDATA);
    }

    private void sign (APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short outLen = musig2.sign(apduBuffer,
                ISO7816.OFFSET_CDATA,
                apdu.getIncomingLength(),
                apduBuffer,
                ISO7816.OFFSET_CDATA);

        apdu.setOutgoing();
        apdu.setOutgoingLength(outLen);
    }

    public boolean select() {
        if(initialized) {
            curve.updateAfterReset();
        }
        return true;
    }

    @Override
    public void process(APDU apdu) throws ISOException {
        if (selectingApplet()) {
            return;
        }

        if (!initialized) {
            initialize();
        }

        if (apdu.getBuffer()[ISO7816.OFFSET_CLA] != Constants.CLA_MUSIG2) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
            return;
        }

        try {
            switch (apdu.getBuffer()[ISO7816.OFFSET_INS]) {
                case Constants.INS_GENERATE_KEYS:
                    generateKeys(apdu);
                    break;
                case Constants.INS_GENERATE_NONCES:
                    nonceGen(apdu);
                    break;
                case Constants.INS_SIGN:
                    sign(apdu);
                    break;
                case Constants.INS_GET_XONLY_PUBKEY:
                    getXonlyPubkey(apdu);
                    break;
                case Constants.INS_GET_PLAIN_PUBKEY:
                    getPlainPubkey(apdu);
                    break;
                case Constants.INS_GET_PNONCE_SHARE:
                    getPublicNonceShare(apdu);
                    break;
                case Constants.INS_SET_AGG_PUBKEY:
                    setAggPubKey(apdu);
                    break;
                case Constants.INS_SET_AGG_NONCES:
                    setPublicNonce(apdu);
                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                    return;
            }
        } catch (CryptoException e) {
            ISOException.throwIt(Constants.E_CRYPTO_EXCEPTION);
        }

    }
}
