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
    private Musig2[] otherCards;

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
        rm.fixModSqMod(curve.rBN);
        musig2 = new Musig2(curve, rm);
        //publicShareList = JCSystem.makeTransientByteArray(Constants.MAX_PSHARE_LIST_LEN, JCSystem.CLEAR_ON_DESELECT);

        // Only for testing purposes
        otherCards = new Musig2[Constants.MAX_PARTICIPATS - 1];

        initialized = true;
    }

    public void generateKeys () {
        musig2.generateKeySharePair();
        //for (short i = 0; i < Constants.MAX_PARTICIPATS - 1; i++) {
        //    otherCards[i].generateKeySharePair();
        //}

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    private void combineKeyShares(APDU apdu) {
        //Tady bych normalne vzal ty shares z APDU
        //TODO: Nejak pridat kartam ID, aby byl vysledek hashovani konzistentni.
        // Nebo je jen nejak deterministicky seradit na klientovi.

        //musig2.combinePubKeyShares(apdu.getBuffer(), some offset here, some other offset here);

        // Only for testing
        short offset = (short) 0;
        for (short i = 0; i < Constants.MAX_PARTICIPATS - 1; i++) {
            otherCards[i].getPublicKeyShare(publicShareList, offset);
            offset += Constants.POINT_LEN;
        }

        musig2.getPublicKeyShare(publicShareList, offset);

        // Should be in production
        musig2.combinePubKeyShares(publicShareList, (short) 0, Constants.MAX_PARTICIPATS);
    }

    private void generateNonces() {
        // For testing only
        for (short i = (short) 0; i < (short) (Constants.MAX_PARTICIPATS - 1); i++) {
            otherCards[i].generateNonces();
        }

        musig2.generateNonces();
    }

    private void combineNonces (APDU apdu) {
        // Only for testing
        short offset = (short) 0;
        for (short i = (short) 0; i < (short) (Constants.MAX_PARTICIPATS - 1); i++) {
            otherCards[i].getPublicNonceShare(publicShareList, offset);
            offset += Constants.POINT_LEN;
        }

        musig2.getPublicNonceShare(publicShareList, offset);

        // Should be in prod
        musig2.aggregateNonces(publicShareList, (short) 0);
    }

    private void getPublicKeyShare (APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        musig2.getPublicKeyShare(apduBuffer, ISO7816.OFFSET_CDATA);

        apdu.setOutgoing();
        apdu.setOutgoingLength(Constants.POINT_LEN);
    }

    private void getPublicNonceShare (APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        musig2.getPublicNonceShare(apduBuffer, ISO7816.OFFSET_CDATA);

        apdu.setOutgoing();
        apdu.setOutgoingLength((short) (Constants.POINT_LEN * Constants.V));
    }

    private void sign(APDU apdu) {
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
                    generateKeys();
                    break;
                case Constants.INS_COMBINE_SHARES:
                    combineKeyShares(apdu);
                    break;
                case Constants.INS_GENERATE_NONCES:
                    generateNonces();
                    break;
                case Constants.INS_COMBINE_NONCES:
                    combineNonces(apdu);
                    break;
                case Constants.INS_GET_PKEY_SHARE:
                    getPublicKeyShare(apdu);
                    break;
                case Constants.INS_GET_PNONCE_SHARE:
                    getPublicNonceShare(apdu);
                    break;
                case Constants.INS_SIGN:
                    sign(apdu);
                    break;
                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                    return;
            }
        } catch (CryptoException e) {
            ISOException.throwIt(Constants.E_CRYPTO_EXCEPTION);
        }

    }
}
