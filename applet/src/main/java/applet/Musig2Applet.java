package applet;

import javacard.framework.*;
import applet.jcmathlib.*;
import applet.jcmathlib.SecP256k1;
import javacard.security.CryptoException;

public class Musig2Applet extends Applet implements AppletEvent {

    /**
     * Noncompliance with BIP0327:
     *  - Message length can be only up to 255 bytes instead of 2^61-1 bytes.
     *  - Tweaks are not supported.
     *  - If aggnonce is a point in infinity, the card throws an error. (Problem with JCMathLib)
     */

    // Utils
    private boolean initialized = false;
    private ResourceManager rm;

    // Crypto args
    private ECCurve curve;
    private Musig2 musig2;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Musig2Applet(bArray, bOffset, bLength);
    }

    public Musig2Applet(byte[] bArray, short bOffset, byte bLength) {
        OperationSupport.getInstance().setCard(Constants.CARD_TYPE);
        if(!OperationSupport.getInstance().DEFERRED_INITIALIZATION) {
            initialize();
        }
        register();
    }

    public void initialize() {
        if (initialized) {
            return;
        }

        try {
            rm = new ResourceManager(Constants.FULL_LEN);
            curve = new ECCurve(SecP256k1.p, SecP256k1.a, SecP256k1.b, SecP256k1.G, SecP256k1.r, rm);
            rm.fixModSqMod(curve.rBN);
            musig2 = new Musig2(curve, rm);

            initialized = true;
        // Error handling is taken from JCFROST
        } catch (ISOException e) {
            throw e; // Our exception from code, just re-emit
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt(Constants.SW_ArrayIndexOutOfBoundsException);
        } catch (ArithmeticException e) {
            ISOException.throwIt(Constants.SW_ArithmeticException);
        } catch (ArrayStoreException e) {
            ISOException.throwIt(Constants.SW_ArrayStoreException);
        } catch (NullPointerException e) {
            ISOException.throwIt(Constants.SW_NullPointerException);
        } catch (NegativeArraySizeException e) {
            ISOException.throwIt(Constants.SW_NegativeArraySizeException);
        } catch (CryptoException e) {
            ISOException.throwIt((short) (Constants.SW_CryptoException_prefix | e.getReason()));
        } catch (SystemException e) {
            ISOException.throwIt((short) (Constants.SW_SystemException_prefix | e.getReason()));
        } catch (PINException e) {
            ISOException.throwIt((short) (Constants.SW_PINException_prefix | e.getReason()));
        } catch (TransactionException e) {
            ISOException.throwIt((short) (Constants.SW_TransactionException_prefix | e.getReason()));
        } catch (CardRuntimeException e) {
            ISOException.throwIt((short) (Constants.SW_CardRuntimeException_prefix | e.getReason()));
        } catch (Exception e) {
            ISOException.throwIt(Constants.SW_Exception);
        }
    }

    public void generateKeys (APDU apdu) {
        musig2.individualPubkey(apdu.getBuffer(), ISO7816.OFFSET_CDATA);

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    private void nonceGen () {
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
        short inLen = (short) (apduBuffer[ISO7816.OFFSET_LC] & 0xFF);
        short outLen = musig2.sign(apduBuffer,
                ISO7816.OFFSET_CDATA,
                inLen,
                apduBuffer,
                ISO7816.OFFSET_CDATA);
        try {
            apdu.setOutgoing();
            apdu.setOutgoingLength(outLen);
            apdu.sendBytesLong(apduBuffer, ISO7816.OFFSET_CDATA, outLen);
        } catch (CryptoException e) {
            ISOException.throwIt(Constants.E_CRYPTO_EXCEPTION);
        } catch (APDUException e) {
            ISOException.throwIt(Constants.E_BUFFER_OVERLOW);
        }
    }

    private void reset(APDU apdu) {
        musig2.reset();
        apdu.setOutgoing();
    }

    private void setUpTestData(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short inOffset = ISO7816.OFFSET_CDATA;

        if (Constants.DEBUG == Constants.STATE_TRUE) {
            if (Constants.DEBUG != Constants.STATE_FALSE) {
                musig2.setTestingValues(apduBuffer, inOffset);
            } else {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
        }
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
                    nonceGen();
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
                    break;
                case Constants.INS_RESET:
                    reset(apdu);
                    break;
                case Constants.INS_SETUP_TEST_DATA:
                    setUpTestData(apdu);
                    break;
                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                    return;
            }
        // Error handling is taken from JCFROST
        } catch (ISOException e) {
            throw e; // Our exception from code, just re-emit
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt(Constants.SW_ArrayIndexOutOfBoundsException);
        } catch (ArithmeticException e) {
            ISOException.throwIt(Constants.SW_ArithmeticException);
        } catch (ArrayStoreException e) {
            ISOException.throwIt(Constants.SW_ArrayStoreException);
        } catch (NullPointerException e) {
            ISOException.throwIt(Constants.SW_NullPointerException);
        } catch (NegativeArraySizeException e) {
            ISOException.throwIt(Constants.SW_NegativeArraySizeException);
        } catch (CryptoException e) {
            ISOException.throwIt((short) (Constants.SW_CryptoException_prefix | e.getReason()));
        } catch (SystemException e) {
            ISOException.throwIt((short) (Constants.SW_SystemException_prefix | e.getReason()));
        } catch (PINException e) {
            ISOException.throwIt((short) (Constants.SW_PINException_prefix | e.getReason()));
        } catch (TransactionException e) {
            ISOException.throwIt((short) (Constants.SW_TransactionException_prefix | e.getReason()));
        } catch (CardRuntimeException e) {
            ISOException.throwIt((short) (Constants.SW_CardRuntimeException_prefix | e.getReason()));
        } catch (Exception e) {
            ISOException.throwIt(Constants.SW_Exception);
        }
    }

    @Override
    public void uninstall() {
        musig2.dereference();
        musig2 = null;
        initialized = false;
        curve = null;
        rm = null;
    }
}
