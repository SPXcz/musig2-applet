package applet;

import javacard.framework.*;
import javacard.security.RandomData;
import javacard.security.MessageDigest;
import applet.jcmathlib.*;

public class Musig2 {

    // Helper
    private MessageDigest digest;
    private RandomData rng;

    // Data storage
    private byte[] digestHelper;
    private byte[] rngArray;
    private ECPoint tmpPoint;

    // States
    private byte stateReadyForSigning;
    private byte stateCurrentSigComplete;
    private byte stateKeysEstablished;

    // Crypto arguments
    private ECCurve curve;
    private ECPoint publicShare;
    private ECPoint groupPubKey;
    private ECPoint[] nonceOut;
    private ECPoint[] nonceAggregate;
    private BigNat secretShare;
    private BigNat coefA;
    private BigNat[] nonceState;
    private short numberOfParticipants;

    // Test values
    final static byte[] ECPOINT_TEST_VALUE = {
            (byte) 0x04,
            (byte) 0x3b, (byte) 0xc1, (byte) 0x5b, (byte) 0xe5,
            (byte) 0xf7, (byte) 0x52, (byte) 0xb3, (byte) 0x27,
            (byte) 0x0d, (byte) 0xb0, (byte) 0xae, (byte) 0xf2,
            (byte) 0xbc, (byte) 0xf0, (byte) 0xec, (byte) 0xbd,
            (byte) 0xb5, (byte) 0x78, (byte) 0x8f, (byte) 0x88,
            (byte) 0xe6, (byte) 0x14, (byte) 0x32, (byte) 0x30,
            (byte) 0x68, (byte) 0xc4, (byte) 0xc4, (byte) 0x88,
            (byte) 0x6b, (byte) 0x43, (byte) 0x91, (byte) 0x4c,
            (byte) 0x22, (byte) 0xe1, (byte) 0x67, (byte) 0x68,
            (byte) 0x3b, (byte) 0x32, (byte) 0x95, (byte) 0x98,
            (byte) 0x31, (byte) 0x19, (byte) 0x6d, (byte) 0x41,
            (byte) 0x88, (byte) 0x0c, (byte) 0x9f, (byte) 0x8c,
            (byte) 0x59, (byte) 0x67, (byte) 0x60, (byte) 0x86,
            (byte) 0x1a, (byte) 0x86, (byte) 0xf8, (byte) 0x0d,
            (byte) 0x01, (byte) 0x46, (byte) 0x0c, (byte) 0xb5,
            (byte) 0x8d, (byte) 0x86, (byte) 0x6c, (byte) 0x09
    };
    final static byte[] SCALAR_TEST_VALUE = {
            (byte) 0xe8, (byte) 0x05, (byte) 0xe8, (byte) 0x02,
            (byte) 0xbf, (byte) 0xec, (byte) 0xee, (byte) 0x91,
            (byte) 0x9b, (byte) 0x3d, (byte) 0x3b, (byte) 0xd8,
            (byte) 0x3c, (byte) 0x7b, (byte) 0x52, (byte) 0xa5,
            (byte) 0xd5, (byte) 0x35, (byte) 0x4c, (byte) 0x4c,
            (byte) 0x06, (byte) 0x89, (byte) 0x80, (byte) 0x54,
            (byte) 0xb9, (byte) 0x76, (byte) 0xfa, (byte) 0xb1,
            (byte) 0xd3, (byte) 0x5a, (byte) 0x10, (byte) 0x91
    };

    public Musig2(ECCurve curve, ResourceManager rm) {

        // Helper objects
        digestHelper = JCSystem.makeTransientByteArray(Constants.HASH_LEN, JCSystem.CLEAR_ON_DESELECT);
        digest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        rng = RandomData.getInstance(RandomData.ALG_KEYGENERATION);

        // Helper attributes
        coefA = new BigNat(Constants.HASH_LEN, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, rm);
        rngArray = JCSystem.makeTransientByteArray(Constants.SHARE_LEN, JCSystem.CLEAR_ON_DESELECT);
        tmpPoint = new ECPoint(curve);
        stateReadyForSigning = Constants.STATE_FALSE;
        stateCurrentSigComplete = Constants.STATE_FALSE; // Controls whether the signature sequence has been completed.

        // Main Attributes
        this.curve = curve;
        groupPubKey = new ECPoint(curve);
        publicShare = new ECPoint(curve);
        secretShare = new BigNat(Constants.SHARE_LEN, JCSystem.MEMORY_TYPE_PERSISTENT, rm); // Effective private key
        nonceOut = new ECPoint[Constants.V];
        nonceState = new BigNat[Constants.V];
        nonceAggregate = new ECPoint[Constants.V];

        for (short i = (short) 0; i < Constants.V; i++) {
            nonceOut[i] = new ECPoint(curve);
            nonceAggregate[i] = new ECPoint(curve);
            nonceState[i] = new BigNat(Constants.SHARE_LEN, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        }
    }

    public void generateKeySharePair() {
        if (curve == null
                || publicShare == null
                || secretShare == null
                || rngArray == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }

        // Generate private key share
        getRandomBigNat(secretShare);

        // Generate public key share
        publicShare.setW(curve.G, (short) 0, (short) curve.G.length);
        publicShare.multiplication(secretShare);
    }

    // Only max. 32B (or the length of a secret key share)
    private void getRandomBigNat (BigNat outBigNat) {
        rng.nextBytes(rngArray, (short) 0, Constants.SHARE_LEN);
        outBigNat.fromByteArray(rngArray, (short) 0, Constants.SHARE_LEN);
    }

    // Can be done off card
    public void combinePubKeyShares (byte[] publicShareList, short offset, short numberOfParticipants) {

        if (numberOfParticipants == 0) {
            ISOException.throwIt(Constants.E_TOO_FEW_PARTICIPANTS);
        }

        if (numberOfParticipants > Constants.MAX_PARTICIPATS) {
            ISOException.throwIt(Constants.E_TOO_MANY_PARTICIPANTS);
        }

        if ((short)(offset + numberOfParticipants * Constants.POINT_LEN) > (short) publicShareList.length) {
            ISOException.throwIt(Constants.E_BUFFER_OVERLOW);
        }

        this.numberOfParticipants = numberOfParticipants;
        short pubKeyShareOffset = offset;

        // Init first point in the sum
        aggregatedCoefs(publicShareList, pubKeyShareOffset, digestHelper);
        coefA.fromByteArray(digestHelper, (short) 0, (short) digestHelper.length);
        groupPubKey.setW(publicShareList, pubKeyShareOffset, Constants.POINT_LEN);
        groupPubKey.multiplication(coefA);

        // Sum up the rest of the key shares
        for (short i = 1; i < numberOfParticipants; i++) {
            pubKeyShareOffset += Constants.POINT_LEN;
            aggregatedCoefs(publicShareList, pubKeyShareOffset, digestHelper);
            coefA.fromByteArray(digestHelper, (short) 0, (short) digestHelper.length);
            tmpPoint.setW(publicShareList, pubKeyShareOffset, Constants.POINT_LEN);
            groupPubKey.multAndAdd(coefA, tmpPoint);
        }

        stateKeysEstablished = Constants.STATE_TRUE;
    }

    private void aggregatedCoefs(byte[] publicShareList, short currentPubShareOffset, byte[] hashOutput) {
        digest.update(publicShareList, (short) 0, (short) publicShareList.length);
        digest.doFinal(publicShareList, currentPubShareOffset, Constants.SHARE_LEN, hashOutput, (short) 0);
        digest.reset();
    }

    // Single signature only
    // Nonce cant be reused
    public void generateNonces () {

        if (Constants.V != 2 && Constants.V != 4) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        for (short i = 0; i < Constants.V; i++) {
            getRandomBigNat(nonceState[i]);
            nonceOut[i].setW(curve.G, (short) 0, (short) curve.G.length);
            nonceOut[i].multiplication(nonceState[i]);
        }

        //TODO: Udelat state machine
        stateReadyForSigning = Constants.STATE_TRUE;
        stateCurrentSigComplete = Constants.STATE_TRUE;

    }

    // Can be done off card
    public void aggregateNonces (byte[] buffer, short offset) {

        if (stateReadyForSigning == Constants.STATE_FALSE || stateKeysEstablished == Constants.STATE_FALSE) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        short allNoncesLength = (short) (numberOfParticipants * Constants.POINT_LEN * Constants.V);

        if ((short)(buffer.length + offset) > allNoncesLength) {
            ISOException.throwIt(Constants.E_BUFFER_OVERLOW);
            return;
        }

        short currentOffset = offset;

        // Init points
        for (short j = 0; j < Constants.V; j++) {
            nonceAggregate[j].setW(buffer, currentOffset, Constants.POINT_LEN);
            currentOffset += Constants.POINT_LEN;
        }

        // Add the rest of the points
        for (short i = (short) 1; i < numberOfParticipants; i++) {
            for (short k = (short) 0; k < Constants.V; k++) {

                // Just to be sure. Should be redundant.
                if ((short) (currentOffset + Constants.POINT_LEN) > (short) buffer.length) {
                    ISOException.throwIt(Constants.E_BUFFER_OVERLOW);
                }

                tmpPoint.setW(buffer, currentOffset, Constants.POINT_LEN);
                nonceAggregate[k].add(tmpPoint);
                currentOffset += Constants.POINT_LEN;
            }
        }
    }

    public void getPublicKeyShare(byte[] buffer, short offset) {
        if ((short)(offset + Constants.POINT_LEN) > (short) buffer.length) {
            ISOException.throwIt(Constants.E_BUFFER_OVERLOW);
        }

        publicShare.getW(buffer, offset);
    }

    //In format v1, v2, v3, v4, ...
    public void getPublicNonceShare (byte[] buffer, short offset) {

        // Is nonce generated?
        if (stateReadyForSigning == Constants.STATE_FALSE) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if ((short)(offset + Constants.POINT_LEN * Constants.V) > (short) buffer.length) {
            ISOException.throwIt(Constants.E_BUFFER_OVERLOW);
        }

        short currentOffset = offset;

        for (short i = (short) 0; i < Constants.V; i++) {
            nonceOut[i].getW(buffer, currentOffset);
            currentOffset += Constants.POINT_LEN;
        }
    }
}
