package applet;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
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
        rng.nextBytes(rngArray, (short) 0, (short) rngArray.length);
        outBigNat.fromByteArray(rngArray, (short) 0, (short) rngArray.length);

        // Erase generated private key share from the array for security
        Util.arrayFill(rngArray, (short) 0, (short) rngArray.length, (byte) 0x00);
    }

    // Can be done off card
    public void combinePubKeyShares (byte[] publicShareList, short offset, short numberOfParticipants) {

        if (numberOfParticipants == 0) {
            ISOException.throwIt(Constants.E_TOO_FEW_PARTICIPANTS);
        }

        if (numberOfParticipants > Constants.MAX_PARTICIPATS) {
            ISOException.throwIt(Constants.E_TOO_MANY_PARTICIPANTS);
        }

        if (offset + numberOfParticipants * Constants.POINT_LEN > publicShareList.length) {
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
