package applet;

import javacard.framework.*;
import javacard.security.RandomData;
import javacard.security.MessageDigest;
import applet.jcmathlib.*;
import org.omg.CORBA.PRIVATE_MEMBER;

public class Musig2 {

    // Helper
    private MessageDigest digest;
    private RandomData rng;

    // Data storage
    private byte[] digestHelper;
    private byte[] tmpArray;
    private ECPoint tmpPoint;
    private BigNat tmpBigNat;

    // States
    private byte stateReadyForSigning;
    private byte stateKeysEstablished;
    private byte stateNoncesAggregated;

    // Crypto arguments
    // Argument names refer to the names of arguments in the founding MuSig 2 paper (p. 15)
    // https://eprint.iacr.org/2020/1261.pdf
    private ECCurve curve;
    private ECPoint publicShare;
    private ECPoint groupPubKey;
    private ECPoint coefR; // Temporary attribute (clear after sig complete)
    private ECPoint[] nonceOut;
    private ECPoint[] nonceAggregate;
    private BigNat secretShare;
    private BigNat coefA;
    private BigNat coefB; // Temporary attribute
    private BigNat coefC; // Temporary attribute
    private BigNat partialSig;
    private BigNat modulo; // TODO: Je rBN spravny atribut?
    private BigNat[] nonceState;
    private short numberOfParticipants;

    public Musig2(ECCurve curve, ResourceManager rm) {

        // Helper objects
        digestHelper = JCSystem.makeTransientByteArray(Constants.HASH_LEN, JCSystem.CLEAR_ON_DESELECT);
        digest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        rng = RandomData.getInstance(RandomData.ALG_KEYGENERATION);

        // Helper attributes
        tmpArray = JCSystem.makeTransientByteArray(Constants.POINT_LEN, JCSystem.CLEAR_ON_DESELECT);
        tmpPoint = new ECPoint(curve);
        stateReadyForSigning = Constants.STATE_FALSE;
        stateNoncesAggregated = Constants.STATE_FALSE;

        // Main Attributes
        this.curve = curve;
        modulo = this.curve.rBN;
        groupPubKey = new ECPoint(curve);
        publicShare = new ECPoint(curve);
        coefR = new ECPoint(curve);
        secretShare = new BigNat(Constants.SHARE_LEN, JCSystem.MEMORY_TYPE_PERSISTENT, rm); // Effective private key
        coefA = new BigNat(Constants.HASH_LEN, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        coefB = new BigNat(Constants.HASH_LEN, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, rm);
        coefC = new BigNat(Constants.HASH_LEN, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, rm);
        partialSig = new BigNat(modulo.length(), JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        tmpBigNat = new BigNat(modulo.length(), JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, rm);
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
                || tmpArray == null) {
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
        rng.nextBytes(tmpArray, (short) 0, Constants.SHARE_LEN);
        outBigNat.fromByteArray(tmpArray, (short) 0, Constants.SHARE_LEN);
    }

    // Can be done off card
    // The last public share is the share of this card. Should be done correctly in the integrated version.
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
        // In this version of the card (with all operations on the card), the last coefA attribute
        // is considered the coefA attribute of this card. This will not be the case in the integrated version.
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

        stateNoncesAggregated = Constants.STATE_TRUE;
    }

    public short sign (byte[] messageBuffer,
                      short inOffset,
                      short inLength,
                      byte[] outBuffer,
                      short outOffset) {

        if (stateReadyForSigning == Constants.STATE_FALSE) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (inLength > Constants.MAX_MESSAGE_LEN) {
            ISOException.throwIt(Constants.E_MESSAGE_TOO_LONG);
            return (short) -1;
        }

        if ((short) (inOffset + inLength) > (short) messageBuffer.length) {
            ISOException.throwIt(Constants.E_BUFFER_OVERLOW);
            return (short) -1;
        }

        if ((short) (outOffset + Constants.POINT_LEN + Constants.SHARE_LEN) > (short) outBuffer.length) {
            ISOException.throwIt(Constants.E_BUFFER_OVERLOW);
            return (short) -1;
        }

        generateCoefB(messageBuffer, inOffset, inLength);
        generateCoefR();
        generateCoefC(messageBuffer, inOffset, inLength);
        signPartially(messageBuffer, inOffset, inLength);

        writePartialSignatureOut(outBuffer, outOffset);

        stateReadyForSigning = Constants.STATE_FALSE;

        return (short) (Constants.POINT_LEN + Constants.SHARE_LEN);
    }

    private void generateCoefB (byte[] messageBuffer, short offset, short length) {

        if (stateNoncesAggregated == Constants.STATE_FALSE || stateKeysEstablished == Constants.STATE_FALSE) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }

        // Hash public key
        digestPoint(groupPubKey);

        // Hash public aggregated nonces
        for (short i = 0; i < Constants.V; i++) {
            digestPoint(nonceAggregate[i]);
        }

        // Hash the message to be signed
        digest.doFinal(messageBuffer, offset, length, tmpArray, (short) 0);
        coefB.fromByteArray(tmpArray, (short) 0, Constants.HASH_LEN);
        digest.reset();
    }

    private void generateCoefR () {

        if (stateNoncesAggregated == Constants.STATE_FALSE) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }

        // Initalize R using R1
        coefR.copy(nonceAggregate[0]);

        // Optimized operation for V = 2
        coefR.multAndAdd(coefB, nonceAggregate[1]);

        // Only for V = 4
        //TODO: Do for V = 4
        for (short i = 2; i < Constants.V; i++) {
            //2*b*R
            //3*b*R
        }
    }

    // Similar to generateCoefB
    private void generateCoefC (byte[] messageBuffer, short offset, short length) {

        if (stateNoncesAggregated == Constants.STATE_FALSE || stateKeysEstablished == Constants.STATE_FALSE) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }

        // Hash public key
        digestPoint(groupPubKey);

        // Hash temporary R attribute
        digestPoint(coefR);

        // Hash the message
        digest.doFinal(messageBuffer, offset, length, tmpArray, (short) 0);
        coefC.fromByteArray(tmpArray, (short) 0, Constants.HASH_LEN);
        digest.reset();
    }

    // Creates the partial signature itself
    // Currently only for V = 2
    private void signPartially (byte[] messageBuffer, short offset, short length) {
        partialSig.copy(coefC);
        partialSig.modMult(coefA, modulo); // TODO: Je modulo fixovane, kdyz jsem pouzil  rm.fixModSqMod(curve.rBN)?
        partialSig.modMult(secretShare, modulo);
        partialSig.modAdd(nonceState[0], modulo);

        tmpBigNat.copy(coefB);
        tmpBigNat.modMult(nonceState[1], modulo);

        partialSig.modAdd(tmpBigNat, modulo);
    }

    // Format: R + s
    private void writePartialSignatureOut (byte[] outbuffer, short offset) {
        coefR.getW(outbuffer, offset);
        partialSig.copyToByteArray(outbuffer, (short) (offset + Constants.POINT_LEN));
    }

    private void digestPoint (ECPoint point) {
        point.getW(tmpArray, (short) 0);
        digest.update(tmpArray, (short) 0, Constants.POINT_LEN);
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
