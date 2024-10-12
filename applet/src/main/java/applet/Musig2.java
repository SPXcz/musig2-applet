package applet;

import javacard.framework.*;
import javacard.security.RandomData;
import applet.jcmathlib.*;

public class Musig2 {

    // Helper
    private HashCustom digest;
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
    private ECPoint[] pubNonce;
    private ECPoint[] nonceAggregate;
    private BigNat secretShare;
    private BigNat coefA;
    private BigNat coefB; // Temporary attribute
    private BigNat coefG;
    private BigNat challangeE;
    private BigNat tacc; // BIP0327 coeficient
    private BigNat gacc; // BIP0327 coeficient
    private BigNat partialSig;
    private BigNat modulo; // TODO: Je rBN spravny atribut?
    private BigNat[] secNonce;
    private short numberOfParticipants;

    public Musig2(ECCurve curve, ResourceManager rm) {

        // Helper objects
        digestHelper = JCSystem.makeTransientByteArray(Constants.HASH_LEN, JCSystem.CLEAR_ON_DESELECT);
        digest = new HashCustom();
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
        coefG = new BigNat(modulo.length(), JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        challangeE = new BigNat(modulo.length(), JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, rm);
        partialSig = new BigNat(modulo.length(), JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        tmpBigNat = new BigNat(modulo.length(), JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, rm);
        tacc = new BigNat(modulo.length(), JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        gacc = new BigNat(modulo.length(), JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        pubNonce = new ECPoint[Constants.V];
        secNonce = new BigNat[Constants.V];
        nonceAggregate = new ECPoint[Constants.V];

        for (short i = (short) 0; i < Constants.V; i++) {
            pubNonce[i] = new ECPoint(curve);
            nonceAggregate[i] = new ECPoint(curve);
            secNonce[i] = new BigNat(Constants.SHARE_LEN, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        }
    }

    // Key generation
    public void individualPubkey() {
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

        // Needed for BIP implementation. In the implementation this is done each time a signature is generated.
        coefG.copy(modulo);

        if (publicShare.isYEven()) {
            coefG.increment();
        } else {
            coefG.decrement();
        }
    }

    // Only max. 32B (or the length of a secret key share)
    private void getRandomBigNat (BigNat outBigNat) {
        rng.nextBytes(tmpArray, (short) 0, Constants.SHARE_LEN);
        outBigNat.fromByteArray(tmpArray, (short) 0, Constants.SHARE_LEN);
    }

    // Single signature only
    // Nonce cant be reused
    public void nonceGen () {

        if (Constants.V != 2 && Constants.V != 4) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        for (short i = 0; i < Constants.V; i++) {
            generateSecNonce(secNonce[i], i);
            pubNonce[i].setW(curve.G, (short) 0, (short) curve.G.length);
            pubNonce[i].multiplication(secNonce[i]);
        }

        //TODO: Udelat state machine
        stateReadyForSigning = Constants.STATE_TRUE;

    }

    private void generateSecNonce (BigNat secNonce, short kIndex) {

        BigNat rand = tmpBigNat;

        // Digest randomly generated data
        getRandomBigNat(rand);
        rand.copyToByteArray(digestHelper, (short) 0);
        digest.init(HashCustom.MUSIG_NONCE);
        digest.update(digestHelper, (short) 0, Constants.SHARE_LEN);

        // Digest public key share of the card
        tmpArray[0] = Constants.XCORD_LEN;
        publicShare.decode(tmpArray, (short) 1, Constants.XCORD_LEN);
        digest.update(tmpArray, (short) 0, (short) (Constants.XCORD_LEN + 1));

        // Digest group public key if it is already established
        if (stateKeysEstablished == Constants.STATE_TRUE) {
            tmpArray[0] = Constants.XCORD_LEN;
            groupPubKey.decode(tmpArray, (short) 1, Constants.XCORD_LEN);
            digest.update(tmpArray, (short) 0, (short) (Constants.XCORD_LEN + 1));
        } else {
            tmpArray[0] = (byte) 0x00;
            digest.update(tmpArray, (short) 0, (short) 1);
        }

        // Add rest of the arguments (most are currently not defined)
        tmpArray[0] = (byte) 0x00; // m_prefixed
        tmpArray[1] = (byte) 0x00; // 1-4 are length of extra_in
        tmpArray[2] = (byte) 0x00;
        tmpArray[3] = (byte) 0x00;
        tmpArray[4] = (byte) 0x00;
        tmpArray[5] = (byte) kIndex; // Index of the secret nonce. Either 0 or 1

        digest.doFinal(tmpArray,
                (short) 0x00,
                (short) 6,
                digestHelper,
                (short) 0);

        secNonce.fromByteArray(digestHelper, (short) 0, Constants.HASH_LEN);
        secNonce.mod(modulo);
    }

    public short sign (byte[] messageBuffer,
                      short inOffset,
                      short inLength,
                      byte[] outBuffer,
                      short outOffset) {

        if (stateReadyForSigning == Constants.STATE_FALSE) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (stateNoncesAggregated == Constants.STATE_FALSE) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // TODO: Jak resit maximalni delku zpravy? (limitace JavaCard)
        if (inLength > Constants.MAX_MESSAGE_LEN) {
            ISOException.throwIt(Constants.E_MESSAGE_TOO_LONG);
            return (short) -1;
        }

        if ((short) (inOffset + inLength) > (short) messageBuffer.length) {
            ISOException.throwIt(Constants.E_BUFFER_OVERLOW);
            return (short) -1;
        }

        if ((short) (outOffset + Constants.XCORD_LEN + Constants.SHARE_LEN) > (short) outBuffer.length) {
            ISOException.throwIt(Constants.E_BUFFER_OVERLOW);
            return (short) -1;
        }

        generateCoefB(messageBuffer, inOffset, inLength);
        generateCoefR();
        generateChallengeE(messageBuffer, inOffset, inLength);
        signPartially();

        writePartialSignatureOut(outBuffer, outOffset);

        eraseNonce();

        stateReadyForSigning = Constants.STATE_FALSE;

        return modulo.length();
    }

    private void generateCoefB (byte[] messageBuffer, short offset, short length) {

        if (stateNoncesAggregated == Constants.STATE_FALSE || stateKeysEstablished == Constants.STATE_FALSE) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }

        digest.init(HashCustom.MUSIG_NONCECOEF);

        // Hash public aggregated nonces
        for (short i = 0; i < Constants.V; i++) {
            digestPoint(nonceAggregate[i], true);
        }

        // Hash public key
        // Must be encoded using xbytes
        digestPoint(groupPubKey, false);

        // Hash the message to be signed
        digest.doFinal(messageBuffer, offset, length, tmpArray, (short) 0);
        coefB.fromByteArray(tmpArray, (short) 0, Constants.HASH_LEN);
        coefB.mod(modulo);
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
    }

    private void generateChallengeE (byte[] messageBuffer, short offset, short length) {

        if (stateNoncesAggregated == Constants.STATE_FALSE || stateKeysEstablished == Constants.STATE_FALSE) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }

        digest.init(HashCustom.BIP_CHALLENGE);

        digestPoint(coefR, false);
        digestPoint(publicShare, false);

        digest.doFinal(messageBuffer, offset, length, tmpArray, (short) 0);
        challangeE.fromByteArray(tmpArray, (short) 0, Constants.HASH_LEN);
        challangeE.mod(modulo);
    }

    // Creates the partial signature itself
    // Currently only for V = 2
    private void signPartially () {

        // TODO: Asi jde optimalizovat
        if (!coefR.isYEven()) {
            for (short i = 0; i < Constants.V; i++) {
                tmpBigNat.copy(modulo);
                tmpBigNat.subtract(secNonce[i]);
                secNonce[i].copy(tmpBigNat);
            }
        }

        partialSig.copy(challangeE);
        partialSig.modMult(coefA, modulo);
        partialSig.modMult(coefG, modulo);
        partialSig.modMult(gacc, modulo);
        partialSig.modMult(secretShare, modulo);
        partialSig.modAdd(secNonce[0], modulo);

        tmpBigNat.copy(coefB);
        tmpBigNat.modMult(secNonce[1], modulo);

        partialSig.modAdd(tmpBigNat, modulo);

        // TODO: Implementovat partialSigVerify na kleintovi
    }

    // Format: psig
    private void writePartialSignatureOut (byte[] outbuffer, short offset) {

        if ((short) (offset + Constants.SHARE_LEN) > (short) outbuffer.length) {
            ISOException.throwIt(Constants.E_BUFFER_OVERLOW);
        }

        partialSig.copyToByteArray(outbuffer, offset);
    }

    private void digestPoint (ECPoint point, boolean cbytes) {

        short length;

        if (cbytes) {
            point.encode(tmpArray, (short) 0, true);  //TODO: True nebo false?
            length = (short) 33;
        } else {
            point.getX(tmpArray, (short) 0);
            length = (short) 32;
        }

        digest.update(tmpArray, (short) 0, length);
    }

    // Nonce must be erased after signing, otherwise the private key is revealed if used twice.
    private void eraseNonce () {

        Util.arrayFill(tmpArray, (short) 0, Constants.SHARE_LEN, (byte) 0x00);

        for (short i = 0; i < Constants.V; i++) {
            pubNonce[i].randomize();
            nonceAggregate[i].randomize();
            secNonce[i].fromByteArray(tmpArray, (short) 0, Constants.SHARE_LEN);
        }

        coefR.randomize();

    }

    // Bitcoin public key format
    public void getXonlyPubKey(byte[] buffer, short offset) {

        if (stateKeysEstablished == Constants.STATE_FALSE) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        if ((short)(offset + Constants.POINT_LEN) > (short) buffer.length) {
            ISOException.throwIt(Constants.E_BUFFER_OVERLOW);
        }

        short len = publicShare.getX(buffer, offset);

        if (len != Constants.XCORD_LEN) {
            ISOException.throwIt(Constants.E_WRONG_XCORD_LEN);
        }
    }

    //In format v1, v2, v3, v4, ...
    public void getPublicNonceShare (byte[] buffer, short offset) {

        // Is nonce generated?
        if (stateReadyForSigning == Constants.STATE_FALSE) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if ((short)(offset + Constants.XCORD_LEN * Constants.V) > (short) buffer.length) {
            ISOException.throwIt(Constants.E_BUFFER_OVERLOW);
        }

        short currentOffset = offset;

        for (short i = (short) 0; i < Constants.V; i++) {
            //TODO: Tady je true nebo false, aby to sedelo k cbytes v BIP?
            pubNonce[i].encode(buffer, currentOffset, true);
            currentOffset += Constants.XCORD_LEN;
        }
    }

    // Public key, gacc, tacc, coefA (33+32+32+32)
    public void setGroupPubKey (byte[] groupPubKeyX, short offset) {

        if ((short)(offset + Constants.XCORD_LEN + 3 * Constants.SHARE_LEN) > (short) groupPubKeyX.length) {
            ISOException.throwIt(Constants.E_BUFFER_OVERLOW);
        }

        this.groupPubKey.decode(groupPubKeyX, offset, Constants.XCORD_LEN);
        gacc.fromByteArray(groupPubKeyX, (short) (offset + Constants.XCORD_LEN), Constants.SHARE_LEN);
        tacc.fromByteArray(groupPubKeyX, (short) (offset + Constants.XCORD_LEN + Constants.SHARE_LEN), Constants.SHARE_LEN);
        coefA.fromByteArray(groupPubKeyX, (short) (offset + Constants.XCORD_LEN + 2 * Constants.SHARE_LEN), Constants.SHARE_LEN);

        stateKeysEstablished = Constants.STATE_TRUE;
    }

    // 33 + 33
    public void setNonceAggregate (byte[] nonces, short offset) {

        if ((short)(offset + 2 * Constants.XCORD_LEN) > (short) nonces.length) {
            ISOException.throwIt(Constants.E_BUFFER_OVERLOW);
        }

        nonceAggregate[0].decode(nonces, offset, Constants.XCORD_LEN);
        nonceAggregate[1].decode(nonces, (short) (offset + Constants.XCORD_LEN), Constants.XCORD_LEN);

        stateNoncesAggregated = Constants.STATE_TRUE;
    }

    // sk + pk + aggpk (3 + 32 + 33 + 33)
    public void setTestingValues (byte[] buffer, short offset) {

            if (Constants.DEBUG == Constants.STATE_FALSE) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }

            short currentOffset = (short) (offset + 3);

            if (Constants.DEBUG != Constants.STATE_TRUE) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }

            // Secret key
            if (buffer[offset] == Constants.STATE_TRUE) {
                secretShare.fromByteArray(buffer, currentOffset, Constants.SHARE_LEN);
                currentOffset += Constants.SHARE_LEN;
            }

            // Public key
            if (buffer[offset + 1] == Constants.STATE_TRUE) {
                publicShare.decode(buffer, currentOffset, Constants.XCORD_LEN);
                currentOffset += Constants.XCORD_LEN;
            }

            // Group public key
            if (buffer[offset + 2] == Constants.STATE_TRUE) {
                groupPubKey.decode(buffer, currentOffset, Constants.XCORD_LEN);
                stateKeysEstablished = Constants.STATE_TRUE;
            }
    }
}
