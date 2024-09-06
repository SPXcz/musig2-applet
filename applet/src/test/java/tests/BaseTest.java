package tests;

import cardTools.CardManager;
import cardTools.CardType;
import cardTools.RunConfig;
import cardTools.Util;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.ArrayList;

/**
 * Base Test class.
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author Petr Svenda, Dusan Klinec (ph4r05)
 */
public class BaseTest {
    private static String APPLET_AID = "01ffff0405060708090102";
    private static byte APPLET_AID_BYTE[] = Util.hexStringToByteArray(APPLET_AID);

    protected CardType cardType = CardType.JCARDSIMLOCAL;

    protected boolean simulateStateful = false;
    protected CardManager statefulCard = null;

    public BaseTest() {

    }

    /**
     * Creates card manager and connects to the card.
     *
     * @return
     * @throws Exception
     */
    public CardManager connect() throws Exception {
        return connect(null);
    }

    public CardManager connect(byte[] installData) throws Exception {
        if (simulateStateful && statefulCard != null){
            return statefulCard;
        } else if (simulateStateful){
            statefulCard = connectRaw(installData);
            return statefulCard;
        }

        return connectRaw(installData);
    }

    public CardManager connectRaw(byte[] installData) {
        return null;
    }

    /**
     * Convenience method for connecting and sending
     * @param cmd
     * @return
     */
    public ResponseAPDU connectAndSend(CommandAPDU cmd) throws Exception {
        return connect().transmit(cmd);
    }

    /**
     * Convenience method for building APDU command
     * @param data
     * @return
     */
    public static CommandAPDU buildApdu(String data){
        return new CommandAPDU(Util.hexStringToByteArray(data));
    }

    /**
     * Convenience method for building APDU command
     * @param data
     * @return
     */
    public static CommandAPDU buildApdu(byte[] data){
        return new CommandAPDU(data);
    }

    /**
     * Convenience method for building APDU command
     * @param data
     * @return
     */
    public static CommandAPDU buildApdu(CommandAPDU data){
        return data;
    }

    /**
     * Sending command to the card.
     * Enables to send init commands before the main one.
     *
     * @param cardMngr
     * @param command
     * @param initCommands
     * @return
     * @throws CardException
     */
    public ResponseAPDU sendCommandWithInitSequence(CardManager cardMngr, String command, ArrayList<String> initCommands) throws CardException {
        if (initCommands != null) {
            for (String cmd : initCommands) {
                cardMngr.getChannel().transmit(buildApdu(cmd));
            }
        }

        final ResponseAPDU resp = cardMngr.getChannel().transmit(buildApdu(command));
        return resp;
    }

    public CardType getCardType() {
        return cardType;
    }

    public BaseTest setCardType(CardType cardType) {
        this.cardType = cardType;
        return this;
    }

    public boolean isSimulateStateful() {
        return simulateStateful;
    }

    public BaseTest setSimulateStateful(boolean simulateStateful) {
        this.simulateStateful = simulateStateful;
        return this;
    }

    public boolean isPhysical() {
        return cardType == CardType.PHYSICAL || cardType == CardType.PHYSICAL_JAVAX;
    }

    public boolean isStateful(){
        return isPhysical() || simulateStateful;
    }

    public boolean canReinstall(){
        return !isPhysical() && !simulateStateful;
    }
}
