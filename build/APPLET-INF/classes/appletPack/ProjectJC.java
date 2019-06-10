package appletPack;

import javacard.framework.*;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;

/**
 *
 * @author ASUS
 */
public class ProjectJC extends Applet {
//  **************       Constantes      **************

    private final static byte CLA = (byte) 0x80;
    private final static byte INS_VERIFY_UNBLOCK = (byte) 0x01;     // verifier pin + unblock avec puk
    private final static byte INS_RESET_PASS = (byte) 0x02;         // update puk & pin
    private final static byte INS_READ_PUBKEY = (byte) 0x03;        // lecture public key
    private final static byte INS_GET_FILE = (byte) 0x04;           // lecture du fichier 1024 bit
    private final static byte INS_SIGN = (byte) 0x05;               // signer le fichier
    private final static byte INS_GEN_RSA = (byte) 0x06;            // generer RSA pair
    /* authentification */
    private final static byte[] PIN_Default = {0x01, 0x02, 0x03, 0x04};
    private final static byte[] PUK_Default = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    private final static byte PIN_MAX_TRIES = 0x03;
    private final static byte PUK_MAX_TRIES = 0x03;
    private final static byte PIN_LENGTH = (byte) 0x04;
    private final static byte PUK_LENGTH = (byte) 0x08;

    /* les phase de applet */
    private static final byte PHASE_INSTALATION = 0x01;        // constructeur
    private static final byte PHASE_PERSONALISATION = 0x02;    // setting puk & pin
    private static final byte PHASE_UTILISATION = 0x03;        // ready to use

//  **************      Variables       **************
    private static byte phase, perso1, perso2, perso3;
    private static OwnerPIN pin;
    private static OwnerPIN puk;
    private static KeyPair K_Carte;
    private static RSAPublicKey K_Carte_PublicKey;
    private static RSAPrivateKey K_Carte_PrivateKey;
    private static Signature ma_sign;
    private static byte[] tmpData = new byte[128];

    /**
     * ****************** Constructor & Methods *******************
     */
    protected ProjectJC() {
        register();
        phase = PHASE_INSTALATION;
        perso1 = 0;
        perso2 = 0;
        perso3 = 0;

        pin = new OwnerPIN(PIN_MAX_TRIES, PIN_LENGTH);
        pin.update(PIN_Default, (short) 0, PIN_LENGTH);
        puk = new OwnerPIN(PUK_MAX_TRIES, PUK_LENGTH);
        puk.update(PUK_Default, (short) 0, PUK_LENGTH);

        K_Carte_PrivateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_512, false);
        K_Carte_PublicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, true);
        K_Carte = new KeyPair(KeyPair.ALG_RSA, K_Carte_PublicKey.getSize());

    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ProjectJC();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buffer = apdu.getBuffer();
        if (buffer[ISO7816.OFFSET_CLA] != CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_GEN_RSA:
                if (phase != PHASE_INSTALATION) {
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                }
                K_Carte.genKeyPair();
                K_Carte_PublicKey = (RSAPublicKey) K_Carte.getPublic();
                K_Carte_PrivateKey = (RSAPrivateKey) K_Carte.getPrivate();

                phase = PHASE_PERSONALISATION;
                break;

            case INS_RESET_PASS:
                short len = apdu.setIncomingAndReceive();
                switch (buffer[ISO7816.OFFSET_P1]) {
                    case (byte) 0x81:                           // PIN p1=0x81
                        switch (phase) {
                            case PHASE_PERSONALISATION:
                                if (len == PIN_LENGTH) {
                                    pin.update(buffer, (short) ISO7816.OFFSET_CDATA, (byte) len);
                                    perso2 = 1;
                                    if (perso1 + perso2 + perso3 == 3) {
                                        phase = PHASE_UTILISATION;
                                    }
                                } else {
                                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                                }
                                break;
                            case PHASE_UTILISATION:
                                if (!pin.isValidated()) {
                                    ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                                }
                                if (len == PIN_LENGTH) {
                                    pin.update(buffer, (short) ISO7816.OFFSET_CDATA, (byte) len);
                                } else {
                                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                                }
                                break;
                            default:
                                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                                break;
                        }
                        break;
                    case (byte) 0x82:                           // PUK p1=0x82
                        if (phase != PHASE_PERSONALISATION) {
                            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                        } else if (len == PUK_LENGTH) {
                            puk.update(buffer, (short) ISO7816.OFFSET_CDATA, (byte) len);
                            perso1 = 1;
                            if (perso1 + perso2 + perso3 == 3) {
                                phase = PHASE_UTILISATION;
                            }
                        } else {
                            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                        }
                        break;
                    default:
                        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                }
                break;
            case INS_READ_PUBKEY:
                if (phase != PHASE_PERSONALISATION) {
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                }
                short expLen = K_Carte_PublicKey.getExponent(buffer, (short) (2));
                Util.setShort(buffer, (short) 0, expLen);
                short nextoff = (short) (expLen + 2);
                short modLen = K_Carte_PublicKey.getModulus(buffer, (short) (nextoff + 2));
                Util.setShort(buffer, (short) (nextoff), modLen);
                apdu.setOutgoingAndSend((short) 0, (short) (4 + expLen + modLen));
                perso3 = 1;
                if (perso1 + perso2 + perso3 == 3) {
                    phase = PHASE_UTILISATION;
                }
                break;
            case INS_VERIFY_UNBLOCK:
                boolean valid = false;
                short lc = buffer[ISO7816.OFFSET_CDATA];
                switch (buffer[ISO7816.OFFSET_P1]) {
                    case (byte) 0x81:						// PIN check
                        if (pin.getTriesRemaining() == (byte) 0) {
                            ISOException.throwIt((short) 0x6983);
                        }
                        valid = pin.check(buffer, (short) ISO7816.OFFSET_CDATA, (byte) lc);
                        break;
                    case (byte) 0x82:						// PUK check
                        valid = puk.check(buffer, (short) ISO7816.OFFSET_CDATA, (byte) lc);
                        if (puk.isValidated() && pin.getTriesRemaining() == 0) {
                            pin.resetAndUnblock();
                        }
                        puk.resetAndUnblock(); // for unlimited puk tries
                        break;
                    default:
                        ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                }
                if (!valid) {
                    ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                }
                break;

            case INS_GET_FILE:
                if (phase != PHASE_UTILISATION) {
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                }
                if (!pin.isValidated()) {
                    ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                }
                short bytesRead = apdu.setIncomingAndReceive();
                short destOffset = (short) 0;
                while (bytesRead > 0) {
                    Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, tmpData, destOffset, bytesRead);
                    destOffset += bytesRead;
                    bytesRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
                }
                break;

            case INS_SIGN:
                if (phase != PHASE_UTILISATION) {
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                }
                if (!pin.isValidated()) {
                    ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                }
                ma_sign = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
                ma_sign.init(K_Carte_PrivateKey, Signature.MODE_SIGN);
                short signLen = ma_sign.sign(tmpData, (short) 0x00, (short) tmpData.length, buffer, (short) 0);
                apdu.setOutgoingAndSend((short) 0, signLen);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
}
