package cn.edu.buaa.crypto.algebra.generators;

import PSN_New.PSNSignPublicKeySerParameter;
import PSN_New.TokenMessage;
import PSN_New.TokenMessage1;
import PSN_New.Tokendata_1;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.security.NoSuchAlgorithmException;

/**
 * Created by Weiran Liu on 2016/11/9.
 * <p>
 * Asymmetric serializable key pair generator.
 */
public interface PairingKeyPairGenerator {
    /**
     * intialise the key pair generator.
     *
     * @param param the parameters the key pair is to be initialised with.
     */
    void init(KeyGenerationParameters param);

    /**
     * return an AsymmetricCipherKeyPair containing the generated keys.
     *
     * @return an AsymmetricCipherKeyPair containing the generated keys.
     */
    PairingKeySerPair generateKeyPair();

    PairingKeySerPair generateKeyPair(byte[] token) throws NoSuchAlgorithmException;

    public PairingKeySerPair generateKeyPair(TokenMessage tokenMessage) throws NoSuchAlgorithmException;

    TokenMessage1 generateTokenMessage(Tokendata_1 tokendata_1);

    public PSNSignPublicKeySerParameter getPSNpublickey(byte[] gBytes, byte[] QBytes, byte[] byteArrayU1, byte[] byteArrayU2);
}
