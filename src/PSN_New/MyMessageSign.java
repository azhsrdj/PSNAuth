package PSN_New;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA256Digest;

import java.security.NoSuchAlgorithmException;

public class MyMessageSign {
    private TokenMessage tokenMessage;
    private Signer signer;
    private PairingKeyPairGenerator asymmetricKeySerPairGenerator;
    private PairingKeySerPair keyPair;
    private PairingKeySerParameter publicKey;
    private PairingKeySerParameter secretKey;


    public MyMessageSign() {

    }

    public MyMessageSign(TokenMessage tokenMessage) {
        this.tokenMessage = tokenMessage;
    }

    public MyMessageSign(PairingKeySerParameter publicKey) {
        this.publicKey = publicKey;
    }

    public void init() {
        PairingParameters pairingParameters = PairingFactory.getPairingParameters(PairingUtils.PATH_a_160_512);
        this.asymmetricKeySerPairGenerator = new PSNSignKeyPairGenerator();
        asymmetricKeySerPairGenerator.init(new PSNSignKeyPairGenerationParameter(pairingParameters));
        this.signer = new PairingDigestSigner(new PSNSigner(), new SHA256Digest());
    }

    public void generateKeyPair() throws NoSuchAlgorithmException {
        this.keyPair = asymmetricKeySerPairGenerator.generateKeyPair(tokenMessage);
        this.publicKey = keyPair.getPublic();
        this.secretKey = keyPair.getPrivate();
    }

    public void generatePublicKey(byte[] gBytes, byte[] QBytes, byte[] byteArrayU1, byte[] byteArrayU2) {
        this.publicKey = asymmetricKeySerPairGenerator.getPSNpublickey(gBytes, QBytes, byteArrayU1, byteArrayU2);
    }

    public byte[] generateSignature(byte[] message) throws CryptoException {
        signer.init(true, secretKey);
        signer.update(message, 0, message.length);
        byte[] signature = signer.generateSignature();
        return signature;
    }

    public boolean verifySignature(byte[] message, byte[] signature) {
        signer.init(false, publicKey);
        signer.update(message, 0, message.length);
        return signer.verifySignature(signature);
    }

}

