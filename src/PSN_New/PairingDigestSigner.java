package PSN_New;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;

import java.io.IOException;

/**
 * Created by Weiran Liu on 2016/10/18.
 * <p>
 * Pairing-based digital signature.
 */
public class PairingDigestSigner implements Signer {
    //    该类的实例是Signer
    private final Digest digest;
    private final PairingSigner pairingSigner;
    private boolean forSigning;

    public PairingDigestSigner(PairingSigner signer, Digest digest) {
        this.digest = digest;
        this.pairingSigner = signer;
    }
//    构造函数 在 BB04方案中 signer 为 BB04Signer()， digest 为 SHA256Digest()

    public void init(boolean forSigning, CipherParameters parameters) {
        this.forSigning = forSigning;
//        传入的这个parameters 是 secretKey
        PairingKeySerParameter k = (PairingKeySerParameter) parameters;
        if (forSigning && !k.isPrivate()) {
            throw new IllegalArgumentException("Signing Requires Private Key.");
        }

        if (!forSigning && k.isPrivate()) {
            throw new IllegalArgumentException("Verification Requires Public Key.");
        }

        reset();
        /*
        引用 bouncycastle API 中的原话 不知道干什么用的
        reset the chaining variablesy
        * */

        pairingSigner.init(forSigning, parameters);
    }

    /**
     * update the internal digest with the byte b
     */
    public void update(byte input) {

        digest.update(input);
    }

    /**
     * update the internal digest with the byte array in
     */
    public void update(byte[] input, int inOff, int length) {

        digest.update(input, inOff, length);
    }

    /**
     * Generate a signature for the message we've been loaded with using
     * the key we were initialised with.
     */
    public byte[] generateSignature() {
        if (!forSigning) {
            throw new IllegalStateException("PairingDigestSigner not initialised for signature generation.");
        }

        /*
        * 整个签名过程如下
        * */

        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        Element[] sig = pairingSigner.generateSignature(hash);

        try {
            return pairingSigner.derEncode(sig);
        } catch (IOException e) {
            throw new IllegalStateException("unable to encode signature");
        }
    }

    public boolean verifySignature(byte[] signature) {
        if (forSigning) {
            throw new IllegalStateException("PairingDigestSigner not initialised for verification");
        }

        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        try {
            Element[] sig = pairingSigner.derDecode(signature);
            return pairingSigner.verifySignature(hash, sig);
        } catch (IOException e) {
            return false;
        }
    }

    public void reset() {
        digest.reset();
    }

}