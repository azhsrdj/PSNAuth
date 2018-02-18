package PSN_New;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

public class PSNSignKeyPairGenerator implements PairingKeyPairGenerator {
    private PSNSignKeyPairGenerationParameter param;

    @Override
    public void init(KeyGenerationParameters param) {
        this.param = (PSNSignKeyPairGenerationParameter) param;
    }

    @Override
    public PairingKeySerPair generateKeyPair() {
        return null;
    }

    @Override
    public PairingKeySerPair generateKeyPair(byte[] token) throws NoSuchAlgorithmException {
        Pairing pairing = PairingFactory.getPairing(param.getPairingParameters());
        Element s = pairing.getZr().newRandomElement().getImmutable();
        Element g = pairing.getG2().newRandomElement().getImmutable();
        Element Q = g.powZn(s).getImmutable();
        byte[] tokenbytes = sha256DigestOf(token);

        Element U1 = PairingUtils.MapByteArrayToGroup(pairing, tokenbytes, PairingUtils.PairingGroupType.G1).mul(Q)
                .mul(PairingUtils.MapByteArrayToGroup(pairing, rdnum(), PairingUtils.PairingGroupType.G1));
        byte[] U2 = getXor(tokenbytes, U1.toBytes());
        Element V1 = U1.powZn(s);
        byte[] U1_U2 = sha256DigestOf(bytearraycopy(U1.toBytes(), U2));
        Element V2 = PairingUtils.MapByteArrayToGroup(pairing,
                U1_U2, PairingUtils.PairingGroupType.G1).powZn(s);

        PSNSignPublicKeySerParameter publicKeySerParameter =
                new PSNSignPublicKeySerParameter(param.getPairingParameters(), g, Q, U1, U2);
        PSNSignSecretKeySerParameter secretKeySerParameter =
                new PSNSignSecretKeySerParameter(param.getPairingParameters(), publicKeySerParameter, s, V1, V2);
        return new PairingKeySerPair(publicKeySerParameter, secretKeySerParameter);
    }

    @Override
    public PairingKeySerPair generateKeyPair(TokenMessage tokenMessage) throws NoSuchAlgorithmException {
        Pairing pairing = PairingFactory.getPairing(param.getPairingParameters());
        Element g = tokenMessage.getG();
        Element Q = tokenMessage.getQ();
        Element s = tokenMessage.gets();
        byte[] tokenbytes = tokenMessage.getTokenBytes();

        Element U1 = PairingUtils.MapByteArrayToGroup(pairing, tokenbytes, PairingUtils.PairingGroupType.G1).mul(Q)
                .mul(PairingUtils.MapByteArrayToGroup(pairing, rdnum(), PairingUtils.PairingGroupType.G1));
        byte[] U2 = getXor(tokenbytes, U1.toBytes());
        Element V1 = U1.powZn(s);
        byte[] U1_U2 = sha256DigestOf(bytearraycopy(U1.toBytes(), U2));
        Element V2 = PairingUtils.MapByteArrayToGroup(pairing,
                U1_U2, PairingUtils.PairingGroupType.G1).powZn(s);

        PSNSignPublicKeySerParameter publicKeySerParameter =
                new PSNSignPublicKeySerParameter(param.getPairingParameters(), g, Q, U1, U2);
        PSNSignSecretKeySerParameter secretKeySerParameter =
                new PSNSignSecretKeySerParameter(param.getPairingParameters(), publicKeySerParameter, s, V1, V2);
        return new PairingKeySerPair(publicKeySerParameter, secretKeySerParameter);
    }

    @Override
    public PSNSignPublicKeySerParameter getPSNpublickey(byte[] gBytes, byte[] QBytes, byte[] byteArrayU1, byte[] byteArrayU2) {
        Pairing pairing = PairingFactory.getPairing(param.getPairingParameters());
        Element g = pairing.getG2().newElementFromBytes(gBytes).getImmutable();
        Element Q = pairing.getG2().newElementFromBytes(QBytes);
        Element U1 = pairing.getG1().newElementFromBytes(byteArrayU1).getImmutable();
        byte[] U2 = byteArrayU2;
        PSNSignPublicKeySerParameter publicKeySerParameter =
                new PSNSignPublicKeySerParameter(param.getPairingParameters(), g, Q, U1, U2);
        return publicKeySerParameter;
    }

    //    public TokenMessage generateTokenMessage(Tokendata_1 tokendata_1){
//        Pairing pairing = PairingFactory.getPairing(param.getPairingParameters());
//        Element s = pairing.getZr().newRandomElement().getImmutable();
//        Element g = pairing.getG2().newRandomElement().getImmutable();
//        Element Q = g.powZn(s).getImmutable();
//        byte[] tokenbytes = tokendata_1.getTokendata();
//        TokenMessage tokenMessage = new TokenMessage(param.getPairingParameters(),g,Q,s,tokenbytes);
//        return tokenMessage;
//    }
    public TokenMessage1 generateTokenMessage(Tokendata_1 tokendata_1) {
        Pairing pairing = PairingFactory.getPairing(param.getPairingParameters());
        Element s = pairing.getZr().newRandomElement().getImmutable();
        Element g = pairing.getG2().newRandomElement().getImmutable();
        Element Q = g.powZn(s).getImmutable();
        byte[] sBytes = s.toBytes();
        byte[] gBytes = g.toBytes();
        byte[] QBytes = Q.toBytes();
        byte[] tokenbytes = tokendata_1.getTokendata();
        TokenMessage1 tokenMessage1 = new TokenMessage1(gBytes, QBytes, sBytes, tokenbytes);
        return tokenMessage1;
    }

    public PairingKeySerPair generateKeyPair(TokenMessage1 tokenMessage1) throws NoSuchAlgorithmException {
        Pairing pairing = PairingFactory.getPairing(param.getPairingParameters());
        byte[] gBytes = tokenMessage1.getByteArrayG();
        byte[] sBytes = tokenMessage1.getByteArrays();
        byte[] QBytes = tokenMessage1.getByteArrayQ();
        byte[] tokenbytes = tokenMessage1.getTokenBytes();
        Element g = pairing.getG2().newElementFromBytes(gBytes).getImmutable();
        Element Q = pairing.getG2().newElementFromBytes(QBytes).getImmutable();
        Element s = pairing.getZr().newElementFromBytes(sBytes).getImmutable();
        Element U1 = PairingUtils.MapByteArrayToGroup(pairing, tokenbytes, PairingUtils.PairingGroupType.G1).mul(Q)
                .mul(PairingUtils.MapByteArrayToGroup(pairing, rdnum(), PairingUtils.PairingGroupType.G1));
        byte[] U2 = getXor(tokenbytes, U1.toBytes());
        Element V1 = U1.powZn(s);
        byte[] U1_U2 = sha256DigestOf(bytearraycopy(U1.toBytes(), U2));
        Element V2 = PairingUtils.MapByteArrayToGroup(pairing,
                U1_U2, PairingUtils.PairingGroupType.G1).powZn(s);

        PSNSignPublicKeySerParameter publicKeySerParameter =
                new PSNSignPublicKeySerParameter(param.getPairingParameters(), g, Q, U1, U2);
        PSNSignSecretKeySerParameter secretKeySerParameter =
                new PSNSignSecretKeySerParameter(param.getPairingParameters(), publicKeySerParameter, s, V1, V2);
        return new PairingKeySerPair(publicKeySerParameter, secretKeySerParameter);
    }

    public static byte[] sha256DigestOf(byte[] input) {
        SHA256Digest d = new SHA256Digest();
        d.update(input, 0, input.length);
        byte[] result = new byte[d.getDigestSize()];
        d.doFinal(result, 0);
        return result;
    }

    private byte[] rdnum() throws NoSuchAlgorithmException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        // SHA1PRNG随机数算法
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
        rng.setSeed(21);
        rng.nextBytes(new byte[1024]);
        // 生成随机数
        int numberToGenerate = 999;
        byte randNumbers[] = new byte[numberToGenerate];
        rng.nextBytes(randNumbers);
        return randNumbers;
    }

    public static byte[] getXor(byte[] a, byte[] b) {
        byte[] temp = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            temp[i] = (byte) (a[i] ^ b[i]);
        }
        return temp;
    }

    public static byte[] bytearraycopy(byte[] a, byte[] b) {
        byte[] res = new byte[a.length + b.length];
        System.arraycopy(a, 0, res, 0, a.length);
        System.arraycopy(b, 0, res, a.length, b.length);
        return res;
    }
}
