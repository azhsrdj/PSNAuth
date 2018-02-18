package PSN_New;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;

import static PSN_New.PSNSignKeyPairGenerator.bytearraycopy;
import static PSN_New.PSNSignKeyPairGenerator.sha256DigestOf;

public class PSNSigner implements PairingSigner {

    private static final String SCHEME_NAME = "PSN signature scheme";
    private PairingKeySerParameter pairingKeySerParameter;

    public PSNSigner() {

    }

    @Override
    public String getEngineName() {
        return SCHEME_NAME;
    }

    @Override
    public void init(boolean forSigning, CipherParameters param) {
        if (forSigning) {
            this.pairingKeySerParameter = (PSNSignSecretKeySerParameter) param;
        } else {
            this.pairingKeySerParameter = (PSNSignPublicKeySerParameter) param;
        }
    }

    @Override
    public Element[] generateSignature(byte[] message) {
        PairingParameters params = this.pairingKeySerParameter.getParameters();
        Pairing pairing = PairingFactory.getPairing(params);
        PSNSignSecretKeySerParameter secretKeySerParameter = (PSNSignSecretKeySerParameter) this.pairingKeySerParameter;
        Element s = secretKeySerParameter.gets();
        Element g = secretKeySerParameter.getPublicKeyParameters().getG();
        Element V1 = secretKeySerParameter.getV1();
        Element V2 = secretKeySerParameter.getV2();
        Element m = PairingUtils.MapByteArrayToGroup(pairing, message, PairingUtils.PairingGroupType.G1);
        Element sigma = m.mulZn(s).mul(V1).mul(V2);

        return new Element[]{sigma, null};
    }

    @Override
    public boolean verifySignature(byte[] message, Element... signature) {
        PairingParameters params = this.pairingKeySerParameter.getParameters();
        Pairing pairing = PairingFactory.getPairing(params);
        PSNSignPublicKeySerParameter publicKeyParameters = (PSNSignPublicKeySerParameter) this.pairingKeySerParameter;
        Element m = PairingUtils.MapByteArrayToGroup(pairing, message, PairingUtils.PairingGroupType.G1);
        Element g = publicKeyParameters.getG();
        Element U1 = publicKeyParameters.getU1();
        byte[] U2 = publicKeyParameters.getU2();
        Element Q = publicKeyParameters.getQ();

        Element signa = signature[0];
        Element temp1 = pairing.pairing(signa, g);
        byte[] U1_U2 = sha256DigestOf(bytearraycopy(U1.toBytes(), U2));
        Element temp2 = pairing.pairing(U1.mul(m).mul(PairingUtils.MapByteArrayToGroup(pairing,
                U1_U2, PairingUtils.PairingGroupType.G1)), Q);
        return PairingUtils.isEqualElement(temp1, temp2);
    }

    @Override
    public byte[] derEncode(Element[] signElements) throws IOException {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERPrintableString(Hex.toHexString(signElements[0].toBytes())));
//        v.add(new DERPrintableString(Hex.toHexString(signElements[1].toBytes())));
        return new DERSequence(v).getEncoded(ASN1Encoding.DER);
    }

    @Override
    public Element[] derDecode(byte[] encoding) throws IOException {
        ASN1Sequence s = (ASN1Sequence) ASN1Primitive.fromByteArray(encoding);
        PairingParameters params = this.pairingKeySerParameter.getParameters();
        Pairing pairing = PairingFactory.getPairing(params);

        return new Element[]{
                pairing.getG1().newElementFromBytes(Hex.decode(((ASN1String) s.getObjectAt(0)).getString())),
//                pairing.getZr().newElementFromBytes(Hex.decode(((ASN1String)s.getObjectAt(1)).getString())),
        };
    }

}
