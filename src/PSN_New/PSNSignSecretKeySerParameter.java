package PSN_New;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

public class PSNSignSecretKeySerParameter extends PairingKeySerParameter {
    private transient Element s;
    private final byte[] byteArrays;
    private transient Element V1;
    private final byte[] byteArrayV1;
    private transient Element V2;
    private final byte[] byteArrayV2;

    private final PSNSignPublicKeySerParameter publicKeyParameters;

    public PSNSignSecretKeySerParameter(PairingParameters parameters, PSNSignPublicKeySerParameter publicKeyParameters,
                                        Element s, Element V1, Element V2) {
        super(true, parameters);
        this.publicKeyParameters = publicKeyParameters;
        this.s = s.getImmutable();
        this.byteArrays = this.s.toBytes();
        this.V1 = V1.getImmutable();
        this.byteArrayV1 = this.V1.toBytes();
        this.V2 = V2.getImmutable();
        this.byteArrayV2 = this.V2.toBytes();
    }

    public Element gets() {
        return this.s.duplicate();
    }

    public Element getV1() {
        return this.V1.duplicate();
    }

    public Element getV2() {
        return this.V2.duplicate();
    }

    public PSNSignPublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof PSNSignSecretKeySerParameter) {
            PSNSignSecretKeySerParameter that = (PSNSignSecretKeySerParameter) anObject;
            //Compare x
            if (!PairingUtils.isEqualElement(this.s, that.gets())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrays, that.byteArrays)) {
                return false;
            }
            if (!PairingUtils.isEqualElement(this.V1, that.getV1())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayV1, that.byteArrayV1)) {
                return false;
            }
            if (!PairingUtils.isEqualElement(this.V2, that.getV2())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayV2, that.byteArrayV2)) {
                return false;
            }
            //Compare public key parameters
            if (!this.publicKeyParameters.equals(that.getPublicKeyParameters())) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());

        this.s = pairing.getZr().newElementFromBytes(this.byteArrays).getImmutable();
        this.V1 = pairing.getG1().newElementFromBytes(this.byteArrayV1).getImmutable();
        this.V2 = pairing.getG1().newElementFromBytes(this.byteArrayV2).getImmutable();

    }
}
