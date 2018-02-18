package PSN_New;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.Arrays;

public class PSNSignPublicKeySerParameter extends PairingKeySerParameter {
    private transient Element g;
    private final byte[] byteArrayG;
    private transient Element Q;
    private final byte[] byteArrayQ;

    private transient Element U1;
    private final byte[] byteArrayU1;

    private transient byte[] U2;
    private final byte[] byteArrayU2;

//    private Element U2;
//    private final byte[] byteArrayU2;


    PSNSignPublicKeySerParameter(PairingParameters parameters, Element g, Element Q, Element U1, byte[] U2) {
        super(false, parameters);
        this.g = g.getImmutable();
        this.byteArrayG = this.g.toBytes();
        this.Q = Q.getImmutable();
        this.byteArrayQ = this.Q.toBytes();
        this.U1 = U1.getImmutable();
        this.byteArrayU1 = this.U1.toBytes();
        this.U2 = U2;
        this.byteArrayU2 = this.U2;
    }

    public Element getG() {
        return this.g.duplicate();
    }

    public Element getQ() {
        return this.Q.duplicate();
    }

    public Element getU1() {
        return this.U1.duplicate();
    }

    public byte[] getU2() {
        return this.U2;
    }

    public byte[] getByteArrayG() {
        return byteArrayG;
    }

    public byte[] getByteArrayQ() {
        return byteArrayQ;
    }

    public byte[] getByteArrayU1() {
        return byteArrayU1;
    }

    public byte[] getByteArrayU2() {
        return byteArrayU2;
    }
    /*public Element getU2() {
        return this.U2.duplicate();
    }*/

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof PSNSignPublicKeySerParameter) {
            PSNSignPublicKeySerParameter that = (PSNSignPublicKeySerParameter) anObject;
            //Compare g1
            if (!PairingUtils.isEqualElement(this.g, that.getG())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG, that.byteArrayG)) {
                return false;
            }
            if (!PairingUtils.isEqualElement(this.Q, that.getQ())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayQ, that.byteArrayQ)) {
                return false;
            }
            if (!PairingUtils.isEqualElement(this.U1, that.getU1())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayU1, that.byteArrayU1)) {
                return false;
            }
//            if (!PairingUtils.isEqualElement(this.U2, that.getU2())) {
//                return false;
//            }
            if (!Arrays.equals(this.U2, that.getU2())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayU2, that.byteArrayU2)) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }

    private void readObject(ObjectInputStream objectInputStream)
            throws IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());

        this.g = pairing.getG2().newElementFromBytes(this.byteArrayG).getImmutable();
        this.Q = pairing.getG2().newElementFromBytes(this.byteArrayQ).getImmutable();
        this.U1 = pairing.getG1().newElementFromBytes(this.byteArrayU1).getImmutable();
        this.U2 = this.byteArrayU2;
//        this.U2 = pairing.getG1().newElementFromBytes(this.byteArrayU2).getImmutable();
    }
}
