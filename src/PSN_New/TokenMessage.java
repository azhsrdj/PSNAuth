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

public class TokenMessage extends PairingKeySerParameter {
    private transient Element g;
    private final byte[] byteArrayG;
    private transient Element Q;
    private final byte[] byteArrayQ;
    private transient Element s;
    private final byte[] byteArrayS;
    private byte[] tokenBytes;

    public TokenMessage(PairingParameters pairingParameters, Element g, Element Q, Element s, byte[] tokenBytes) {
        super(false, pairingParameters);
        this.g = g.getImmutable();
        this.byteArrayG = this.g.toBytes();
        this.Q = Q.getImmutable();
        this.byteArrayQ = this.Q.toBytes();
        this.s = s.getImmutable();
        this.byteArrayS = this.s.toBytes();
        this.tokenBytes = tokenBytes;
    }

    public Element getG() {
        return this.g.duplicate();
    }

    public byte[] getByteArrayG() {
        return this.byteArrayG;
    }

    public Element getQ() {
        return this.Q.duplicate();
    }

    public byte[] getByteArrayQ() {
        return this.byteArrayQ;
    }

    public Element gets() {
        return this.s.duplicate();
    }

    public byte[] getByteArrays() {
        return this.byteArrayS;
    }

    public byte[] getTokenBytes() {
        return this.tokenBytes;
    }


    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof TokenMessage) {
            TokenMessage that = (TokenMessage) anObject;
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
            if (!PairingUtils.isEqualElement(this.s, that.gets())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayS, that.byteArrayS)) {
                return false;
            }
            if (!Arrays.equals(this.tokenBytes, that.getTokenBytes())) {
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
        this.s = pairing.getG1().newElementFromBytes(this.byteArrayS).getImmutable();
        this.tokenBytes = this.tokenBytes;
    }
}

