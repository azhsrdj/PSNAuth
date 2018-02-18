package PSN_New;


import java.io.Serializable;


public class TokenMessage1 implements Serializable {

    private byte[] byteArrayG;
    private byte[] byteArrayQ;
    private byte[] byteArrayS;
    private byte[] tokenBytes;

    public TokenMessage1(byte[] byteArrayG, byte[] byteArrayQ, byte[] byteArrayS, byte[] tokenBytes) {
        this.byteArrayG = byteArrayG;
        this.byteArrayQ = byteArrayQ;
        this.byteArrayS = byteArrayS;
        this.tokenBytes = tokenBytes;
    }

    public byte[] getByteArrayG() {
        return this.byteArrayG;
    }

    public byte[] getByteArrayQ() {
        return this.byteArrayQ;
    }

    public byte[] getByteArrays() {
        return this.byteArrayS;
    }

    public byte[] getTokenBytes() {
        return this.tokenBytes;
    }

}
