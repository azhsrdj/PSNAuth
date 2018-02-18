package PSN_New;

import java.io.Serializable;

public class Tokendata_1 implements Serializable {

    private byte[] tokendata;

    String s = "sahbfkasjbf.wbfq.kqw12314————=12412";


    public byte[] getTokendata() {
        tokendata = s.getBytes();
        return tokendata;
    }
}
