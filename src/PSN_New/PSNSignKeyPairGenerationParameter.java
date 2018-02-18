package PSN_New;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;

public class PSNSignKeyPairGenerationParameter extends PairingKeyPairGenerationParameter {
    public PSNSignKeyPairGenerationParameter(PairingParameters pairingParameters) {
        super(pairingParameters);
    }
}
