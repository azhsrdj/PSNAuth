package PSN_New;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyPairGenerator;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class PSNSigningEngine {

    public static final String PATH_a_160_512 = "params/a_160_512.properties";

    private PairingParameters pairingParameters;

    private PairingKeyPairGenerator asymmetricKeySerPairGenerator;

    private Tokendata_1 tokendata_1;

    public PSNSigningEngine() {
        this.pairingParameters = PairingFactory.getPairingParameters(PATH_a_160_512);
        this.asymmetricKeySerPairGenerator = new PSNSignKeyPairGenerator();
        this.asymmetricKeySerPairGenerator.init(new PSNSignKeyPairGenerationParameter(pairingParameters));
        this.tokendata_1 = new Tokendata_1();
    }

    public TokenMessage1 generateTokenMessage() {
        TokenMessage1 tokenMessage1 = this.asymmetricKeySerPairGenerator.generateTokenMessage(tokendata_1);
        return tokenMessage1;
    }

}
