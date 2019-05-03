import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.oiw.ElGamalParameter;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.interfaces.ElGamalPublicKey;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.jce.spec.ElGamalPublicKeySpec;

import javax.crypto.spec.DHParameterSpec;
import java.io.IOException;
import java.math.BigInteger;

public class GamalPublicKey implements ElGamalPublicKey {
    static final long serialVersionUID = 8712728417091216948L;

    private BigInteger y;
    private ElGamalParameterSpec elSpec;

    GamalPublicKey(ElGamalPublicKeySpec spec) {
        this.y = spec.getY();
        this.elSpec = new ElGamalParameterSpec(spec.getParams().getP(), spec.getParams().getG());
    }

    public BigInteger getY() {
        return this.y;
    }

    public String getAlgorithm() {
        return "ElGamal";
    }

    public String getFormat() {
        return "X.509";
    }

    public byte[] getEncoded() {
        try
        {
            SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(OIWObjectIdentifiers.elGamalAlgorithm, new ElGamalParameter(elSpec.getP(), elSpec.getG())), new DERInteger(y));

            return info.getEncoded(ASN1Encoding.DER);

        }
        catch (IOException e)
        {
            return null;
        }

    }

    public ElGamalParameterSpec getParameters() {
        return this.elSpec;
    }


    public DHParameterSpec getParams() {
        return new DHParameterSpec(elSpec.getP(), elSpec.getG());
    }
}
