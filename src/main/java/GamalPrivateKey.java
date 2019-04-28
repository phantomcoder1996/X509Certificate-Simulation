import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.oiw.ElGamalParameter;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.interfaces.ElGamalPrivateKey;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.jce.spec.ElGamalPrivateKeySpec;

import javax.crypto.spec.DHParameterSpec;
import java.io.IOException;
import java.math.BigInteger;

class GamalPrivateKey implements ElGamalPrivateKey {

    private BigInteger X;
    private transient ElGamalParameterSpec elSpec;

    GamalPrivateKey(ElGamalPrivateKeySpec spec)
    {
        this.X = spec.getX();
        this.elSpec = new ElGamalParameterSpec(spec.getParams().getP(), spec.getParams().getG());
    }

    public BigInteger getX() {
        return this.X;
    }

    public String getAlgorithm() {
        return "ElGamal";
    }

    public String getFormat() {
        return "PKCS#8";
    }

    public byte[] getEncoded() {
        try
        {
            PrivateKeyInfo info = new PrivateKeyInfo(new AlgorithmIdentifier(OIWObjectIdentifiers.elGamalAlgorithm, new ElGamalParameter(elSpec.getP(), elSpec.getG())), new DERInteger(getX()));

            return info.getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            return null;
        }

    }

    public DHParameterSpec getParams() {
        return new DHParameterSpec(elSpec.getP(), elSpec.getG());
    }

    public ElGamalParameterSpec getParameters() {
        return this.elSpec;
    }
}