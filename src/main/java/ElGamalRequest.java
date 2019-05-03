import org.bouncycastle.jce.interfaces.ElGamalPublicKey;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.PublicKey;

public class ElGamalRequest implements Serializable {


    public String subjectName;
    public BigInteger Y;
    public BigInteger G;
    public BigInteger P;

    public String type;

    ElGamalRequest(String subjectName, BigInteger Y,BigInteger G,BigInteger P, String type)
    {
        this.subjectName=subjectName;
        this.type = type;
        this.Y = Y;
        this.G = G;
        this.P = P;



    }


}
