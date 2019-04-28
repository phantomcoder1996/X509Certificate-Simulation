import org.bouncycastle.jce.interfaces.ElGamalPublicKey;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.jce.spec.ElGamalPrivateKeySpec;
import org.bouncycastle.jce.spec.ElGamalPublicKeySpec;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Random;

public class ElGammalDS {



    public static byte[] signMessage(byte[] message,PrivateKey key)
    {
        //hash the message
        //find signature
        // append message and signature
        //return appended message and signature

        //May be you will need to use certain encoding such as DER to deal with byte array

        return null;
    }

    public static boolean verifyMessageSignature(byte[]message, PublicKey key)
    {
        //hash the message
        //decrypt signature using public key
        //compare message hash with decrypted signature

        ElGamalPublicKey gkey = (ElGamalPublicKey)key;
        BigInteger Y = gkey.getY();
        BigInteger P = gkey.getParameters().getP();
        BigInteger G = gkey.getParameters().getG();


        return true;
    }

    //Returns the message part without the signature
    public static String getMessagePart(byte[]message)
    {
        return "";
    }


    public static KeyPair generateElGamalKeyPair()
    {
        //First global parameters q(p)and alpha(g)
        BigInteger p = generateP();
        BigInteger g = generateG();
        //Private key
        BigInteger XA=generatePrivateKey(p,g); //elgamal private key
        // Public key
        BigInteger Y = generatePublickey(p,g,XA);


        ElGamalParameterSpec spec = new ElGamalParameterSpec(p,g);
        ElGamalPrivateKeySpec prs= new ElGamalPrivateKeySpec(XA,spec);
        ElGamalPublicKeySpec pbls = new ElGamalPublicKeySpec(Y,spec);

        GamalPublicKey gpk= new GamalPublicKey(pbls);
        GamalPrivateKey gp = new GamalPrivateKey(prs);

        return new KeyPair(gpk,gp);

    }

    private static BigInteger generatePublickey(BigInteger p, BigInteger g, BigInteger xa) {
        return null;
    }

    private static BigInteger generatePrivateKey(BigInteger p, BigInteger g) {
        return null;
    }

    private static BigInteger generateG() {
        return null;
    }

    private static BigInteger generateP() {
        return null;
    }


}
