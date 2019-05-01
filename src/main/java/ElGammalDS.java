import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.bouncycastle.jce.interfaces.ElGamalPublicKey;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.jce.spec.ElGamalPrivateKeySpec;
import org.bouncycastle.jce.spec.ElGamalPublicKeySpec;
import java.security.SecureRandom;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Random;
import org.bouncycastle.jce.interfaces.ElGamalPrivateKey;

public class ElGammalDS {
   static Random random = new SecureRandom();
   static int mStreangth = 64;
   static int plength;
   public static BigInteger TWO = new BigInteger("2");



    public static byte[] signMessage(byte[] message,PrivateKey key) throws NoSuchAlgorithmException 
    {
        BigInteger k;
        BigInteger r = BigInteger.ZERO,s = BigInteger.ZERO;
        ElGamalPrivateKey gkey = (ElGamalPrivateKey)key;
        BigInteger Xm = gkey.getX();
        BigInteger P = gkey.getParameters().getP();
        BigInteger G = gkey.getParameters().getG();
        boolean isCorrect_s = false;
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(message);
        BigInteger hashm = new BigInteger(1,hash);
        while(!isCorrect_s)
        { BigInteger PminusOne = P.subtract(BigInteger.ONE);
        do
        {
            
            k = new BigInteger(P.bitLength()-1,new SecureRandom());
            
        } while(k.gcd(PminusOne).equals(BigInteger.ONE)== false);
        
         r = G.modPow(k, P);
        
       
        
        BigInteger top = hashm.subtract(Xm.multiply(r)).mod(PminusOne);
        s = top.multiply(k.modPow(BigInteger.ONE, PminusOne)).mod(PminusOne);
         if((s.equals(BigInteger.ZERO))){
                isCorrect_s = false;
            }
         else isCorrect_s=true;
        }
        
        int modulusLength = (plength +7)/8;
        byte [] signature =new byte [(modulusLength*2) + message.length ];
        byte [] rbytes = getBytes(r);
        int rlength= rbytes.length;
        byte [] sbytes = getBytes(s);
        int slength = sbytes.length;
        System.arraycopy(rbytes, 0, signature, modulusLength - rlength, rlength);
        System.arraycopy(sbytes, 0, signature, modulusLength *2 - slength , slength);
        System.arraycopy(message, 0, signature, modulusLength *2 , message.length);
        return  signature;
        
        
        
        
        
        
        
        
        //hash the message
        //find signature
        // append message and signature
        //return appended message and signature

        //May be you will need to use certain encoding such as DER to deal with byte array

       // return null;
    }

    public static boolean verifyMessageSignature(byte[]message, PublicKey key) throws NoSuchAlgorithmException
    {
        //hash the message
        //decrypt signature using public key
        //compare message hash with decrypted signature

        ElGamalPublicKey gkey = (ElGamalPublicKey)key;
        BigInteger Y = gkey.getY();
        BigInteger P = gkey.getParameters().getP();
        BigInteger G = gkey.getParameters().getG();
        
        int modulusLength = (plength +7)/8;
        byte[] rbytes = new byte [modulusLength];
        byte[] sbytes = new byte [modulusLength];
        byte[] mbytes = new byte [message.length - (2*modulusLength)];
        System.arraycopy(message, 0, rbytes, 0, modulusLength);
        System.arraycopy(message, modulusLength, sbytes, 0, modulusLength);
        System.arraycopy(message, 2*modulusLength, mbytes, 0, (message.length - (2*modulusLength)));
        BigInteger r = new BigInteger(1,rbytes);
        BigInteger s = new BigInteger(1,sbytes);
        
        
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(mbytes);
        BigInteger hashm = new BigInteger(1,hash);
        
        BigInteger yrrs =  Y.modPow(r, P).multiply(r.modPow(s, P)).mod(P);
        BigInteger ghm = G.modPow(hashm, P);
        
        return yrrs.equals(ghm);
        
        
        


    
    }

    //Returns the message part without the signature
    public static String getMessagePart(byte[]message)
    {
        int modulusLength = (plength +7)/8;
        byte[] mbytes  = new byte [message.length - (2*modulusLength)];
        System.arraycopy(message, 2*modulusLength, mbytes, 0, (message.length - (2*modulusLength)));
        
        return new String(mbytes);
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
        return g.modPow(xa, p);
    }

    private static BigInteger generatePrivateKey(BigInteger p, BigInteger g) {
         return new BigInteger(mStreangth-1, random) ;
    }

    private static BigInteger generateG() {
        
        return new BigInteger(mStreangth-1, random) ;
    }

    private static BigInteger generateP() {
        
        BigInteger p = BigInteger.probablePrime(mStreangth, random);
        plength = p.bitLength();
        return p;
    
    }
    private static byte []  getBytes(BigInteger big)
    {
       byte[] bigbytes = big.toByteArray();
       if(big.bitLength()%8 ==0)
       {
           return bigbytes;
       }
       else 
       {
           byte [] smallerbytes = new byte [big.bitLength()/8];
           System.arraycopy(bigbytes, 1, smallerbytes, 0, smallerbytes.length);
           return smallerbytes;
       }
    }


}
