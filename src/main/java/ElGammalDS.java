/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

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
   static int mStreangth = 300;
   static int plength;
   public static BigInteger TWO = new BigInteger("2");
   public static int  lengthS=38,lengthr=38;


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
        BigInteger hashm = new BigInteger(hash);
        while(!isCorrect_s)
        { BigInteger PminusOne = P.subtract(BigInteger.ONE);
        do
        {
            
            k = new BigInteger(P.bitLength()-1,new SecureRandom());
            
        } while(k.gcd(PminusOne).equals(BigInteger.ONE)== false);
        
         r = G.modPow(k, P);
        
       
        
        BigInteger top = hashm.subtract(Xm.multiply(r)).mod(PminusOne);
        s = top.multiply(k.modPow(BigInteger.ONE.negate(), PminusOne)).mod(PminusOne);
         if((s.equals(BigInteger.ZERO))){
                isCorrect_s = false;
            }
         else isCorrect_s=true;
        }
        
        //int modulusLength = (plength +7)/8;
        
        byte [] rbytes = r.toByteArray();
        lengthr= rbytes.length;
        byte [] sbytes =s.toByteArray();
        lengthS= sbytes.length;
        byte [] signature =new byte [lengthr+ lengthS+ message.length ];
        System.arraycopy(rbytes, 0, signature, 0, lengthr);
        System.arraycopy(sbytes, 0, signature,lengthr , lengthS);
        System.arraycopy(message, 0, signature, lengthr+ lengthS , message.length);
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
        
        //int modulusLength = (plength +7)/8;
        byte[] rbytes = new byte [lengthr];
        byte[] sbytes = new byte [lengthS];
        byte[] mbytes = new byte [message.length - (lengthS+lengthr)];
        System.arraycopy(message, 0, rbytes, 0, lengthr);
        System.arraycopy(message, lengthr, sbytes, 0, lengthS);
        System.arraycopy(message, (lengthS+lengthr), mbytes, 0, (message.length - (lengthS+lengthr)));
        BigInteger r = new BigInteger(rbytes);
        BigInteger s = new BigInteger(sbytes);
        
        
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(mbytes);
        BigInteger hashm = new BigInteger(hash);
        
        BigInteger yrrs =  Y.modPow(r, P).multiply(r.modPow(s, P)).mod(P);
        BigInteger ghm = G.modPow(hashm, P);
        
        return yrrs.equals(ghm);
        
        
        


    
    }

    //Returns the message part without the signature
    public static String getMessagePart(byte[]message)
    {
        //int modulusLength = (plength +7)/8;
        byte[] mbytes  = new byte [message.length - (lengthS+lengthr)];
        System.arraycopy(message,(lengthS+lengthr), mbytes, 0, message.length - (lengthS+lengthr));
        
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

    public static GamalPublicKey wrapKey(BigInteger Y , BigInteger G, BigInteger P)
    {
        ElGamalParameterSpec spec = new ElGamalParameterSpec(P,G);

        ElGamalPublicKeySpec pbls = new ElGamalPublicKeySpec(Y,spec);
        GamalPublicKey gpk= new GamalPublicKey(pbls);
        return gpk;
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
    
    
    
     public static void main(String[] args)
    {
        try {



            KeyPair kp = generateElGamalKeyPair();
            PublicKey pk = kp.getPublic();
            PrivateKey prk = kp.getPrivate();

            System.out.println(plength);

            String message = "R";
            byte[] result;
            result=signMessage(message.getBytes(),prk);
            KeyPair rsa = RSAEncryption.generateRSAKeyPair();
            byte[] Encrypted  = RSAEncryption.encrypt(result,rsa.getPublic());
            byte[] decrypted = RSAEncryption.decrypt(Encrypted,rsa.getPrivate());

            boolean ver = verifyMessageSignature(decrypted,pk);
            String restored = getMessagePart(decrypted);


            System.out.println(restored);
            System.out.println(ver);



        } catch (Exception e) {
            e.printStackTrace();
        }
    }

  
}
