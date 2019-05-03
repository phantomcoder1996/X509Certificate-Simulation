import org.bouncycastle.jcajce.provider.asymmetric.elgamal.BCElGamalPublicKey;
import org.bouncycastle.jce.interfaces.ElGamalPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;

public class RSAEncryption {



    public static byte[] encrypt(byte[] text,PublicKey key) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {

        byte[] cipherText = null;
        //
        // get an RSA cipher object and print the provider
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        // encrypt the plaintext using the public key
        cipher.init(Cipher.ENCRYPT_MODE, key);

        cipherText = cipher.doFinal(text);
        //return new String(cipherText,"UTF8");
        return cipherText;


    }

    public static byte[] decrypt(byte[] text,PrivateKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
        byte[] plainText = null;
        //
        // get an RSA cipher object and print the provider
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        // decrypt the plaintext using the private key
        cipher.init(Cipher.DECRYPT_MODE, key);

        plainText = cipher.doFinal(text);
        return plainText;
    }



    public static KeyPair generateRSAKeyPair() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
        kpGen.initialize(1024, new SecureRandom());
        return kpGen.generateKeyPair();
    }




    public static void main(String[] args)
    {
        try {


            KeyPair kp = generateRSAKeyPair();
            PublicKey pk = kp.getPublic();
            PrivateKey prk = kp.getPrivate();

            String message = "I am very sad";
            byte[] result;
            result=encrypt(message.getBytes(),pk);
            byte[] restored = decrypt(result,prk);
//            long p=System.currentTimeMillis();
//            g,x;
//            ElGamalParameterSpec spec = new ElGamalParameterSpec(p,g);
//
//            ElGamalPublicKey key;


            System.out.print(new String(result));



        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
