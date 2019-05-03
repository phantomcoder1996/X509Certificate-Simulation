import org.bouncycastle.jce.interfaces.ElGamalPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public class Sender extends Client{


    public Sender(String name) {
        super(name);
    }

    byte[] createMessage(String content, PublicKey key, PrivateKey k)
    {

        //TODO:Sign the message using ELGamal Algorithm (Uncomment when Reem finishes)


        try {
            byte[] signed = ElGammalDS.signMessage(content.getBytes(),k);


        //byte[] signed = content.getBytes();


        //Encrypt the message using RSA

            byte[] encrypted = RSAEncryption.encrypt(signed,key);

            return encrypted;
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null; //if any error has occured

    }



    public static void main(String[]args)
    {
       Sender Alice = new Sender("Alice");
        //Read trusted certificate authority's certificate
        System.out.printf("Reading Certificate of trusted certificate authority\n");
        Alice.readTrustedCACertificate();

        //Send CSR to CA to create certificate

        Socket socket = null;
        try {
            socket = new Socket("localhost", 9898);
            Request CSR = new Request(Alice.subjectName,Alice.RSApair.getPublic(),"RSA");
            System.out.printf("Alice creates CSR for her RSA public key\n");
            System.out.printf("Alice public key = ");
            System.out.println(Alice.RSApair.getPublic());

            ObjectOutputStream objStream = new ObjectOutputStream(socket.getOutputStream());
            objStream.writeObject(CSR);
            //TODO: Create CSR for ELGamalCertificate as well and uncomment(Reem Gody)
            ElGamalRequest CSR2 = new ElGamalRequest(Alice.subjectName,((ElGamalPublicKey)Alice.ElGamalPair.getPublic()).getY(),((ElGamalPublicKey)Alice.ElGamalPair.getPublic()).getParams().getG(),((ElGamalPublicKey)Alice.ElGamalPair.getPublic()).getParams().getP(),"ElGamal");
            System.out.printf("Alice creates CSR for her ElGamal public key\n");
            System.out.printf("Alice public key = ");
            System.out.println(Alice.ElGamalPair.getPublic());
            objStream.writeObject(CSR2);


            objStream.close();
            socket.close();

            //Now Contact BoB and send him a message
            //First Get Bob's public key from CA
            X509Certificate BobRSACert =  Alice.findCertificate("Bob","RSA");


            //Second validate the certificate
            if(!Alice.validateCertificate(BobRSACert))
            {
                System.out.printf("Certificate is not valid\n");
            }
            else if(!Alice.verifyCertificate(BobRSACert))
            {
                System.out.printf("Certificate is not verified\n");
                //If valid in terms of date, verify it's from certificate authority (Not fake)
            }
            else { //Certificate is valid and verified
                System.out.printf("Certificate is valid and verified\n");

                socket = new Socket("localhost", 9899);
                String message = "I want to graduate.......please :'(.";
                System.out.printf("Alice sends a message to Bob: %s", message);
                byte[] encrypted = Alice.createMessage(message, BobRSACert.getPublicKey(),Alice.ElGamalPair.getPrivate());

                OutputStream socketOutputStream = socket.getOutputStream();
                socketOutputStream.write(encrypted);

                //End of communication
                socket.close();

            }






        } catch (IOException e) {
            e.printStackTrace();
        }


    }
}
