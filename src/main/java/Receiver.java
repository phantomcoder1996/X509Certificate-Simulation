import org.bouncycastle.jce.interfaces.ElGamalPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

public class Receiver extends Client{


    public Receiver(String name) {
        super(name);
    }

    public static  void main(String[] args)
    {
        Receiver Bob = new Receiver("Bob");
        //Read trusted certificate authority's certificate
        System.out.printf("Reading Certificate of trusted certificate authority\n");
        Bob.readTrustedCACertificate();
        Socket socket = null;

        try {
            socket = new Socket("localhost", 9898);

            Request CSR = new Request(Bob.subjectName,Bob.RSApair.getPublic(),"RSA");
            System.out.printf("Bob creates CSR for his RSA public key\n");
            System.out.printf("Bob public key = ");
            System.out.println(Bob.RSApair.getPublic());
            ObjectOutputStream objStream = new ObjectOutputStream(socket.getOutputStream());
            objStream.writeObject(CSR);

            //TODO: Create CSR for ELGamalCertificate as well and Uncomment (Reem Gody)

            System.out.println(((ElGamalPublicKey)Bob.ElGamalPair.getPublic()).getY());
            System.out.println(((ElGamalPublicKey)Bob.ElGamalPair.getPublic()).getParams().getP());
            System.out.println(((ElGamalPublicKey)Bob.ElGamalPair.getPublic()).getParams().getG());
            ElGamalRequest CSR2 = new ElGamalRequest(Bob.subjectName,((ElGamalPublicKey)Bob.ElGamalPair.getPublic()).getY(),((ElGamalPublicKey)Bob.ElGamalPair.getPublic()).getParams().getG(),((ElGamalPublicKey)Bob.ElGamalPair.getPublic()).getParams().getP(),"ElGamal");
            System.out.printf("Bob creates CSR for his ElGamal public key\n");
            System.out.printf("Bob public key = ");
            System.out.println(Bob.ElGamalPair.getPublic());
            objStream.writeObject(CSR2);


            objStream.close();
            socket.close();

            System.out.println("Bob waiting to receive messages ...");

            ServerSocket server = new ServerSocket(9899);
            socket = server.accept();

            InputStream socketInputStream = socket.getInputStream();
            byte[] tempMessage = new byte[10000];
            byte[] message;
            int cnt = socketInputStream.read(tempMessage);
            message = new byte[cnt];
            for(int i=0;i<cnt;i++)
            {
                message[i]=tempMessage[i];
            }
            byte[] decrypted = RSAEncryption.decrypt(message,Bob.RSApair.getPrivate());
            System.out.printf("Bob received a message\n");
            System.out.printf("Decrypted message = %s\n",decrypted);

            //TODO: uncomment this when Reem finishes (Reem Gody)
            //First : Get Alice's public key certificate for elGamal signature
            X509Certificate AliceElGamalCert = Bob.findCertificate("Alice","ElGamal");
            //Second : validate the certificate
            if(!Bob.validateCertificate(AliceElGamalCert))
            {
                System.out.printf("Certificate is not valid\n");
            }
            else if(!Bob.verifyCertificate(AliceElGamalCert))
            {
                System.out.printf("Certificate is not verified\n");
                //If valid in terms of date, verify it's from certificate authority (Not fake)
            }
            else { //Certificate is valid and verified
                System.out.printf("Certificate is valid and verified\n");
                //use Alice ElGamal publicKey to verify the signature
              
                boolean verified =ElGammalDS.verifyMessageSignature(decrypted,AliceElGamalCert.getPublicKey());

                if(verified) //correct signature
                {
                    System.out.println("Correct Signature\n");

                    //Get Message
                    String msg = ElGammalDS.getMessagePart(decrypted);
                    System.out.printf("Restored message: %s\n",msg);

                }
                else
                {
                    System.out.println("Incorrect Signature\n");
                }

            }

            //End of communication
            socket.close();
            server.close();





        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }


    }

}
