import org.bouncycastle.x509.X509V1CertificateGenerator;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;



 class AppendingObjectOutputStream extends ObjectOutputStream {

    public AppendingObjectOutputStream(OutputStream out) throws IOException {
        super(out);
    }

    @Override
    protected void writeStreamHeader() throws IOException {
        // do not write a header, but reset:
        // this line added after another question
        // showed a problem with the original
        reset();
    }

}

public class CertificateAuthority {

    private static KeyPair keypair;

    static {
        try {
            keypair = RSAEncryption.generateRSAKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    ;
    private static X509V1CertificateGenerator certGen=new X509V1CertificateGenerator();;
    private static String issuerName="CN=Trusted_CA";
    public static String RSACertificatesFileName  = "RSACertificates.txt";
    public static String ElGamalCertificatesFileName = "ElGamalCertificates.txt";

//    public CertificateAuthority()
//    {
//
//        certGen = new X509V1CertificateGenerator();
//        issuerName = "CN=Trusted_CA";
//
//        try {
//            keypair = RSAEncryption.generateRSAKeyPair();
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//
//
//
//    }

    public static PublicKey getPublicKey ()
    {
        return keypair.getPublic();
    }


    public static void createSelfSignedCertificate()
    {
        //In self-signed certificates
        //issuerDN = subjectDN
        //subject publicKey = issuerPublicKey
        //Only rootCA in CA chain can have self-signed certificates

        try {
            X509Certificate CACertificate = generateV1Certificate(keypair.getPublic(),issuerName);
            Certificate cert = new Certificate(CACertificate);

            //Now save the certificate in a file to be available for communicating parties

            String CACertificateFileName = "CACertificate.txt";
            try {
                ObjectOutputStream objStream = new ObjectOutputStream(new FileOutputStream(CACertificateFileName));
                objStream.writeObject(cert);
            } catch (IOException e) {
                e.printStackTrace();
            }

        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
    }







    public static X509Certificate generateV1Certificate(PublicKey subjectPublicKey,String subjectDN) throws InvalidKeyException,
            NoSuchProviderException, SignatureException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());



        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setIssuerDN(new X500Principal(issuerName));
        certGen.setNotBefore(new Date(System.currentTimeMillis()));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000)); //Valid for one year
        certGen.setSubjectDN(new X500Principal("CN="+subjectDN));
        certGen.setPublicKey(subjectPublicKey);
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption"); // The algorithm used for signing certificate

        return certGen.generateX509Certificate(keypair.getPrivate(), "BC"); //We need private key of CA to sign the Certificate
    }

    public static void saveCertificate(X509Certificate cert,String type)
    {
        String CertificatesFileName;
        if(type.equals("RSA"))
        {
            CertificatesFileName = RSACertificatesFileName;
        }
        else
        {
            CertificatesFileName = ElGamalCertificatesFileName;
        }
        try {
            ObjectOutputStream objStream = new AppendingObjectOutputStream(new FileOutputStream(CertificatesFileName,true));

            Certificate cer = new Certificate(cert);

            objStream.writeObject(cer);
            objStream.close();


            ObjectInputStream objIStream  = new ObjectInputStream(new FileInputStream(CertificatesFileName));

            try
            {
                int i=1;
                while(true)
                {
                    Certificate c = (Certificate)objIStream.readObject();
                    System.out.print(i);
                    System.out.println(c.certificate.getSubjectDN().getName());
                    i++;
                }
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
            catch(EOFException e)
            {
                System.out.print("End of file reached\n");
            }


        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public static void initCertificateRepository()
    {
        try {
            ObjectOutputStream objStream = new ObjectOutputStream(new FileOutputStream(RSACertificatesFileName));

            //First write number of certificates
           // objStream.writeObject(new Integer(50));

            for(int i =0 ;i<2;i++)
            {
                String subjectDN = "sub"+(new Random().nextInt());
                try {
                    KeyPair pair = RSAEncryption.generateRSAKeyPair();
                    X509Certificate certificate = CertificateAuthority.generateV1Certificate(pair.getPublic(),subjectDN);
                    objStream.writeObject(new Certificate(certificate));
                } catch (Exception e) {
                    e.printStackTrace();
                }

            }
            objStream.close();

        } catch (IOException e) {
            e.printStackTrace();
        }

    }





//    public static void main(String[] args)
//    {
//
//        //CertificateAuthority CA = new CertificateAuthority();
//
//        //Create a self-signed certifcate for CA and save it in a file
//        CertificateAuthority.createSelfSignedCertificate();
//        //Create a large set of certificates and save them all in a file (For RSA)
//        String RSACertificatesFileName = "RSACertificates.txt";
//        try {
//            ObjectOutputStream objStream = new ObjectOutputStream(new FileOutputStream(RSACertificatesFileName));
//
//            //First write number of certificates
//           // objStream.writeObject(new Integer(50));
//
//            for(int i =0 ;i<50;i++)
//            {
//                String subjectDN = "sub"+(new Random().nextInt());
//                try {
//                    KeyPair pair = RSAEncryption.generateRSAKeyPair();
//                    X509Certificate certificate = CertificateAuthority.generateV1Certificate(pair.getPublic(),subjectDN);
//                    objStream.writeObject(new Certificate(certificate));
//                } catch (Exception e) {
//                    e.printStackTrace();
//                }
//
//            }
//
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//
//        //Only for checking if Certificates were written correctly
//        ObjectInputStream objIstream= null;
//        try {
//            objIstream = new ObjectInputStream(new FileInputStream(RSACertificatesFileName));
//           // Integer num = (Integer)objIstream.readObject();
//            int i=1;
//            while(true)
//            {
//                Certificate c = (Certificate) objIstream.readObject();
//                System.out.print(i);
//                System.out.print(" ");
//                System.out.println(c.certificate.getSubjectDN().toString());
//                i++;
//            }
//
//
//        } catch (EOFException e)
//        {
//            System.out.println("EOF");
//            try {
//                objIstream.close();
//            } catch (IOException e1) {
//                e1.printStackTrace();
//            }
//
//        } catch (IOException e) {
//            e.printStackTrace();
//        } catch (ClassNotFoundException e) {
//            e.printStackTrace();
//        }
//
//
//        //Create a large set of certificates and save them all in a file (For ElGamal)
//
//
//
//    }



    public static void main(String[] args) throws IOException {

        System.out.println("The CA is running now");
        int clientNumber = 0;
        ServerSocket listener = new ServerSocket(9898);
        Socket socket;

        //First : Create self signed certificate

        createSelfSignedCertificate();

        //Second : Generate certificates
        initCertificateRepository();


        //Third : Listen to CSRs from clients
        try {
            while (true) {

                socket = listener.accept();
                ObjectInputStream objIstream = new ObjectInputStream(socket.getInputStream());

                Request CSR = (Request)objIstream.readObject();
                System.out.printf("%s requested a certificate for RSA public key\n",CSR.subjectName);
                System.out.printf("Public key of %s = ",CSR.subjectName);
                System.out.println(CSR.key);


                //Creating certificate and storing it in database
                System.out.printf("Generating a certificate for %s\n",CSR.subjectName);
                X509Certificate certificate = generateV1Certificate(CSR.key,CSR.subjectName);

                //storing it in database
                System.out.printf("Saving certificate for %s\n",CSR.subjectName);
                saveCertificate(certificate,CSR.type);


                //TODO : (REEM Gody) Uncomment this when Reem finishes

//                CSR = (Request)objIstream.readObject();
//                System.out.printf("%s requested a certificate for ElGamal public key \n",CSR.subjectName);
//                System.out.printf("Public key of %s = ",CSR.subjectName);
//                System.out.println(CSR.key);
//
//
//                //Creating certificate and storing it in database
//                System.out.printf("Generating a certificate for %s\n",CSR.subjectName);
//                certificate = generateV1Certificate(CSR.key,CSR.subjectName);
//
//                //storing it in database
//                System.out.printf("Saving certificate for %s\n",CSR.subjectName);
//                saveCertificate(certificate,CSR.type);



            }
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } finally {
            listener.close();
        }


    }


}
