import org.bouncycastle.jce.interfaces.ElGamalPublicKey;

import java.io.EOFException;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;

public class Client {


    protected X509Certificate trustedCA; //Certificate authority certificate
    protected KeyPair RSApair;
    protected KeyPair ElGamalPair;
    protected String subjectName;

    public Client(String name)
    {
        this.subjectName = name;
        try {
            RSApair = RSAEncryption.generateRSAKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }

        //TODO: Generate ElGamalKeyPair as well and uncomment (Reem Gody)
        ElGamalPair = ElGammalDS.generateElGamalKeyPair();

        System.out.println("Elgamal publick key");
        System.out.println(((ElGamalPublicKey)ElGamalPair.getPublic()).getY());
        System.out.println(((ElGamalPublicKey)ElGamalPair.getPublic()).getParams().getP());
        System.out.println(((ElGamalPublicKey)ElGamalPair.getPublic()).getParams().getG());
    }


    public void readTrustedCACertificate()
    {
        String CACertificateFileName = "CACertificate.txt";
        try {
            ObjectInputStream objIstream = new ObjectInputStream(new FileInputStream(CACertificateFileName));
            Certificate trustedCACert = (Certificate)objIstream.readObject();
            trustedCA = trustedCACert.certificate;

            System.out.print("Trusted certificate Auth public key = ");
            System.out.println(trustedCA.getPublicKey());
            objIstream.close();


        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    public X509Certificate findCertificate(String subjectName,String type)
    {
        String CertificatesFileName = "RSACertificates.txt";
        if(type.equals("ElGamal"))
        {
            CertificatesFileName = "ElGamalCertificates.txt";
        }



        ObjectInputStream objIstream= null;
        try {
            objIstream = new ObjectInputStream(new FileInputStream(CertificatesFileName));
            String subjectDN="";
            while(true)
            {
                Certificate c = (Certificate) objIstream.readObject();
                subjectDN=(c.subjectName);
                if(subjectDN.equals(subjectName)) //You have found subject in file
                {
                    objIstream.close();
                    return c.certificate;
                }

            }


    } catch (EOFException e)
    {
        System.out.println("EOF");
        try {
            objIstream.close();
        } catch (IOException e1) {
            e1.printStackTrace();
        }

    } catch (IOException e) {
        e.printStackTrace();
    } catch (ClassNotFoundException e) {
        e.printStackTrace();
    }
    return null; //if you haven't found the certificate
    }



    public boolean validateCertificate(X509Certificate certificate)
    {
        System.out.printf("Validating certificate of %s\n",certificate.getSubjectDN().toString().substring(3));


        try
        {
            certificate.checkValidity(new Date()); //Make sure that the certificate is valid


        } catch (CertificateNotYetValidException e) {

            return false;
        } catch (CertificateExpiredException e) {


            return false;
        }
        return true;
    }

    public boolean verifyCertificate(X509Certificate certificate)
    {
        //Get the CA's public key
        PublicKey CAkey = trustedCA.getPublicKey();
        try
        {
            certificate.verify(CAkey);
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {

            return false; //The certificate was not signed by the authority
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }

        return true;
    }









}
