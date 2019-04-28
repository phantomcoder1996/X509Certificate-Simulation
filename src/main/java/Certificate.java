import org.bouncycastle.x509.X509V1CertificateGenerator;

import javax.security.auth.x500.X500Principal;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

public class Certificate implements Serializable{


    X509Certificate certificate;
    String subjectName;

    Certificate(X509Certificate cert)
    {
        this.certificate = cert;
        this.subjectName = cert.getSubjectDN().toString().substring(3);
    }







}
