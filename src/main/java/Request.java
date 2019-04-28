import java.io.Serializable;
import java.security.PublicKey;

public class Request implements Serializable {


    public String subjectName;
    public PublicKey key;
    public String type;

    Request(String subjectName,PublicKey key,String type)
    {
        this.subjectName=subjectName;
        this.type = type;
        this.key=key;


    }


}
