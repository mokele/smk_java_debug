import smarkets.eto.EtoPiqi;
import smarkets.seto.SetoPiqi;
import java.io.*;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.TrustManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import com.google.protobuf.CodedOutputStream;
import com.google.protobuf.ByteString;

public class Go
{
    public static void main(String[] args)
    {
        SetoPiqi.Payload payload = SetoPiqi.Payload.newBuilder()
            .setType(SetoPiqi.PayloadType.PAYLOAD_LOGIN)
            .setEtoPayload(
                EtoPiqi.Payload.newBuilder()
                    .setType(EtoPiqi.PayloadType.PAYLOAD_LOGIN)
                    .setSeq(1)
                    .build()
            )
            .setLogin(
                SetoPiqi.Login.newBuilder()
                    .setUsername("you@api-sandbox.smarkets.com")
                    .setPassword("*****")
                    .build()
            )
            .build();
        System.out.println(payload.toString());
        try
        {
            SSLSocketFactory fac = trustAll().getSocketFactory();
            SSLSocket ssl = (SSLSocket)fac.createSocket("api-dev.corp.smarkets.com", 3701);
            CodedOutputStream co = CodedOutputStream.newInstance(ssl.getOutputStream());
            System.out.println("Logging in...");
            
            int byteCount = payload.getSerializedSize();
            co.writeRawBytes(encodeVarint(byteCount));
            payload.writeTo(co);
            co.writeRawBytes(padding(byteCount));
            co.flush();
            ssl.getOutputStream().flush();
            BufferedReader in = new BufferedReader(new InputStreamReader(ssl.getInputStream()));
            while (!in.ready()) {}
            System.out.println("Reading...");
            System.out.println(in.read()); // Read one line and output it
            System.out.println(in.read()); // Read one line and output it
            System.out.println(in.read()); // Read one line and output it
            // todo: properly read and deframe the input
            System.out.print("'\n");
            in.close();
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }
    public static byte[] padding(int byteCount) throws IOException
    {
        //padding = '\x00' * max(0, 3 - byte_count);
        ByteString.Output out = ByteString.newOutput();
        for(int i = 0; i < Math.max(0, 3 - byteCount); i++)
        {
            out.write(0x00);
        }
        return out.toByteString().toByteArray();
    }

    public static byte[] encodeVarint(int value) throws IOException
    {
        ByteString.Output out = ByteString.newOutput();
        int bits = value & 0x7f;
        value = value >> 7;
        while(value > 0)
        {
            out.write(0x80 | bits);
            bits = value & 0x7f;
            value = value >> 7;
        }
        out.write(bits);
        return out.toByteString().toByteArray();
    }
    
    public static SSLContext trustAll() throws Exception
    {
        // cert not checked for now on sandbox
        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[]{
            new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
                public void checkClientTrusted(
                    java.security.cert.X509Certificate[] certs, String authType) {
                }
                public void checkServerTrusted(
                    java.security.cert.X509Certificate[] certs, String authType) {
                }
            }
        };

        // Install the all-trusting trust manager
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        return sc;
    }
}
