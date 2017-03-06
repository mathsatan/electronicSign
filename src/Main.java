import com.itextpdf.text.DocumentException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;
import java.security.Security;

public class Main
{
    public static String PATH = "res/conf.properties";

    public static void main(String[] args) throws IOException, DocumentException, GeneralSecurityException
    {
        String src = null;
        BufferedReader appInput = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("Type PDF file name that you want to sign or press enter to generate new test file...");
        try
        {
           src = appInput.readLine().trim();
        }
        catch (IOException e1)
        {
            System.out.println("Error: " + e1.getMessage());
        }

        Security.addProvider(new BouncyCastleProvider());

        DigitalSignPDF signatures = new DigitalSignPDF();
        try
        {
            signatures.loadProperties(PATH);
        } catch (FileNotFoundException e)
        {
            System.out.println("Error: Resource folder not found!; " + e.getMessage());
            System.exit(0);
        }
        if (src.isEmpty())
        {
            src = "original.pdf";
            signatures.createPdf(src);
        }
        String dest1 = src.substring(0, src.length() - 4) + "_signed1.pdf";
        String dest2 = src.substring(0, src.length() - 4) + "_signed2.pdf";
        try
        {
            signatures.signPdfFirstTime(src, dest1);
            signatures.signPdfSecondTime(dest1, dest2);
            signatures.verifySignatures(dest2);
        }catch (IOException e)
        {
            System.out.println("Error: " + e.getMessage());
        }
        //signatures.extractFirstRevision();
    }

}
