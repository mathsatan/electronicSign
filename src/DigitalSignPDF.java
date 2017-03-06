import java.io.*;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Properties;

import com.itextpdf.text.exceptions.InvalidPdfException;
import com.itextpdf.text.pdf.codec.Base64;

import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Image;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfWriter;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.CertificateInfo;
import com.itextpdf.text.pdf.security.CertificateVerification;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.PrivateKeySignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.VerificationException;

public class DigitalSignPDF
{
    MyKeyStore mKeyStore;
        // Some properties used when signing
    public static Properties properties = new Properties();

    public void loadProperties(String path) throws FileNotFoundException, IOException
    {
        properties.load(new FileInputStream(path));
    }

    /**
     * Creates a PDF document.
     * @param filename the path to the new PDF document
     * @throws DocumentException
     * @throws IOException
     */
    public void createPdf(String filename) throws IOException, DocumentException
    {
        Document document = new Document();
        PdfWriter.getInstance(document, new FileOutputStream(filename));
        document.open();
        document.add(new Paragraph("This is example pdf"));
        document.close();
    }

    /**
     * Manipulates a PDF file src with the file dest as result
     * @param src the original PDF
     * @param dest the resulting PDF
     * @throws IOException
     * @throws DocumentException
     * @throws GeneralSecurityException
     */
    public void signPdfFirstTime(String src, String dest)
            throws IOException, DocumentException, GeneralSecurityException
    {
        String key_password = properties.getProperty("PASSWORD");
        mKeyStore = new MyKeyStore(properties.getProperty("KS_PATH") + "ks1.jks", properties.getProperty("PASSWORD"));
        String alias = mKeyStore.getAlias();
        Certificate[] chain = mKeyStore.getCertChain(alias);

            // reader and stamper
        PdfReader reader = new PdfReader(src);
        FileOutputStream os = new FileOutputStream(dest);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
            // appearance
        PdfSignatureAppearance appearance = stamper .getSignatureAppearance();
        appearance.setImage(Image.getInstance(properties.getProperty("LOGO")));
        appearance.setReason("I've written this");
        appearance.setLocation("Europe");
        appearance.setVisibleSignature(new Rectangle(100, 720, 150, 770), 1, "first");
            // digital signature
        ExternalSignature es = new PrivateKeySignature(mKeyStore.getPrivateKey(alias, key_password), "SHA-256", "BC");
        ExternalDigest digest = new BouncyCastleDigest();
        MakeSignature.signDetached(appearance, digest, es, chain, null, null, null, 0, MakeSignature.CryptoStandard.CMS);
    }

    /**
     * Manipulates a PDF file src with the file dest as result
     * @param src the original PDF
     * @param dest the resulting PDF
     * @throws IOException
     * @throws DocumentException
     * @throws GeneralSecurityException
     */
    public void signPdfSecondTime(String src, String dest)
            throws IOException, DocumentException, GeneralSecurityException
    {
        String key_password = "password";

        mKeyStore = new MyKeyStore(properties.getProperty("KS_PATH") + "ks2.jks", "password");
        String alias = mKeyStore.getAlias();
        Certificate[] chain = mKeyStore.getCertChain(alias);

            // reader / stamper

        PdfReader reader = new PdfReader(src);
        FileOutputStream os = new FileOutputStream(dest);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0', null, true);
            // appearance
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason("I'm approving this");
        appearance.setLocation("Europe");
        appearance.setVisibleSignature(new Rectangle(160, 720, 210, 770), 1, "second");
            // digital signature
        ExternalSignature es = new PrivateKeySignature(mKeyStore.getPrivateKey(alias, key_password), "SHA-256", "BC");
        ExternalDigest digest = new BouncyCastleDigest();
        MakeSignature.signDetached(appearance, digest, es, chain, null, null, null, 0, MakeSignature.CryptoStandard.CMS);
    }

    /**
     * Verifies the signatures of a PDF we've signed twice.
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public void verifySignatures(String signedDoc)
            throws GeneralSecurityException, IOException
    {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, null);
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        FileInputStream is1 = new FileInputStream(properties.getProperty("CERT_PATH") + "cert1.crt");
        X509Certificate cert1 = (X509Certificate) cf.generateCertificate(is1);
        ks.setCertificateEntry("alias1", cert1);
        FileInputStream is2 = new FileInputStream(properties.getProperty("CERT_PATH") + "cert2.crt");
        X509Certificate cert2 = (X509Certificate) cf.generateCertificate(is2);
        ks.setCertificateEntry("alias2", cert2);

        PrintWriter out = new PrintWriter(new FileOutputStream("verify.txt"));

        PdfReader reader = new PdfReader(signedDoc);
        AcroFields af = reader.getAcroFields();
        ArrayList<String> names = af.getSignatureNames();
        for (String name : names)
        {
            out.println("Signature name: " + name);
            out.println("Signature covers whole document: " + af.signatureCoversWholeDocument(name));
            out.println("Document revision: " + af.getRevision(name) + " of " + af.getTotalRevisions());
            PdfPKCS7 pk = af.verifySignature(name);
            Calendar cal = pk.getSignDate();
            Certificate[] pkc = pk.getCertificates();
            out.println("Subject: " + CertificateInfo.getSubjectFields(pk.getSigningCertificate()));
            out.println("Revision modified: " + !pk.verify());
            List<VerificationException> errors = CertificateVerification.verifyCertificates(pkc, ks, null, cal);
            if (errors.size() == 0)
                out.println("Certificates verified against the KeyStore");
            else
                out.println(errors);
        }
        out.flush();
        out.close();
    }

    /**
     * Extracts the first revision of a PDF we've signed twice.
     * @throws IOException

    public void extractFirstRevision() throws IOException
    {
        PdfReader reader = new PdfReader(SIGNED2);
        AcroFields af = reader.getAcroFields();
        FileOutputStream os = new FileOutputStream(REVISION);
        byte bb[] = new byte[1028];
        Base64.InputStream ip = (Base64.InputStream) af.extractRevision("first");
        int n = 0;
        while ((n = ip.read(bb)) > 0)
            os.write(bb, 0, n);
        os.close();
        ip.close();
    }
    */

}
