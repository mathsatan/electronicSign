import java.security.*;
import java.security.cert.Certificate;
import java.io.FileInputStream;
import java.io.IOException;

public class MyKeyStore
{
    protected KeyStore ks;

    public MyKeyStore(String keystore, String ks_pass) throws GeneralSecurityException, IOException
    {
        initKeyStore(keystore, ks_pass);
    }

    public void initKeyStore(String keystore, String ks_pass) throws GeneralSecurityException, IOException
    {
        ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream(keystore), ks_pass.toCharArray());
    }

    public Certificate[] getCertChain(String a) throws KeyStoreException
    {
        return ks.getCertificateChain(a);
    }

    public String getAlias() throws KeyStoreException
    {
        return (String) ks.aliases().nextElement();
    }

    public Certificate getCertificate(String alias) throws KeyStoreException
    {
        return ks.getCertificate(alias);
    }

    public  PublicKey getPublicKey(String alias)throws GeneralSecurityException, IOException
    {
        return getCertificate(alias).getPublicKey();
    }

    public PrivateKey getPrivateKey(String alias, String pk_pass)
            throws GeneralSecurityException, IOException
    {
        return (PrivateKey) ks.getKey(alias, pk_pass.toCharArray());
    }
}