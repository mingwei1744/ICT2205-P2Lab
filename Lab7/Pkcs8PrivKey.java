import java.io.FileReader;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;

import javax.crypto.EncryptedPrivateKeyInfo;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;

public class Pkcs8PrivKey 
{
	public static void main(String[] args) 
	{
		if (Security.getProvider("BC") == null) {
			Security.addProvider(new BouncyCastleProvider());
        }
		
		String filename = System.getProperty("user.dir") + "\\src\\priv.pem";
		char[] password = new String("cryptomadness").toCharArray();
		
		Pkcs8PrivKey pkcs8pk = new Pkcs8PrivKey();
		try {
			PrivateKey privKey = pkcs8pk.readEncodedEncryptedPKCS8PrivateKeyFile(filename, password);
			
		}
		catch (Exception e) {
			System.out.println(e);
		}
	}
	
	public PrivateKey readEncodedEncryptedPKCS8PrivateKeyFile 
		   (String filename, char[] password) throws Exception 
	{
		PrivateKey privKey = null;
		
		// decode
		PEMParser pemParser = new PEMParser(new FileReader(filename));
		Object o = pemParser.readObject();
			
        if (o instanceof PKCS8EncryptedPrivateKeyInfo) {
			// decrypt
            PKCS8EncryptedPrivateKeyInfo p8epki = (PKCS8EncryptedPrivateKeyInfo) o;
			
			JcePKCSPBEInputDecryptorProviderBuilder builder =
				new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC");
            InputDecryptorProvider idp = builder.build(password);
            PrivateKeyInfo pki = p8epki.decryptPrivateKeyInfo(idp);
			
			// extract private key
			JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            privKey = converter.getPrivateKey(pki);
		}
		return privKey;
	}
}