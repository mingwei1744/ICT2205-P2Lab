import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.Security;

import javax.crypto.EncryptedPrivateKeyInfo;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;

public class Pkcs8Unknown 
{
	public static void main(String[] args) 
	{
		if (Security.getProvider("BC") == null) {
			Security.addProvider(new BouncyCastleProvider());
        }
		// Get Pem File
		String filename = System.getProperty("user.dir") + "\\src\\unknownpriv.pem";
		
		// Get Password File (ict2205)
		String passwordFile = System.getProperty("user.dir") + "\\src\\passwords.txt";
		
		Pkcs8PrivKey pkcs8pk = new Pkcs8PrivKey();
		
		try (BufferedReader br = new BufferedReader(new FileReader(passwordFile))) {
			String password;
			// Read list of password from file and decrypt Pem key
			while ((password = br.readLine()) != null) {
				// Attempt decrypt using each password in text file
				try {
					PrivateKey privKey = pkcs8pk.readEncodedEncryptedPKCS8PrivateKeyFile(filename, password.toCharArray());
					System.out.println("Password found: " + password);
					break;
				}
				
				// Since wrong password returns an exception of "unable to read encrypted data: Error finalising cipher"
				catch (Exception e) {
					System.out.println("No Password Found");
				}
			}
		} catch (IOException e) {
			System.out.println("Error reading password file: " + e);
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
