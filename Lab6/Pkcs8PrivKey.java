import java.io.FileReader;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.PrivateKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HexFormat;

import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
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
		
		String filename = System.getProperty("user.dir") + "\\src\\unknownpriv.pem";
		char[] password = new String("cryptomadness").toCharArray();
		
		// PKCS8: 
		Pkcs8PrivKey pkcs8pk = new Pkcs8PrivKey();
		try {
			PrivateKey privKey = pkcs8pk.readEncodedEncryptedPKCS8PrivateKeyFile(filename, password);
			
			// 1.2.1
			// Get Modulus
			System.out.println(privKey);
			
			// Get Private Exponent using RSAPrivateKey class from the java.security package
			RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privKey;
	        BigInteger privateExponent = rsaPrivateKey.getPrivateExponent();
	        System.out.println("Private Exponent: " + privateExponent.toString(16));
	        System.out.println("--- End 1.2.1 ---");
			
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
            
            ASN1Primitive p8epkiAsnip = ASN1Primitive.fromByteArray(p8epki.getEncoded());
            System.out.println(ASN1Dump.dumpAsString(p8epkiAsnip, true));
            System.out.println("--- End ASN1Dump ---");
            
            // 1.3.1
            AlgorithmIdentifier p8epkiAlgID = p8epki.getEncryptionAlgorithm();
            System.out.println("Q1.3.1");
            System.out.println("Standard Algorithm OID: " + p8epkiAlgID.getAlgorithm());
            
            EncryptedPrivateKeyInfo javaEpki = new EncryptedPrivateKeyInfo(p8epki.getEncoded());
            String algName = javaEpki.getAlgName();
            System.out.println("Standard Algorithm Name: " + algName);
            System.out.println("--- End Q1.3.1 ---");
            
            // 1.3.2
            AlgorithmParameters algParams = javaEpki.getAlgParameters();
            System.out.println("Q1.3.2");
            System.out.println(algParams.getAlgorithm());
            System.out.println("Pseudo-random function algorithm name and Cipher algorithm name: " + algParams.toString());
            System.out.println("--- End Q1.3.2 ---");
            
            if (algName.equals("PBES2")) {
            	// 1.3.3
            	PBEParameterSpec pbeps = algParams.getParameterSpec(PBEParameterSpec.class);
            	byte[] salt = pbeps.getSalt();
            	System.out.println("Q1.3.3");
            	System.out.println("Salt: " + HexFormat.of().formatHex(salt));
            	System.out.println("Iteration Count: " + pbeps.getIterationCount());
            	System.out.println("--- End Q1.3.3 ---");
            	
                // 1.3.4
                System.out.println("Q1.3.4");
                AlgorithmParameterSpec aps = pbeps.getParameterSpec();
                if(aps instanceof IvParameterSpec) {
                	IvParameterSpec ivs = (IvParameterSpec)aps;
                	byte[] iv = ivs.getIV();
                	System.out.println("IV: " + HexFormat.of().formatHex(iv));
                	System.out.println("--- End Q1.3.4 ---");
                }
            }
			
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