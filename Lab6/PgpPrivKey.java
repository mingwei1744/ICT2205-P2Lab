import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.Security;

import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

public class PgpPrivKey 
{
	public static void main(String[] args) 
	{
		if (Security.getProvider("BC") == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
		
		String filename = System.getProperty("user.dir") + "\\src\\GMW_0x6657D95F_SECRET.asc";
		char[] password = new String("cryptomadness").toCharArray();
		
		PgpPrivKey pgppk = new PgpPrivKey();
		try {
			PGPPrivateKey privKey = pgppk.readEncodedEncryptedPGPPrivateKeyFile(filename, password);
			
			System.out.println(privKey);
		}
		catch (Exception e) {
			System.out.println(e);
		}
	}
	
	public PGPPrivateKey readEncodedEncryptedPGPPrivateKeyFile 
		   (String filename, char[] password) throws Exception 
	{
		PGPPrivateKey privKey = null;
			
		// decode into PGP key ring collection 
		// which can contain one or more key rings
		FileInputStream fis = new FileInputStream(filename);
		PGPSecretKeyRingCollection ringCollection = new PGPSecretKeyRingCollection
			(PGPUtil.getDecoderStream(fis), new JcaKeyFingerprintCalculator());
			
		// for simplicity, get 1st key ring from collection
		PGPSecretKeyRing keyRing = ringCollection.getKeyRings().next();
		
		// each key ring typically contains 2 key-pairs:
		// 1. master key-pair for signature which can be used long-term
		// 2. non-master key-pair for encryption which can be replaced whenever needed
		// for simplicity, get encrypted master private key
		PGPSecretKey masterKey = keyRing.getSecretKey();

		// REF: https://www.bouncycastle.org/docs/pgdocs1.5to1.8/org/bouncycastle/bcpg/S2K.html
		// PGP (RFC 4880) - String to Key (S2K)
		// 2.3.1
		S2K param = masterKey.getS2K();
		System.out.println("S2K Type: " + param.getType()); // Type 3
		System.out.println("S2K Hash Algorithm: " + param.getHashAlgorithm());  // ID 2 = SHA1
		
		// 2.3.4
		byte[] salt = param.getIV();
		System.out.println("Salt: " +  new BigInteger(1, salt).toString(16));
		System.out.println("Iteration Count: " + param.getIterationCount());
			
		// decrypt and extract master private key
		JcePBESecretKeyDecryptorBuilder builder = new JcePBESecretKeyDecryptorBuilder();
		PBESecretKeyDecryptor decryptorFac = builder.build(password);
		privKey = masterKey.extractPrivateKey(decryptorFac);
					
		return privKey;
	}
}
