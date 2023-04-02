import java.io.FileReader;
import java.security.Security;

import javax.crypto.EncryptedPrivateKeyInfo;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;

public class GetPemInfo 
{
	public static void main(String[] args) 
	{
		if (Security.getProvider("BC") == null) {
			Security.addProvider(new BouncyCastleProvider());
        }
		
		// Get Pem File
		String filename = System.getProperty("user.dir") + "\\src\\unknownpriv.pem";
		
        try {
        	// Read Pem File using PEMParser
            PEMParser pemParser = new PEMParser(new FileReader(filename));
            Object o = pemParser.readObject();
            if (o instanceof PKCS8EncryptedPrivateKeyInfo) {
            	
                // 1.3.1 Standard algorithm OID
                PKCS8EncryptedPrivateKeyInfo p8epki = (PKCS8EncryptedPrivateKeyInfo) o;
                System.out.println("Q1.3.1. Standard algorithm OID: " + p8epki.getEncryptionAlgorithm().getAlgorithm());

                // 1.3.1 Standard algorithm name
                // https://www.bouncycastle.org/docs/pkixdocs1.5on/org/bouncycastle/pkcs/PKCS8EncryptedPrivateKeyInfo.html#PKCS8EncryptedPrivateKeyInfo-byte:A-
                EncryptedPrivateKeyInfo javaEpki = new EncryptedPrivateKeyInfo(p8epki.getEncoded());
                System.out.println("Q1.3.1. Standard algorithm name: " + javaEpki.getAlgName());
                
                
                // https://www.rfc-editor.org/rfc/rfc8018
                // 1.3.2 Pseudo-random function algorithm: HmacSHA256 (1.2.840.113549.2.9)
                // 1.3.2 Cipher algorithm name: AES256-CBC (2.16.840.1.101.3.4.1.42)
                System.out.println("Q1.3.2. Cipher Algorithm Name: " + javaEpki.getAlgParameters());
                // 1.3.3 Salt in hex: bf7d9ceb82d23ae0
                // 1.3.3 Iteration count: 2048
                // 1.3.4 IV in Hex (6d49b1c7f014de4818c4fa2f458d694a)
                System.out.println("Q1.3.3., Q.1.3.4. Parameters: " + p8epki.getEncryptionAlgorithm().getParameters());
                
                // 1.3.5 Mode of operation: AES-CBC
            
                // 1.3.5 Padding: 16
                // https://www.rfc-editor.org/rfc/rfc8018#page-32
                
                // Using ASN1 Dump
                ASN1Primitive p8epkiAsnip = ASN1Primitive.fromByteArray(p8epki.getEncoded());
                System.out.println(ASN1Dump.dumpAsString(p8epkiAsnip, true));
                
            }
        }
        catch (Exception e) {
            System.out.println(e);
        }
	}
}