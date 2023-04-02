import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Collection;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.io.pem.PemObject;

public class RsaPss
{
    public static void main(String[] args) throws Exception
    {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        
        // 1.4.1 Verify the signature to determine which is the correct message that is being signed.
        String unknown = System.getProperty("user.dir") + "\\src\\unknown-sigdata.p7m";
        
        for (int i = 1; i < 5; i++) {
        	String msg = System.getProperty("user.dir") + String.format("\\src\\msg%d.txt", i);
        	
        	File dataFile = new File(msg);
            byte[] dataBytes = new byte[(int) dataFile.length()];
            FileInputStream dataInputStream = new FileInputStream(dataFile);
            dataInputStream.read(dataBytes);
            dataInputStream.close();
            
            // Read detached signature file
            byte[] signatureBytes = getDetachedSignatureBytes(new File(unknown));
            

        	// INIT pkcs7 CMS signed-data type
        	CMSProcessableByteArray signedContent = new CMSProcessableByteArray(dataBytes);
        	CMSSignedData cmsSignedData = new CMSSignedData(signedContent, signatureBytes);
        	
        	// Get signer
        	SignerInformationStore signers = cmsSignedData.getSignerInfos();
        	SignerInformation signer = signers.getSigners().iterator().next();
        	
        	// Iterate to search signer cert to get public key
        	Store<X509CertificateHolder> certStore = cmsSignedData.getCertificates();
    		Collection<X509CertificateHolder> certCollection = certStore.getMatches((Selector<X509CertificateHolder>)signer.getSID());
        	X509CertificateHolder certHolder = certCollection.iterator().next();
        	
        	boolean verifyStatus;
			try {
				verifyStatus = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certHolder));
				if (verifyStatus == true) {
	        		System.out.println(String.format("MESSAGE VERIFIED: msg%d is the correct message", i));
	        	}
			} catch (OperatorCreationException e) {
				e.printStackTrace();
				continue;
			} catch (CertificateException e) {
				e.printStackTrace();
				continue;
			} catch (CMSException e) {
				//e.printStackTrace();
				System.out.println(String.format("MESSAGE NOT MATCH: msg%d is NOT the correct message", i));
				continue;
			}
        	
        }
        
    }
    
    // Function to compare data with detached signature
    public boolean verifyDataWithDetachedSignatureInPKCS7(byte[] data, byte[] detachedSig) throws Exception 
    {
    	// Init pkcs7 CMS signed-data type
    	CMSProcessableByteArray signedContent = new CMSProcessableByteArray(data);
    	CMSSignedData cmsSignedData = new CMSSignedData(signedContent, detachedSig);
    	
    	// Get signer
    	SignerInformationStore signers = cmsSignedData.getSignerInfos();
    	SignerInformation signer = signers.getSigners().iterator().next();
    	
    	// Iterate to search signer cert to get public key
    	Store<X509CertificateHolder> certStore = cmsSignedData.getCertificates();
    	Collection<X509CertificateHolder> certCollection = 
    			certStore.getMatches((Selector<X509CertificateHolder>)signer.getSID());
    	X509CertificateHolder certHolder = certCollection.iterator().next();
    	
    	boolean verifyStatus = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certHolder));
    	
    	return verifyStatus;
    }
    
    // Function to get detached signature in Bytes
    private static byte[] getDetachedSignatureBytes(File signatureFile) throws Exception {
        // Load the PEM-encoded signature file into a PemReader object
        try (PEMParser pemParser = new PEMParser(new FileReader(signatureFile))) {
            PemObject pemObject = pemParser.readPemObject();
            
            ByteArrayOutputStream signatureStream = new ByteArrayOutputStream();
            signatureStream.write(pemObject.getContent());
            signatureStream.close();
            
            return signatureStream.toByteArray();
        }
    }
}