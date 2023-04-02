import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.AlgorithmParameters;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource.PSpecified;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.AlgorithmParametersSpi;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.io.pem.PemObject;

public class RsaOaep
{
    public static void main(String[] args)
    {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

		String certFile = System.getProperty("user.dir") + "\\src\\pub.cer";
		String privKeyFile = System.getProperty("user.dir") + "\\src\\unknown-priv.pem";
        char[] privKeyPasswd = new String("cryptomadness").toCharArray();
        byte[] data = "This is a test message.".getBytes();
        String p7envFile = "pkcs7envdata.p7m";
        String p7sigFile = "pkcs7sigdata.p7m";

        Pkcs7Cms pkcs7cms = new Pkcs7Cms();
        Pkcs8PrivKey pkcs8pk = new Pkcs8PrivKey();
        try {
            CertificateFactory certFactory= CertificateFactory.getInstance("X.509", "BC");
            X509Certificate cert = (X509Certificate)certFactory.generateCertificate(new FileInputStream(certFile));

            PrivateKey privKey = pkcs8pk.readEncodedEncryptedPKCS8PrivateKeyFile(privKeyFile, privKeyPasswd);

            // 1.3.1 Encrypted message file
            // Get Encrypted EnvDataFile
            String envdataFile = System.getProperty("user.dir") + "\\src\\unknown-envdata.p7m";
            
            // Read the EnvDataFile
            PEMParser pemParser = new PEMParser(new FileReader(envdataFile));
            Object o = pemParser.readObject();
            
            // Parse content into CMS EnvelopedData
            CMSEnvelopedData cmsEnvelopedData = new CMSEnvelopedData((ContentInfo)o);

            AlgorithmIdentifier ContentEncryptAlgo = cmsEnvelopedData.getContentEncryptionAlgorithm();
            
            // Get message recipient information
            RecipientInformationStore recipients = cmsEnvelopedData.getRecipientInfos();
            
            // Iterate through recipients
            Collection c = recipients.getRecipients();
            Iterator it = c.iterator();
            
            //https://www.bouncycastle.org/docs/pkixdocs1.4/org/bouncycastle/cms/CMSEnvelopedData.html
            if (it.hasNext()) {
                RecipientInformation recipient = (RecipientInformation) it.next();
                //
                byte[] recData = recipient.getContent(new JceKeyTransEnvelopedRecipient(privKey).setProvider("BC"));
                String contentString = new String(recData, StandardCharsets.UTF_8);
                System.out.println(contentString);
            }

        }
        catch (Exception e) {
            System.out.println(e);
        }
        
    }

    
	// Encryption Function, (Data, Receipient Cert)
	// x509 v3 cert contains public key and user ID used for encryption
	public byte[] encryptDataWithRSA_OAEPinPKCS7(byte[] data, X509Certificate recipientCert) 
		throws Exception 
	{     
		// init PKCS#7 enveloped-data type, generate a CMS Envelop Data
		CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator = new CMSEnvelopedDataGenerator();

		// specify RSA-OAEP parameters lect_7b slide 6
		byte[] label = new String("label").getBytes();
		PSpecified p = new PSpecified(label);
		OAEPParameterSpec oaepSpec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, p);
		JcaAlgorithmParametersConverter paramsConverter = new JcaAlgorithmParametersConverter();
		AlgorithmIdentifier keyEncAlgId = paramsConverter.getAlgorithmIdentifier
			(PKCSObjectIdentifiers.id_RSAES_OAEP, oaepSpec);
		
		System.out.println(oaepSpec.getDigestAlgorithm());
		System.out.println(keyEncAlgId.getParameters());
		
		// add recipient info + encrypted session key into enveloped-data
		JceKeyTransRecipientInfoGenerator encSessionKey 
			= new JceKeyTransRecipientInfoGenerator(recipientCert, keyEncAlgId);
		cmsEnvelopedDataGenerator.addRecipientInfoGenerator(encSessionKey);
		
		// specify data encryption algo
		JceCMSContentEncryptorBuilder builder = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC);
		OutputEncryptor encryptor = builder.build();
		
		// add data encrypted using session key into enveloped-data
		CMSTypedData cmsData = new CMSProcessableByteArray(data);
		CMSEnvelopedData cmsEnvelopedData = cmsEnvelopedDataGenerator.generate(cmsData, encryptor);
		
		RecipientInformationStore ris = cmsEnvelopedData.getRecipientInfos();
		RecipientInformation ri = ris.iterator().next();
		System.out.println("Key Enc Algoritm OID: " + ri.getKeyEncryptionAlgOID());
		
		System.out.println("Enc Algorithm OID: " + cmsEnvelopedData.getContentEncryptionAlgorithm().getAlgorithm().getId());
		
		byte[] envelopedData = cmsEnvelopedData.getEncoded();
		
		// ASN1 Dump Enveloped Daya
		ASN1Primitive cmsEnvDataAsnip = ASN1Primitive.fromByteArray(envelopedData);
		System.out.println(ASN1Dump.dumpAsString(cmsEnvDataAsnip, true));
		System.out.println("----------------------------");
		
		return envelopedData;
	}
	
	// Decryption Function, (Enveloped Data, Receipient Private Key)
	public byte[] decryptDataWithRSA_OAEPinPKCS7(byte[] envelopedData, PrivateKey recipientPrivKey)
		      throws Exception
		{  
		   // init PKCS#7 CMS signed-data type, generate a CMS Envelop Data
		   CMSEnvelopedData cmsEnvelopedData = new CMSEnvelopedData(envelopedData);

		   // Get first recipient in collection instead of searching through for correct recipient
		   Collection<RecipientInformation> recipients = cmsEnvelopedData.getRecipientInfos().getRecipients();
		   KeyTransRecipientInformation recipientInfo = (KeyTransRecipientInformation) recipients.iterator().next();
		   // decrypt using recipient private-key to recover session-key,
		   // then decrypt data using recovered session-key
		   JceKeyTransRecipient sessionkey = new JceKeyTransEnvelopedRecipient(recipientPrivKey);
		   byte[] decryptedData = recipientInfo.getContent(sessionkey);
		   
		   return decryptedData;
		   
		}
	
	// Signing Data Function (Data, SignerCert, PrivateKey)
	public byte[] signDataWithRSA_PSSinPKCS7(byte[] data, X509Certificate signerCert,
		PrivateKey signerPrivKey) throws Exception 
	{
		// init PKCS#7 CMS signed-data type, generate a CMS Envelop Data
		CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
	
		// add signer cert into signed-data for recipient to verify signature
		List<X509Certificate> certList = new ArrayList<X509Certificate>();
		certList.add(signerCert);
		cmsGenerator.addCertificates(new JcaCertStore(certList));
    
		// specify PSS parameters
		int sLen = 32; // typical value = hLen
		int trailer = PSSParameterSpec.TRAILER_FIELD_BC; // default 1 byte = 0xBC
		PSSParameterSpec pssSpec = new PSSParameterSpec
			("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, sLen, trailer);
		JcaContentSignerBuilder builder = new JcaContentSignerBuilder
			(PKCSObjectIdentifiers.id_RSASSA_PSS.toString(), pssSpec);
			
		// add signature into signed-data
		ContentSigner contentSigner = builder.build(signerPrivKey);
		cmsGenerator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
			new JcaDigestCalculatorProviderBuilder().build()).build(contentSigner, signerCert));
		// true : signature + data added in signedData 
		// false: detached signature, only signature in signedData, no data
		CMSTypedData cmsData= new CMSProcessableByteArray(data);
		CMSSignedData cmsSignedData = cmsGenerator.generate(cmsData, true);
	
		byte[] signedData = cmsSignedData.getEncoded();
		return signedData;
	}

	public void writeEncodedPKCS7CmsFile(String p7File, byte[] pkcs7Encoded) 
		throws Exception
	{
		PemObject po = new PemObject(PEMParser.TYPE_CMS, pkcs7Encoded);
		po.generate();
		JcaPEMWriter jpw = new JcaPEMWriter(new FileWriter(p7File));
		jpw.writeObject(po);
		jpw.flush();
	}
	
}