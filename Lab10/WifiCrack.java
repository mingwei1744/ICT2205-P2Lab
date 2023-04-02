import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.bouncycastle.util.Arrays;


// REFERENCE: Lecture 10b Slide 18.
public class WifiCrack {
	
    public static void main(String[] args) throws Exception
    {
    	// Get wordlist
    	String [] passwords = getPasswordList("D:\\pass.txt");
    	
    	// Extract PMKID from pcap
    	String extractedPMKID = "eb5af8ed3453bf321a3792f6aac22305";

    	// Salt
    	byte[] salt = "ciscosb1".getBytes();
    	// Iterations
    	int iteration = 4096;
    	// keyLength
    	int keyLen = 256;	
    	
    	// Authenticator MAC; Station MAC
        // AA: b8621f50edd3
    	// SA: 5e7577643888
    	byte [] AA = hexStringToByteArray("b8621f50edd3");
        byte [] SA = hexStringToByteArray("5e7577643888");
        
        // PMK Name
        byte [] pmkName = "PMK Name".getBytes();      
        // Hex converter
        HexFormat hexFormat = HexFormat.of();
    	
        // Iterate through password list, brute force attack
        for (String pass : passwords) {
        	
        	// Get Pairwise Master Key - 256bit
        	byte[] pmk = Pbkdf2(pass.toCharArray(), salt, iteration, keyLen);  
        	
        	// Get PMK Name + AA + SA
        	byte[] pmkAASA = concatPMKName(pmkName, AA, SA);
        	
        	// HMAC-SHA1 pmkAASA and PMK
        	byte[] pmkid = hmacSha1(pmk, pmkAASA);
        	
        	// First 128-bit of PMKID 
        	byte[] pmkid16Bytes =  Arrays.copyOfRange(pmkid, 0, 16);
        	System.out.println(hexFormat.formatHex(pmkid16Bytes));
        	
          	if (bytesToHex(pmkid16Bytes).equals(extractedPMKID)) {
        		System.out.println("PASSWORD FOUND: " + pass);
        		break;
        	}
        	
        }
    	
    }
    
    // PBKDF2 with HmacSHA1
    public static byte[] Pbkdf2(char [] passwd, byte[] salt, int iteration, int keyLen) throws Exception
    {
    	SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    	PBEKeySpec keySpec = new PBEKeySpec(passwd, salt, iteration, keyLen);
    	
    	byte[] encodedKey = keyFac.generateSecret(keySpec).getEncoded();
    	
    	return encodedKey;
    }
    
    // HMACSHA1
    public static byte[] hmacSha1(byte[] key, byte[] data) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA1");
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(keySpec);
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (java.security.InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }
    
    // "PMK Name" || AA || SA
    public static byte[] concatPMKName(byte[] arr1, byte[] arr2, byte[] arr3) {
        
        byte[] result = new byte[arr1.length + arr2.length + arr3.length];
        System.arraycopy(arr1, 0, result, 0, arr1.length);
        System.arraycopy(arr2, 0, result, arr1.length, arr2.length);
        System.arraycopy(arr3, 0, result, arr1.length + arr2.length, arr3.length);
        
        return result;
    }
    
    // Get list of password
    public static String[] getPasswordList(String filePath) throws IOException {
        List<String> password = new ArrayList<>();
        BufferedReader reader = new BufferedReader(new FileReader(filePath));
        String line = null;
        while ((line = reader.readLine()) != null) {
        	password.add(line);
        }
        reader.close();
        return password.toArray(new String[password.size()]);
    }
    
    // Convert a hex string to a byte array
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    // Convert a byte array to a hex string
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

}
