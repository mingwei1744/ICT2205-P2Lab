import java.math.BigInteger;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Methods {

	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}
	
	// AES Key Wrap - Lecture 6B Slide 7
	public byte [] wrapKeyWithAESkey(Key key, SecretKey KEK) throws Exception
	{
		// init cipher
		Cipher cipher = Cipher.getInstance("AESWrap");
		cipher.init(Cipher.WRAP_MODE, KEK);
		
		// wrap key
		byte[] wrappedKey = cipher.wrap(key);
		
		// display wrapped key in hex
		System.out.println(new BigInteger(1, wrappedKey).toString(16));
		
		return wrappedKey;
	}
	
	// AES Key Unwrap - Lecture 6B Slide 8
	public Key unwrapKeyWithAESkey(byte[] wrappedKey, SecretKey KEK) throws Exception
	{
		// init cipher
		Cipher cipher = Cipher.getInstance("AESWrap");
		cipher.init(Cipher.UNWRAP_MODE, KEK);
		
		// unwrap key
		Key key = cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
		
		return key;
	}
	
	// Derive AES Key from PBKDF2 - Lecture 6B Slide 10
	public SecretKey deriveAESkeyFromPbkdf2(char[] passwd, byte[] salt, int iteration, int keyLen) throws Exception
	{
		// init PBKDF2
		SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		PBEKeySpec keySpec = new PBEKeySpec(passwd, salt, iteration, keyLen);
		
		// derive secret key
		SecretKey s = keyFac.generateSecret(keySpec);
		SecretKey key = new SecretKeySpec(s.getEncoded(), "AES");
		
		return key;
		
	}
	
	// Encrypt a message using AES Block Cipher ECB - Lecture 7A Slide 6
	public byte[] encryptWithAesEcb(SecretKey key, byte[] plainText) throws Exception
	{
		// init cipher
		Cipher cipher = Cipher.getInstance("AES/ECB/PCKS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		
		// encrypt
		byte[] cipherText = cipher.doFinal(plainText);
		
		return cipherText;
	}
	
	// Encrypt a message using AES CTR mode (block to stream cipher) - Lecture 7A Slide 11
	public byte[] encryptWithAesCtr(SecretKey key, byte[] iv, byte[] plainText) throws Exception
	{
		//init cipher
		Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
		
		// encrypt
		byte[] cipherText = cipher.doFinal(plainText);
		
		return cipherText;
	}
	
	// HmacSHA256 - Lecture 7a Slide 18
	public byte[] computeHmacSha256(SecretKey key, byte[] plainText) throws Exception
	{
		// init MAC
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(key);
		
		// compute mac
		byte[] tag = mac.doFinal(plainText);
		
		// display mac in hexadecimal
		System.out.println(HexFormat.of().formatHex(tag));
		
		return tag;
	}
	
	// Encrypt-then-MAC using AES-GCM  - Lecture 7a Slide 25
	public byte[] encryptWithAesGcm(SecretKey key, byte[] iv, int tagLen, byte[] aad, byte[] plainText) throws Exception
	{
		// init cipher
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		GCMParameterSpec spec = new GCMParameterSpec(tagLen, iv);
		cipher.init(Cipher.ENCRYPT_MODE, key, spec);
		
		// associated data
		cipher.updateAAD(aad);
		
		// encrypt
		byte[] cipherText = cipher.doFinal(plainText);
		
		return cipherText;
	}
	
	// Verify and Decrypt with AES-GCM - Lecture 7a Slide 26
	public byte[] decryptWithAesGcm(SecretKey key, byte[] iv, int tagLen, byte[] aad, byte[] cipherText) throws Exception
	{
		// init cipher
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		GCMParameterSpec spec = new GCMParameterSpec(tagLen, iv);
		cipher.init(Cipher.DECRYPT_MODE, key, spec);
		
		// associated data
		cipher.updateAAD(aad);
		
		// decrypt
		// If MAC verification fails, AEADBagTagException will be thrown and decryption aborted.
		byte[] plainText = cipher.doFinal(cipherText);
		
		return plainText;
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
}
