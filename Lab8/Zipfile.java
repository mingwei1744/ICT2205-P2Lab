import java.io.File;
import java.nio.file.Files;
import java.util.HexFormat;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.Arrays;

public class Zipfile {
	
	public static void main(String[] args) {
		char[] password = new String("simple").toCharArray();
		byte[] salt = HexFormat.of().parseHex("426696368abc4a24");
		
		String zipfile = System.getProperty("user.dir") + "\\unknown.mzip";
		String mp4file = System.getProperty("user.dir") + "\\unknown.mp4";
		
		try {
			// read and extract encrypted file from unknown.mzip file
			byte[] mzipFile = Files.readAllBytes(new File(zipfile).toPath());
			byte[] encFile = Arrays.copyOfRange(mzipFile, 54, mzipFile.length);
			
			// derive secret key from password
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			PBEKeySpec spec = new PBEKeySpec(password, salt, 1000, 34*8);
			byte[] encodedKey = factory.generateSecret(spec).getEncoded();
			
			// verify password verification value before decrypting
			if (encodedKey[32]==(byte)0xf6 && encodedKey[33]==(byte)0xfd) {
				
				// init GCM
				byte[] iv = Arrays.copyOfRange(encodedKey, 16, 32);
				GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
				
				// init cipher and decrypt
				SecretKey aesKey = new SecretKeySpec(Arrays.copyOfRange(encodedKey, 0, 16), "AES");
				Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
				cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);
				cipher.updateAAD(salt);
				byte[] decFile = cipher.doFinal(encFile);
				
				// if no exception generated, write to new file
				Files.write(new File (mp4file).toPath(), decFile);
			}
		}
		catch (Exception e) {
			System.out.println(e);
		}
		
	}
	
	// Function to decrypt AES-GCM
	public byte[] decryptAesGcm(SecretKey key, byte[] iv, int tagLen, byte[] aad, byte[] ct) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		GCMParameterSpec spec = new GCMParameterSpec(tagLen, iv);
		cipher.init(Cipher.DECRYPT_MODE, key, spec);
		cipher.updateAAD(aad);
		byte[] plainText = cipher.doFinal(ct);
		
		return plainText;
	}

}
