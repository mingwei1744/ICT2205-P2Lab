import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class TwoTimePad {
	
	public static void main(String[] args) throws IOException 
	{
		
		// Ciphertext 1
		String c1Path = System.getProperty("user.dir") + "\\src\\ciphertext1.txt"; 
		Path c1File = Path.of(c1Path);
		String cipher1 = Files.readString(c1File);
		
		System.out.println("Ciphertext 1: " + cipher1);
		
		
		// Ciphertext 2
		String c2Path = System.getProperty("user.dir") + "\\src\\ciphertext2.txt"; 
		Path c2File = Path.of(c2Path);
		String cipher2 = Files.readString(c2File);
		
		System.out.println("Ciphertext 2: " + cipher2);
		
		// XOR C1 and C2 to remove unknown key
		// Convert hex strings to byte arrays
		byte[] bytes1 = hexStringToByteArray(cipher1);
		byte[] bytes2 = hexStringToByteArray(cipher2);
		
		byte[] result = new byte[bytes1.length];
		for (int i = 0; i < bytes1.length; i++) {
		    result[i] = (byte) (bytes1[i] ^ bytes2[i]);
		}
		
		
		// Convert result byte array back to hex string
		String xorResult = byteArrayToHexString(result);
		System.out.println("C1 XOR C2: " + xorResult);
		
		
		// Get first two binary digit of xorResult, "01" = possibility of space XOR letter
		byte[] byteResult = hexStringToByteArray(xorResult);
		StringBuilder sb = new StringBuilder();
		for (byte b : byteResult) {
			String xorBinary = Integer.toBinaryString(b & 0xFF);
			while (xorBinary.length() < 8) {
				xorBinary = "0" + xorBinary;
			}
			sb.append(xorBinary);
		}
		String xorBinaryResult = sb.toString();
		
		// Get the position of all the "01" results
		List<String> pos = new ArrayList<String>();
		for (int i = 0; i < xorBinaryResult.length(); i += 8) {
			String twoDigits = xorBinaryResult.substring(i, i + 2);
			pos.add(twoDigits);
			
		}
		int binIndex = 0;
		String[] subResult = xorResult.split("(?<=\\G..)"); // regex for every HEX value
		
		// Print all the Possible SPACE XOR LETTER combination and their XOR-ed ASCII
		System.out.println("\n>>> Possible Space XOR Letter combination. \"01\" of first two binary digit <<<");
		for (int i = 0; i < pos.size(); i++) {
			if(pos.get(i).equals("01")) {
				System.out.println("Index: [" + (binIndex) + "] " + "Hex: [" + subResult[binIndex] + "] " 
			+ "SpaceXorHex: [" + xorWithSpaceHex(subResult[binIndex]) + "] " 
						+ " ASCII: [" + hexToAscii(xorWithSpaceHex(subResult[binIndex])) + "]");
			}
			binIndex++;
		}
		
		// Start trial and error
		System.out.println("\n>>> Trial and Error Phase <<<");
		// Since first "01" occurrence is at Index 3, this means that index 0~2 is a letter
		// Hence, XOR the first 3 Hex value of C1XORC2 with a Trigram
		// Bi/Trigram reference: http://practicalcryptography.com/cryptanalysis/letter-frequencies-various-languages/english-letter-frequencies/
		String trigram [] = {"the", "and", "ing", "ent", "ion", "her", "for", "tha", "nth", "int", "ere", "tio", "ter", "est", "ers", "ati", "hat", "ate", "all", "eth", "hes", "ver", "his", "oft", "ith"};
		String bigram [] = {"th", "he", "in", "er", "an", "re", "es", "on", "st", "nt", "en", "at", "ed", "nd", "to", "or", "ea", "ti", "ar", "te", "ng", "al", "it", "as", "is", "ha", "et", "se", "ou", "of"};
		
		for (String s: trigram) {
			String str = xorStrings(s, hexToAscii(xorResult.substring(0, 6))); // Index 0 to 6 of M1
			System.out.println(str);
		}
		
		System.out.println("\n>>> Index 3 [e] and 4 [t] <<<");
		System.out.println("\"Take\" assumed to be the first word for M1, followed by space >> M1: [Take_]");
		System.out.println("Then, trigram \"and\" is for M2 and Index 4 \"t\" assumed to be for M2: [and_t]");
		
		for (String s: bigram) {
			String str = xorStrings(s, hexToAscii(xorResult.substring(10, 14))); // Index 10 to 14 of M2
			System.out.println(str);
		}
		
		System.out.println("\"he\" for M2 forms word 'the'. M2: [and the]");
		System.out.println("Then, M1: [Take he_ _ ?]");
		
		
		for (String s: bigram) {
			String str = xorStrings(s, hexToAscii(xorResult.substring(14, 18))); // Index 14 to 18 of M1
			System.out.println(str);
		}
		
		System.out.println("\n>>> Index 7 [e] and 9 [r] <<<");
		System.out.println("Assume M1: [Take heed]");
		System.out.println("Then, M2: [and the t_ _ _?]");
		System.out.println("Adding Index 9 [r] to M2, M2: [and the tr _ _ _]");
		
		for (String s: trigram) {
			String str = xorStrings(s, hexToAscii(xorResult.substring(20, 26))); // Index 20 to 26 of M2
			System.out.println(str);
		}
		
		System.out.println("\n>>> Index 13 [t] and 14 [s] <<<");
		System.out.println("M2: [and the truth]");
		System.out.println("Index 13 [t], M1: [Take heed that]");
		System.out.println("Index 14 [s] M2: [and the truth s]");
		
		for (String s: bigram) {
			String str = xorStrings(s, hexToAscii(xorResult.substring(30, 34))); // Index 30 to 34 of M1
			System.out.println(str);
		}
		
		System.out.println("\n>>> Index 17 [l] and 19 [a] <<<");
		System.out.println("M1: [Take heed that no]");
		System.out.println("M2: [and the truth sha]");
		System.out.println("Index 17 [l], M2: [and the truth shal]");
		
		String guessL = xorStrings("l", hexToAscii(xorResult.substring(36, 38))); // Index 36 to 38 of M2
		System.out.println(guessL);
		
		System.out.println("M2: [and the truth shall]");
		System.out.println("M1: [Take heed that no m]");
		System.out.println("Index 19 [a]. M1: [Take heed that no ma]");
		
		String guessN = xorStrings("n", hexToAscii(xorResult.substring(40, 42))); // Index 40 to 42 of M1
		System.out.println(guessN);
		System.out.println("\n>>> Index 21 [a] <<<");
		System.out.println("M1: [Take heed that no man]");
		System.out.println("M2: [and the truth shall m");
		System.out.println("Index 21 [a]. M2: [and the truth shall ma");
		
		String guessKE = xorStrings("ke", hexToAscii(xorResult.substring(44, 48))); // Index 40 to 42 of M2
		System.out.println("\n>>> Index 24 [c] <<<");
		System.out.println(guessKE);
		System.out.println("M2: [and the truth shall make]");
		System.out.println("M1: [Take heed that no man de]");
		System.out.println("Index 24 [c]. M1: [Take heed that no man dec]");
		
		String guessEIV = xorStrings("eiv", hexToAscii(xorResult.substring(50, 56))); // Index 50 to 56 of M1
		System.out.println("\n>>> Index 28 [e], 29 [f] <<<");
		System.out.println(guessEIV);
		System.out.println("M1: [Take heed that no man deceiv]");
		System.out.println("Index 28 [e]. M1: [Take heed that no man deceive]");
		System.out.println("M2: [and the truth shall make you]");
		System.out.println("Index 29 [f]. M2: [and the truth shall make you f]\n");
		
		String guessREE = xorStrings("ree", hexToAscii(xorResult.substring(60, 66))); // Index 60 to 66 of M2
		System.out.println(guessREE);
		System.out.println("M1: Take heed that no man deceive you");
		System.out.println("M2: and the truth shall make you free");
		
	}
	
	// Method to convert hex-byte
	public static byte[] hexStringToByteArray(String hexString) {
	    int len = hexString.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
	                             + Character.digit(hexString.charAt(i+1), 16));
	    }
	    return data;
	}
	
	// Method to convert byte-hex
	public static String byteArrayToHexString(byte[] byteArray) {
	    StringBuilder sb = new StringBuilder();
	    for (byte b : byteArray) {
	        sb.append(String.format("%02X", b));
	    }
	    return sb.toString();
	}
	
	// Method to XOR with ascii space "20"
	public static String xorWithSpaceHex(String inputHex) {
	    // Convert the input hex string to a byte array
	    byte[] inputBytes = new byte[inputHex.length() / 2];
	    for (int i = 0; i < inputBytes.length; i++) {
	        inputBytes[i] = (byte) Integer.parseInt(inputHex.substring(i * 2, i * 2 + 2), 16);
	    }
	    
	    // XOR each byte of the input with the space byte
	    byte spaceByte = 0x20;
	    for (int i = 0; i < inputBytes.length; i++) {
	        inputBytes[i] ^= spaceByte;
	    }
	    
	    // Convert the XORed byte array back to a hex string
	    StringBuilder sb = new StringBuilder();
	    for (byte b : inputBytes) {
	        sb.append(String.format("%02X", b));
	    }
	    return sb.toString();
	}
	
	// Method to convert hex to ascii
	public static String hexToAscii(String hex) {
	    StringBuilder sb = new StringBuilder();
	    for (int i = 0; i < hex.length(); i += 2) {
	        String hexPair = hex.substring(i, i + 2);
	        int asciiValue = Integer.parseInt(hexPair, 16);
	        sb.append((char) asciiValue);;
	    }
	    return sb.toString();
	}
	
	// Method to XOR two equal length strings
	public static String xorStrings(String s1, String s2) {
	    if (s1.length() != s2.length()) {
	        throw new IllegalArgumentException("Strings must have equal length");
	    }

	    char[] result = new char[s1.length()];
	    for (int i = 0; i < s1.length(); i++) {
	        result[i] = (char) (s1.charAt(i) ^ s2.charAt(i));
	    }

	    return new String(result);
	}
}
