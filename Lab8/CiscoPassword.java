import org.bouncycastle.crypto.generators.SCrypt;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;


// REFERENCES:
// HASHCAT: https://www.infosecmatter.com/cisco-password-cracking-and-decrypting-guide/
// CISCO PASSWORD TYPES: https://www.router-switch.com/faq/six-types-of-cisco-password.html
// TOOLS: https://community.cisco.com/t5/other-security/python-tool-for-converting-plain-text-to-type9-passwords/td-p/4316528
// TOOLS: https://github.com/BrettVerney/ciscoPWDhasher 

public class CiscoPassword {
    private static final String STD_B64CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    private static final String CISCO_B64CHARS = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    public static void main(String[] args) throws Exception {
    	
    	// Declare variables
        String fileName = "D:\\rockyou.txt";
        String encryptedHash = "$9$Sz9isKUcavFN33$Pye28w411Wc/2byQhN3yMBQ/aPOp4qsi2Da1Vk0oP9s";
        String[] hashSplit = encryptedHash.split("\\$");
        ArrayList<String> parameters = new ArrayList<String>();
        String algoType = "";

        for (String s : hashSplit) {
            parameters.add(s);
        }

        // Get Algorithm Type
        int algoCode = Integer.parseInt(parameters.get(1));
        switch (algoCode) {
            case 5:
                algoType = "md5";
                break;

            case 8:
                algoType = "sha256";
                break;

            case 9:
                algoType = "scrypt";
                break;
        }

        // Get Salt
        String salt = parameters.get(2);

        // Get Hashed Password
        String hashedPassword = parameters.get(3);
        
        System.out.println("Algorithm Type: " + algoType);
        System.out.println("Salt: " + salt);
        System.out.println("Hashed Password: " + hashedPassword);
        
        System.out.println("--- Start Decrypting... ---");
        try (BufferedReader br = new BufferedReader(new FileReader(fileName))) {
            String password;
            while ((password = br.readLine()) != null) {
            	// TODO: TYPE 5, TYPE 8 according to lecture slide
                String computedHash = type9(password, salt);
                if (computedHash.equals(encryptedHash)) {
                    System.out.println("Password Found: " + password);
                    break;
                }
                else {
                	System.out.println("Password not match: " + password);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    // Format $9 | $Salt (14) | $Hashed_Password (43)
    public static String type9(String pwd, String salt) throws Exception {
        byte[] hash = generateScrypt(pwd, salt);
        String base64Hash = Base64.getEncoder().encodeToString(hash);
        String ciscoBase64Hash = ConvertToCiscoBase64(base64Hash);
        return "$9$" + salt + "$" + ciscoBase64Hash;
    }
    
    // Function to generate Scrypt
    public static byte[] generateScrypt(String passwd, String salt) throws Exception {
        byte[] P = passwd.getBytes(StandardCharsets.UTF_8);
        byte[] S = salt.getBytes(StandardCharsets.UTF_8);

        int N = 16384; // CPU/Memory cost 2^14
        int r = 1; // Block size, Cisco r = 1
        int p = 1; // Parallelization, RFC recommends p = 1
        int dkLen = 32; // Hash length in bytes
        
        byte[] hash = SCrypt.generate(P, S, N, r, p, dkLen);

        return hash;
    }
    
    // Convert standard Base64 encoding to Cisco Base64
    public static String ConvertToCiscoBase64(String stdBase64) {
        StringBuilder ciscoBase64 = new StringBuilder(stdBase64.length());
        for (int i = 0; i < stdBase64.length(); i++) {
            char ch = stdBase64.charAt(i);
            int index = STD_B64CHARS.indexOf(ch);
            if (index != -1) {
                ciscoBase64.append(CISCO_B64CHARS.charAt(index));
            }
        }
        return ciscoBase64.toString();
    }
}
