import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.Base64;

public class SimpleEncryptionUtil {

    // Method to generate a 16-character AES key from a passphrase or random string
    public static SecretKey generateAESKey(String keyPhrase) throws Exception {
        byte[] key = keyPhrase.getBytes("UTF-8");
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        key = sha.digest(key); // Hash it for consistency
        byte[] shortKey = new byte[16]; // AES requires 128-bit key (16 bytes)
        System.arraycopy(key, 0, shortKey, 0, 16);
        return new SecretKeySpec(shortKey, "AES");
    }

    // Method to encrypt data using AES and Base64-encode the result
    public static String encryptAES(String data, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        
        // Initialize IV (Initialization Vector) for CBC mode
        byte[] iv = new byte[16]; // Using a zero IV for simplicity, but it's better to use a random IV in production.
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encryptedData = cipher.doFinal(data.getBytes("UTF-8"));
        
        // Encode the encrypted data in Base64
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    // Method to decrypt Base64-encoded data using AES
    public static String decryptAES(String base64EncryptedData, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        
        // Initialize IV for CBC mode (must be the same IV used for encryption)
        byte[] iv = new byte[16]; 
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        
        // Decode Base64 before decrypting
        byte[] encryptedData = Base64.getDecoder().decode(base64EncryptedData);
        byte[] originalData = cipher.doFinal(encryptedData);
        
        return new String(originalData, "UTF-8");
    }

    // Method to return data in the form ENC_BASE64(AES_ENCRYPT('String', 'key'))
    public static String getEncryptedOutput(String originalText, String keyPhrase) throws Exception {
        SecretKey aesKey = generateAESKey(keyPhrase);
        String base64Encrypted = encryptAES(originalText, aesKey);

        // Return result in ENC_BASE64(AES_ENCRYPT('originalText', 'keyPhrase')) format
        return base64Encrypted;
    }

    // Method to write data to CSV
    private static void writeToCSV(String filePath, String originalText, String encryptedData, String keyPhrase) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) { // No "true" argument, so it will overwrite
            // Write the header
            writer.write("Original_Text,Encrypted_Text,AES_KEY");
            writer.newLine();
    
            // Write the data
            writer.write(String.format("\"%s\",\"%s\",\"%s\"", originalText, encryptedData, keyPhrase));
            writer.newLine();
            System.out.println("Data written to " + filePath);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }    

    public static void main(String[] args) {
        try {
            // Passphrase or string for key generation
            String keyPhrase = "mySecretKey12345"; // Must be exactly 16 characters

            // Sample data to encrypt and decrypt
            String originalData = "This is a secret message";

            // Get the result in ENC_BASE64(AES_ENCRYPT('String', 'key')) format
            String encryptedResult = getEncryptedOutput(originalData, keyPhrase);
            System.out.println("Encrypted data in desired format: " + encryptedResult);

            String filePath = "C:\\Users\\ppenthoi\\OneDrive - Informatica\\Documents\\IDMC\\Flat File Transformation\\output.csv"; // Update with your desired path

            // Write to CSV
            writeToCSV(filePath, originalData, encryptedResult, keyPhrase);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
