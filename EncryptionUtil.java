import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 * Utility class used for encryption/decryption using security private/public keys
 */
public class EncryptionUtil {
	private static SecretKeySpec secretKey;
    
    
	private EncryptionUtil(){
		// Added default constructor to hide implicit one
	}
	
	public static PublicKey getPublicKey() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
		byte[] encodedPublicKey=null;
		File filePublicKey = new File(
				PropertyLoader
						.getCommonProperties(Constants.API_KEY_PUBLIC_FILE_PATH));
		try(FileInputStream fis = new FileInputStream(
				PropertyLoader
				.getCommonProperties(Constants.API_KEY_PUBLIC_FILE_PATH))){
		
		encodedPublicKey = new byte[(int) filePublicKey.length()];
		fis.read(encodedPublicKey);
		}
		KeyFactory keyFactory = KeyFactory.getInstance(PropertyLoader
				.getCommonProperties(Constants.ALGORITHM));
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
				encodedPublicKey);

		return keyFactory.generatePublic(publicKeySpec);
	}

	public static PrivateKey getPrivateKey() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
		byte[] encodedPrivateKey =null;
		File filePrivateKey = new File(
				PropertyLoader.getProperty(Constants.API_KEY_PRIVATE_FILE_PATH));
		try( FileInputStream fis = new FileInputStream(
				PropertyLoader.getProperty(Constants.API_KEY_PRIVATE_FILE_PATH))){
		encodedPrivateKey = new byte[(int) filePrivateKey.length()];
		fis.read(encodedPrivateKey);
       }

		KeyFactory keyFactory = KeyFactory.getInstance(PropertyLoader
				.getCommonProperties(Constants.ALGORITHM));
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
				encodedPrivateKey);

		return keyFactory.generatePrivate(privateKeySpec);
	}

	public static boolean keysPresent() {

		boolean isKeysPresent=false;
		final File publicKey = new File(
				PropertyLoader
						.getCommonProperties(Constants.API_KEY_PUBLIC_FILE_PATH));
		final File privateKey = new File(
				PropertyLoader
						.getCommonProperties(Constants.API_KEY_PRIVATE_FILE_PATH));

		if (privateKey.exists() && publicKey.exists()) {
			isKeysPresent= true;
		}
		return isKeysPresent;
	}

	public static String processData(String textData, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{

		String processedText = null;

		final Cipher cipher = Cipher.getInstance(PropertyLoader
				.getCommonProperties(Constants.ALGORITHM));

		if (key instanceof PublicKey) {
			cipher.init(Cipher.ENCRYPT_MODE, key);
			processedText=Base64.getEncoder().encodeToString(cipher
					.doFinal(textData.getBytes()));
		} else if (key instanceof PrivateKey) {
			cipher.init(Cipher.DECRYPT_MODE, key);
			processedText = new String(cipher.doFinal(Base64.getDecoder().decode(textData)));
					
		}
		return processedText;
	}
	
	//AES encryption
	public static void setKey() throws UnsupportedEncodingException {
		 byte[] key;
		String myKey = PropertyLoader.getProperty(Constants.AES_SECRET_KEY);
		key = myKey.getBytes("UTF-8");
		secretKey = new SecretKeySpec(key, "AES");
	}

	public static String encryptAES(String strToEncrypt) throws APIKEYEncrptionFailedException {
		try {
		setKey();
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
		} catch (Exception exc) {
			throw new APIKEYEncrptionFailedException(Constants.UNKNOWN_ERROR, exc);
		}
	}

	public static String decryptAES(String strToDecrypt) throws APIKEYEncrptionFailedException {
		try {
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
		} catch (Exception exc) {
			throw new APIKEYEncrptionFailedException(Constants.UNKNOWN_ERROR, exc);
		}
	}

}
