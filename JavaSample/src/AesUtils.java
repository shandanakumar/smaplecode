import java.io.File;
import java.io.FileNotFoundException;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public final class AesUtils {

	private static final String ALGORITHM = "AES";
	private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
	private static final String FORMAT = "UTF-8";
	
	
	
	public static int getMaxKeyLength()
	{
		try {
			// return max allowed key length
			final int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
			return maxKeyLen;
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException("invalid algorithm", e);
		}
	}

	private static String getKey()
	{
		try {
			// read key from file
			ResourceBundle labels = ResourceBundle.getBundle("MessageResources", Locale.ENGLISH);
			String KEYPATH = labels.getString("aes.encryption.keypath");
			final File keyFile = new File(KEYPATH);
			final String key = new Scanner(keyFile).next();
			return key;
		} catch (FileNotFoundException e) {
			throw new IllegalArgumentException("path argument is not valid");
		}
	}

	public static String encrypt(final String plainMessage)
	{
		final String symKeyHex = getKey();
		final byte[] symKeyData = DatatypeConverter.parseHexBinary(symKeyHex);
		final byte[] encodedMessage = plainMessage.getBytes(Charset.forName(FORMAT));

		try {
			final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
			final int blockSize = cipher.getBlockSize();

			// create the key
			final SecretKeySpec symKey = new SecretKeySpec(symKeyData, ALGORITHM);

			// generate random IV using block size (possibly create a method for this)
			final byte[] ivData = new byte[blockSize];
			final SecureRandom rnd = SecureRandom.getInstance("SHA1PRNG");
			rnd.nextBytes(ivData);
			final IvParameterSpec iv = new IvParameterSpec(ivData);

			cipher.init(Cipher.ENCRYPT_MODE, symKey, iv);
			final byte[] encryptedMessage = cipher.doFinal(encodedMessage);
			// concatenate IV and encrypted message
			final byte[] ivAndEncryptedMessage = new byte[ivData.length + encryptedMessage.length];
			System.arraycopy(ivData, 0, ivAndEncryptedMessage, 0, blockSize);
			System.arraycopy(encryptedMessage, 0, ivAndEncryptedMessage, blockSize, encryptedMessage.length);
			final String ivAndEncryptedMessageBase64 = DatatypeConverter.printBase64Binary(ivAndEncryptedMessage);
			return ivAndEncryptedMessageBase64;
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("key argument does not contain a valid AES key", e);
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException("Unexpected exception during encryption", e);
		}
	}

	public static String decrypt(final String ivAndEncryptedMessageBase64)
	{
		final String symKeyHex = getKey();
		final byte[] symKeyData = DatatypeConverter.parseHexBinary(symKeyHex);
		final byte[] ivAndEncryptedMessage = DatatypeConverter.parseBase64Binary(ivAndEncryptedMessageBase64);

		try {
			final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
			final int blockSize = cipher.getBlockSize();
			// create the key
			final SecretKeySpec symKey = new SecretKeySpec(symKeyData, ALGORITHM);

			// retrieve random IV from start of the received message
			final byte[] ivData = new byte[blockSize];
			System.arraycopy(ivAndEncryptedMessage, 0, ivData, 0, blockSize);
			final IvParameterSpec iv = new IvParameterSpec(ivData);

			// retrieve the encrypted message itself
			final byte[] encryptedMessage = new byte[ivAndEncryptedMessage.length - blockSize];
			System.arraycopy(ivAndEncryptedMessage, blockSize, encryptedMessage, 0, encryptedMessage.length);
			cipher.init(Cipher.DECRYPT_MODE, symKey, iv);
			final byte[] encodedMessage = cipher.doFinal(encryptedMessage);

			// concatenate IV and encrypted message
			final String message = new String(encodedMessage, Charset.forName(FORMAT));
			return message;

		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("key argument does not contain a valid AES key");
		} catch (BadPaddingException e) {
			// you'd better know about padding oracle attacks
			return null;
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException("Unexpected exception during decryption", e);
		}
	}
	
	public static void main(String[] args) {
		AesUtils.encrypt("ShanMay@2016");
	}

}