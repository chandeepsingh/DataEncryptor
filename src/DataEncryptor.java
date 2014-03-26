import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class DataEncryptor {
	public static void main(String args[])
	{		
		String userInput = null;
		Scanner input = new Scanner(System.in);
		System.out.println("Enter E to encrypt or D to decrypt: ");
		userInput = input.nextLine();
		if(userInput.equals("E") || userInput.equals("D"))
		{
			getData(userInput);
		}
		else
		{
			System.out.println("Wrong Input");
		}
	}
	public static void getData(String userInput)
	{
		try
		{
			String strKeyAlg = "AES";
			int nKeySize = 128;
			String strCipherAlg = "AES/CBC/PKCS5Padding";

			byte[] baKey = new byte[nKeySize / 8];
			SecureRandom.getInstance("SHA1PRNG").nextBytes(baKey);
			SecretKey key = new SecretKeySpec(baKey, strKeyAlg);

			byte[] baIv = new byte[128];

			SecureRandom.getInstance("SHA1PRNG").nextBytes(baIv);
			doFileCryptoTest(key, baIv, strCipherAlg, userInput);

			SecureRandom.getInstance("SHA1PRNG").nextBytes(baIv);
			doByteCryptoTest(key, baIv, strCipherAlg);
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
	}

	private static void doFileCryptoTest(SecretKey key, byte[] baIv, String strCipherAlg, String userInput) throws Exception
	{
		Scanner input = new Scanner(System.in);
		String strFile = null;

		if(userInput.equals("E"))
		{
			System.out.println("Enter path for file to encrypted");
			strFile = input.nextLine();
			File f = new File(strFile);
			String strEncryptedFile = f.getParent() + "/EncryptedFile.txt";
			encrypt(key, baIv, new FileInputStream(strFile), new FileOutputStream(strEncryptedFile), strCipherAlg);			
			byte[] encoded = key.getEncoded();
			String stringKey = new BigInteger(1, encoded).toString(16);

			FileOutputStream out = new FileOutputStream(f.getParent() + "/Support.txt");
			out.write(baIv); 
			out.close();

			System.out.println("Encrypted file can be found at: " + strEncryptedFile);
			System.out.println("Supporting file can be found at: " + f.getParent() + "/Support.txt");
			System.out.println("Key: " + stringKey);

		}
		else
			if(userInput.equals("D"))
			{
				System.out.println("Enter path for the encrypted file");
				String strEncryptedFile = input.nextLine();
				System.out.println("Enter path for support file");
				String stringSupportFile = input.nextLine();
				System.out.println("Enter key");
				String stringKey = input.nextLine();

				byte[] encoded = new BigInteger(stringKey, 16).toByteArray();
				key = new SecretKeySpec(encoded, "AES");

				RandomAccessFile raf = new RandomAccessFile(stringSupportFile, "r");
				raf.read(baIv);
				raf.close();
				File f = new File(strEncryptedFile);
				String strDecryptedFile = f.getParent() + "/DecryptedFile.txt";
				decrypt(key, baIv, new FileInputStream(strEncryptedFile), new FileOutputStream(strDecryptedFile), strCipherAlg);
				System.out.println("Decrypted file can be found at: " + strDecryptedFile);
			}
	}

	private static void doByteCryptoTest(SecretKey key, byte[] baIv, String strCipherAlg) throws Exception
	{
		byte[] baData = "This is some data.".getBytes();
		ByteArrayInputStream baisData = new ByteArrayInputStream( baData );
		ByteArrayOutputStream baosEncrytpedData = new ByteArrayOutputStream();

		encrypt(key, baIv, baisData, baosEncrytpedData, strCipherAlg);
		byte[] baEncrytpedData = baosEncrytpedData.toByteArray();

		ByteArrayInputStream baisEncryptedData = new ByteArrayInputStream(baEncrytpedData);
		ByteArrayOutputStream baosDecryptedData = new ByteArrayOutputStream();

		decrypt(key, baIv, baisEncryptedData, baosDecryptedData, strCipherAlg);
	}

	public static void encrypt(SecretKey key, byte[] baIv, InputStream in, OutputStream out, String strCipherAlg) throws Exception
	{
		doCrypto(key, baIv, in, out, Cipher.ENCRYPT_MODE, strCipherAlg);
	}

	public static void decrypt(SecretKey key, byte[] baIv, InputStream in, OutputStream out, String strCipherAlg) throws Exception
	{
		doCrypto(key, baIv, in, out, Cipher.DECRYPT_MODE, strCipherAlg);
	}

	private static void doCrypto(SecretKey key, byte[] baIv, InputStream in, OutputStream out, int nMode, String strCipherAlg) throws Exception
	{
		Cipher cipher = Cipher.getInstance(strCipherAlg);
		cipher.init(nMode, key, new IvParameterSpec(baIv, 0, cipher.getBlockSize()));

		CipherInputStream cis = new CipherInputStream(in, cipher);

		byte[] baBuff = new byte[1024];
		int nBytesRead = -1;

		while ((nBytesRead = cis.read(baBuff)) != -1)
		{
			out.write(baBuff, 0, nBytesRead);
		}

		cis.close();
		in.close();

		out.flush();
		out.close();
	}
}
