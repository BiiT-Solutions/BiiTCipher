package com.biit.cipher;

import com.biit.cipher.logger.CipherLogger;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import static com.biit.cipher.EncryptionConfiguration.encryptionKey;
import static com.biit.cipher.EncryptionConfiguration.encryptionSalt;

public class CipherInitializer {

    private static final String CIPHER_INSTANCE_NAME = "AES/CBC/PKCS5Padding";
    private static final String SECRET_KEY_ALGORITHM = "AES";
    private static EncryptCipherPool encryptCipherPool = new EncryptCipherPool();
    private static DecryptCipherPool decryptCipherPool = new DecryptCipherPool();
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public Cipher prepareAndInitCipher(int encryptionMode, String password, String salt) throws InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        CipherLogger.debug(EncryptionConfiguration.class, "Using cipher '" + CIPHER_INSTANCE_NAME + "'.");
        final Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE_NAME);

        if (salt == null) {
            CipherLogger.warning(EncryptionConfiguration.class, "No salt set, generating an empty one.");
            salt = "";
        }

        final KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(StandardCharsets.UTF_8), 65536, 256); // AES-256
        final SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        final Key secretKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), SECRET_KEY_ALGORITHM);
        CipherLogger.debug(EncryptionConfiguration.class, "Using '" + SECRET_KEY_ALGORITHM + "' algorithm.");

        final AlgorithmParameterSpec algorithmParameters = getAlgorithmParameterSpec(cipher);

        callCipherInit(cipher, encryptionMode, secretKey, algorithmParameters);
        return cipher;
    }

    void callCipherInit(Cipher cipher, int encryptionMode, Key secretKey, AlgorithmParameterSpec algorithmParameters) throws InvalidKeyException,
            InvalidAlgorithmParameterException {
        cipher.init(encryptionMode, secretKey, algorithmParameters);
    }

    int getCipherBlockSize(Cipher cipher) {
        return cipher.getBlockSize();
    }

    private AlgorithmParameterSpec getAlgorithmParameterSpec(Cipher cipher) {
        final byte[] iv = new byte[getCipherBlockSize(cipher)];
        SECURE_RANDOM.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static Cipher getCipherForDecrypt() {
        return decryptCipherPool.getNextElement();
    }

    public static Cipher getNewCipherForDecrypt() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException,
            InvalidKeyException, InvalidKeySpecException {
        final CipherInitializer cipherInitializer = new CipherInitializer();
        return cipherInitializer.prepareAndInitCipher(Cipher.DECRYPT_MODE, encryptionKey, encryptionSalt);
    }

    public static void resetCipherForDecrypt() {
        decryptCipherPool.reset();
    }

    public static Cipher getCipherForEncrypt() {
        return encryptCipherPool.getNextElement();
    }

    public static Cipher getNewCipherForEncrypt() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException,
            InvalidKeyException, InvalidKeySpecException {
        final CipherInitializer cipherInitializer = new CipherInitializer();
        return cipherInitializer.prepareAndInitCipher(Cipher.ENCRYPT_MODE, encryptionKey, encryptionSalt);
    }

    public static void resetCipherForEncrypt() {
        encryptCipherPool.reset();
    }
}
