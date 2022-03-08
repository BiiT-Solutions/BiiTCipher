package com.biit.cipher;

import com.biit.cipher.logger.CipherLogger;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Random;

import static com.biit.cipher.EncryptionConfiguration.encryptionKey;
import static com.biit.cipher.EncryptionConfiguration.encryptionSalt;

public class CipherInitializer {

    private static final String CIPHER_INSTANCE_NAME = "AES/CBC/PKCS5Padding";
    private static final String SECRET_KEY_ALGORITHM = "AES";
    private static final int LEFT_LIMIT = 97; // letter 'a'
    private static final int RIGHT_LIMIT = 122; // letter 'z'
    private static final int DEFAULT_SALT_LENGTH = 10;
    private static Cipher cipherEncryptor;
    private static Cipher cipherDecryptor;

    public Cipher prepareAndInitCipher(int encryptionMode, String password, String salt) throws InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        CipherLogger.debug(EncryptionConfiguration.class, "Using cipher '" + CIPHER_INSTANCE_NAME + "'.");
        final Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE_NAME);

        if (salt == null) {
            CipherLogger.warning(EncryptionConfiguration.class, "No salt set, generating a random one.");
            final Random random = new SecureRandom();
            salt = random.ints(LEFT_LIMIT, RIGHT_LIMIT + 1)
                    .limit(DEFAULT_SALT_LENGTH)
                    .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                    .toString();
            CipherLogger.warning(EncryptionConfiguration.class, "Random salt set as '" + salt + "'.");
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
        return new IvParameterSpec(iv);
    }

    public static Cipher getCipherForDecrypt() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException,
            InvalidKeyException, InvalidKeySpecException {
        if (cipherDecryptor == null) {
            final CipherInitializer cipherInitializer = new CipherInitializer();
            cipherDecryptor = cipherInitializer.prepareAndInitCipher(Cipher.DECRYPT_MODE, encryptionKey, encryptionSalt);
        }
        return cipherDecryptor;
    }

    public static void resetCipherForDecrypt() {
        cipherDecryptor = null;
    }

    public static Cipher getCipherForEncrypt() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException,
            InvalidKeyException, InvalidKeySpecException {
        if (cipherEncryptor == null) {
            final CipherInitializer cipherInitializer = new CipherInitializer();
            cipherEncryptor = cipherInitializer.prepareAndInitCipher(Cipher.ENCRYPT_MODE, encryptionKey, encryptionSalt);
        }
        return cipherEncryptor;
    }

    public static void resetCipherForEncrypt() {
        cipherEncryptor = null;
    }
}
