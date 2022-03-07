package com.biit.cipher;

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

import static com.biit.cipher.EncryptionConfiguration.eventEncryptionKey;
import static com.biit.cipher.EncryptionConfiguration.eventEncryptionSalt;

public class CipherInitializer {

    private static final String CIPHER_INSTANCE_NAME = "AES/CBC/PKCS5Padding";
    private static final String SECRET_KEY_ALGORITHM = "AES";
    private static Cipher cipherEncryptor;
    private static Cipher cipherDecryptor;

    public Cipher prepareAndInitCipher(int encryptionMode, String password, String salt) throws InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        final Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE_NAME);

        if (salt == null) {
            int leftLimit = 97; // letter 'a'
            int rightLimit = 122; // letter 'z'
            int targetStringLength = 10;
            Random random = new SecureRandom();
            salt = random.ints(leftLimit, rightLimit + 1)
                    .limit(targetStringLength)
                    .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                    .toString();
        }

        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(StandardCharsets.UTF_8), 65536, 256); // AES-256
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        final Key secretKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), SECRET_KEY_ALGORITHM);

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

    private static Cipher getCipherForDecrypt() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException,
            InvalidKeyException, InvalidKeySpecException {
        if (cipherDecryptor == null) {
            final CipherInitializer cipherInitializer = new CipherInitializer();
            cipherDecryptor = cipherInitializer.prepareAndInitCipher(Cipher.DECRYPT_MODE, eventEncryptionKey, eventEncryptionSalt);
        }
        return cipherDecryptor;
    }

    private static Cipher getCipherForEncrypt() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException,
            InvalidKeyException, InvalidKeySpecException {
        if (cipherEncryptor == null) {
            final CipherInitializer cipherInitializer = new CipherInitializer();
            cipherEncryptor = cipherInitializer.prepareAndInitCipher(Cipher.ENCRYPT_MODE, eventEncryptionKey, eventEncryptionSalt);
        }
        return cipherEncryptor;
    }
}
