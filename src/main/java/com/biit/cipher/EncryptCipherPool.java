package com.biit.cipher;

import com.biit.cipher.logger.CipherLogger;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static com.biit.cipher.EncryptionConfiguration.encryptionKey;
import static com.biit.cipher.EncryptionConfiguration.encryptionSalt;

public class EncryptCipherPool extends CipherPool {

    @Override
    public Cipher createNewElement() {
        final CipherInitializer cipherInitializer = new CipherInitializer();
        try {
            return cipherInitializer.prepareAndInitCipher(Cipher.ENCRYPT_MODE, encryptionKey, encryptionSalt);
        } catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeySpecException e) {
            CipherLogger.errorMessage(this.getClass(), e);
        }
        return null;
    }
}
