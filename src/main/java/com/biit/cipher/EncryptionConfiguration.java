package com.biit.cipher;

import com.biit.cipher.logger.CipherLogger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class EncryptionConfiguration {

    public static String encryptionKey;
    public static String encryptionSalt;

    public EncryptionConfiguration(@Value("${encryption.key:}") String encryptionKey, @Value("${encryption.salt:}") String encryptionSalt) {
        setEncryptionKey(encryptionKey);
        setEncryptionSalt(encryptionSalt);
    }

    private static synchronized void setEncryptionKey(String encryptionKey) {
        CipherLogger.debug(EncryptionConfiguration.class, "Encryption key '" + encryptionKey + "'.");
        EncryptionConfiguration.encryptionKey = encryptionKey;
    }

    private static synchronized void setEncryptionSalt(String encryptionSalt) {
        CipherLogger.debug(EncryptionConfiguration.class, "Encryption salt '" + encryptionSalt + "'.");
        EncryptionConfiguration.encryptionSalt = encryptionSalt;
    }


}
