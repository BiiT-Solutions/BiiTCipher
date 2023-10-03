package com.biit.cipher;

import com.biit.cipher.logger.CipherLogger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@SuppressWarnings("checkstyle:HideUtilityClassConstructor")
@Component
public class EncryptionConfiguration {

    @SuppressWarnings("checkstyle:VisibilityModifier")
    public static String encryptionKey;
    @SuppressWarnings("checkstyle:VisibilityModifier")
    public static String encryptionSalt;
    @SuppressWarnings("checkstyle:VisibilityModifier")
    public static String cipherPoolSize;

    public EncryptionConfiguration(@Value("${encryption.key:}") String encryptionKey, @Value("${encryption.salt:}") String encryptionSalt,
                                   @Value("${cipher.pool.size:}") String cipherPoolSize) {
        setEncryptionKey(encryptionKey);
        setEncryptionSalt(encryptionSalt);
        setCipherPoolSize(cipherPoolSize);
    }

    private static synchronized void setEncryptionKey(String encryptionKey) {
        CipherLogger.debug(EncryptionConfiguration.class, "Encryption key '" + encryptionKey + "'.");
        EncryptionConfiguration.encryptionKey = encryptionKey;
    }

    private static synchronized void setEncryptionSalt(String encryptionSalt) {
        CipherLogger.debug(EncryptionConfiguration.class, "Encryption salt '" + encryptionSalt + "'.");
        EncryptionConfiguration.encryptionSalt = encryptionSalt;
    }

    private static synchronized void setCipherPoolSize(String cipherPoolSize) {
        CipherLogger.debug(EncryptionConfiguration.class, "Cipher pool size '" + cipherPoolSize + "'.");
        EncryptionConfiguration.cipherPoolSize = cipherPoolSize;
    }


}
