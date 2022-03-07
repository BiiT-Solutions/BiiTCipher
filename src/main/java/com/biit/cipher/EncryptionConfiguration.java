package com.biit.cipher;

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
        EncryptionConfiguration.encryptionKey = encryptionKey;
    }

    private static synchronized void setEncryptionSalt(String encryptionSalt) {
        EncryptionConfiguration.encryptionSalt = encryptionSalt;
    }


}
