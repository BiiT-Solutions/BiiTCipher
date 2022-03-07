package com.biit.cipher;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class EncryptionConfiguration {

    public static String eventEncryptionKey;
    public static String eventEncryptionSalt;

    public EncryptionConfiguration(@Value("${encryption.key:}") String eventEncryptionKey, @Value("${encryption.salt:}") String eventEncryptionSalt) {
        setEventEncryptionKey(eventEncryptionKey);
    }

    private static synchronized void setEventEncryptionKey(String eventEncryptionKey) {
        EncryptionConfiguration.eventEncryptionKey = eventEncryptionKey;
    }

    private static synchronized void setEventEncryptionSalt(String eventEncryptionSalt) {
        EncryptionConfiguration.eventEncryptionSalt = eventEncryptionSalt;
    }


}
