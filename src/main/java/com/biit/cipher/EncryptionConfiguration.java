package com.biit.cipher;

/*-
 * #%L
 * Basic Cipher tool
 * %%
 * Copyright (C) 2022 - 2025 BiiT Sourcing Solutions S.L.
 * %%
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * #L%
 */

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
