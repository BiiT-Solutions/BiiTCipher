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
