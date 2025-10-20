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
import com.biit.utils.pool.LimitedPool;

import javax.crypto.Cipher;

import static com.biit.cipher.EncryptionConfiguration.cipherPoolSize;

public abstract class CipherPool extends LimitedPool<Cipher> {
    private static final long EXPIRATION_TIME = 5 * 60 * 1000L;
    private static final int MAX_ITEMS = 10;
    private static boolean warningShown = false;

    @Override
    public int getMaxElements() {
        if (cipherPoolSize != null) {
            try {
                return Integer.parseInt(cipherPoolSize);
            } catch (NumberFormatException ignored) {
            }
        }
        if (!warningShown) {
            CipherLogger.warning(this.getClass(), "Invalid value '" + cipherPoolSize + "' on property 'cipher.pool.size' using default value '"
                    + MAX_ITEMS + "'.");
            warningShown = true;
        }
        return MAX_ITEMS;
    }

    @Override
    public long getExpirationTime() {
        return EXPIRATION_TIME;
    }

    @Override
    public boolean isDirty(Cipher cipher) {
        return false;
    }
}
