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

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.testng.AbstractTestNGSpringContextTests;
import org.testng.Assert;
import org.testng.annotations.Test;

@SpringBootTest
@Test(groups = "encryptorProperties")
public class EncryptorPropertyTest extends AbstractTestNGSpringContextTests {

    @Test
    public void checkKeyProperty() {
        Assert.assertEquals(EncryptionConfiguration.encryptionKey, "asd123");
    }

    public void checkSaltProperty() {
        Assert.assertEquals(EncryptionConfiguration.encryptionSalt, "123456");
    }

    public void checkCipherPoolSize() {
        Assert.assertEquals(EncryptionConfiguration.cipherPoolSize, "15");
    }

}
