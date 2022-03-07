package com.biit.cipher;

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

}
