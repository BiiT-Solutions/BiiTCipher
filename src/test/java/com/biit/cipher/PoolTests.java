package com.biit.cipher;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.testng.AbstractTestNGSpringContextTests;
import org.testng.Assert;
import org.testng.annotations.Test;

@SpringBootTest
@Test(groups = "poolTest")
public class PoolTests extends AbstractTestNGSpringContextTests {
    private DecryptCipherPool decryptCipherPool = new DecryptCipherPool();
    private EncryptCipherPool encryptCipherPool = new EncryptCipherPool();

    public void checkPoolSizes() {
        Assert.assertEquals(decryptCipherPool.getMaxElements(), 15);
        Assert.assertEquals(encryptCipherPool.getMaxElements(), 15);
    }
}
