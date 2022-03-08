package com.biit.cipher;

import com.biit.utils.pool.LimitedPool;

import javax.crypto.Cipher;

public abstract class CipherPool extends LimitedPool<Cipher> {
    private static final long EXPIRATION_TIME = 5 * 60 * 1000L;
    private static final int MAX_ITEMS = 10;

    @Override
    public int getMaxElements() {
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
