package com.apigee.noderunner.core.test;

import com.apigee.noderunner.core.internal.CryptoAlgorithms;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.*;

public class CipherSuiteTest
{
    private static CryptoAlgorithms alg;

    @BeforeClass
    public static void init()
    {
        alg = CryptoAlgorithms.get();
    }

    @Test
    public void testNodeToJava()
    {
        ensureAlgorithm("aes-128-cbc", "AES/CBC/PKCS5Padding", 128, true);
        ensureAlgorithm("aes-128-cbc", "AES/CBC/NoPadding", 128, false);
        ensureAlgorithm("aes128", "AES/CBC/PKCS5Padding", 128, true);
        ensureAlgorithm("aes-192-ecb", "AES/ECB/PKCS5Padding", 192, true);
        ensureAlgorithm("des-cbc", "DES/CBC/PKCS5Padding", 0, true);
        ensureAlgorithm("des-ecb", "DES/ECB/PKCS5Padding", 0, true);
        ensureAlgorithm("des", "DES/CBC/PKCS5Padding", 0, true);
        ensureAlgorithm("des-ede-cbc", "DESede/CBC/PKCS5Padding", 0, true);
        ensureAlgorithm("des-ede-ecb", "DESede/ECB/PKCS5Padding", 0, true);
        ensureAlgorithm("des-ede", "DESede/CBC/PKCS5Padding", 0, true);
        ensureAlgorithm("des3", "DESede/CBC/PKCS5Padding", 0, true);
    }

    private void ensureAlgorithm(String name, String javaName, int len, boolean pad)
    {
        CryptoAlgorithms.Spec spec = alg.getAlgorithm(name, pad);
        assertNotNull(spec);
        assertEquals(javaName, spec.getName());
        assertEquals(len, spec.getKeyLen());

        try {
            Cipher.getInstance(javaName);
        } catch (NoSuchAlgorithmException e) {
            assertFalse("No such algorithm " + name + " (" + javaName + ')', true);
        } catch (NoSuchPaddingException e) {
            assertFalse("No such padding " + name + " (" + javaName + ')', true);
        }
    }
}
