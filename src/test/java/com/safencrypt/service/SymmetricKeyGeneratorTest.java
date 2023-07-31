package com.safencrypt.service;


import com.safencrypt.enums.KeyAlgorithm;
import com.safencrypt.enums.SymmetricAlgorithm;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class SymmetricKeyGeneratorTest {


    @Test
    void createSymmetricDefaultKey() {
        Assertions.assertNotNull(SymmetricKeyGenerator.generateSymmetricKey());
    }


    @Test
    void createSymmetricKey_GCM_192() {
        Assertions.assertNotNull(SymmetricKeyGenerator.generateSymmetricKey(SymmetricAlgorithm.AES_GCM_192_NoPadding));
    }

    @Test
    void createSymmetricKey_CBC_256() {
        Assertions.assertNotNull(SymmetricKeyGenerator.generateSymmetricKey(SymmetricAlgorithm.AES_CBC_256_PKCS5Padding));
    }

    @Test
    void createSymmetricKeyFromPasswordUsingDefaultAlgo() {
        Assertions.assertNotNull(SymmetricKeyGenerator.generateSymmetricKeyFromPassword("byte23241dsa".getBytes(), 128));
    }

    @Test
    void createSymmetricKeyFromPasswordUsingAlgo() {
        Assertions.assertNotNull(SymmetricKeyGenerator.generateSymmetricKeyFromPassword("sdfaaf$5423".getBytes(), KeyAlgorithm.PBKDF2_With_Hmac_SHA256, 128));
    }
}
