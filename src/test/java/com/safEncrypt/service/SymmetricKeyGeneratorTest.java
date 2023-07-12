package com.safEncrypt.service;


import com.safEncrypt.enums.KeyAlgorithm;
import com.safEncrypt.enums.SymmetricAlgorithm;
import com.safEncrypt.service.SymmetricKeyGenerator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SymmetricKeyGeneratorTest {


    @Test
    public void createSymmetricDefaultKey() {
        Assertions.assertNotNull(SymmetricKeyGenerator.generateSymmetricKey());
    }


    @Test
    public void createSymmetricKey_GCM_192() {
        Assertions.assertNotNull(SymmetricKeyGenerator.generateSymmetricKey(SymmetricAlgorithm.AES_GCM_192_NoPadding));
    }

    @Test
    public void createSymmetricKey_CBC_256() {
        Assertions.assertNotNull(SymmetricKeyGenerator.generateSymmetricKey(SymmetricAlgorithm.AES_CBC_256_PKCS5Padding));
    }

    @Test
    public void createSymmetricKeyFromPasswordUsingDefaultAlgo() {
        Assertions.assertNotNull(SymmetricKeyGenerator.generateSymmetricKeyFromPassword("byte".getBytes(), 128));
    }

    @Test
    public void createSymmetricKeyFromPasswordUsingAlgo() {
        Assertions.assertNotNull(SymmetricKeyGenerator.generateSymmetricKeyFromPassword("byte".getBytes(), KeyAlgorithm.PBKDF2_With_Hmac_SHA256, 128));
    }
}
