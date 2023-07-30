package com.safencrypt.builder;

import com.safencrypt.exceptions.SafencryptException;
import com.safencrypt.enums.SymmetricAlgorithm;
import com.safencrypt.models.SymmetricCipher;
import com.safencrypt.service.SymmetricKeyGenerator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

class SafEncryptTest {


    @Test
    void testBuilderAES_GCM() {
        SafEncrypt.symmetricEncryption()
                .loadKey(SymmetricKeyGenerator.generateSymmetricKey())
                .plaintext("sda".getBytes(StandardCharsets.UTF_8))
                .encrypt();
    }

    @Test
    void testBuilderAES_GCMWithAssociatedData() {
        SafEncrypt.symmetricEncryption(SymmetricAlgorithm.DEFAULT)
                .loadKey(SymmetricKeyGenerator.generateSymmetricKey())
                .plaintext("ds".getBytes(StandardCharsets.UTF_8), "ads".getBytes(StandardCharsets.UTF_8))
                .encrypt();
    }

    @Test
    void testBuilderAES_CBC() {
        SafEncrypt.symmetricEncryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
                .loadKey(SymmetricKeyGenerator.generateSymmetricKey(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding))
                .plaintext("ds".getBytes(StandardCharsets.UTF_8))
                .encrypt();
    }

    @Test
    void testSettingAssociatedDataIncorrectAlgorithm() {

        Assertions.assertThrows(SafencryptException.class, () -> {
            SafEncrypt.symmetricEncryption(SymmetricAlgorithm.AES_CBC_192_PKCS5Padding)
                    .loadKey(SymmetricKeyGenerator.generateSymmetricKey(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding))
                    .plaintext("asd".getBytes(StandardCharsets.UTF_8), "ads".getBytes(StandardCharsets.UTF_8))
                    .encrypt();
        });


        SymmetricCipher symmetricCipher = new SymmetricCipher("iv".getBytes(StandardCharsets.UTF_8), "key".getBytes(StandardCharsets.UTF_8), "cipherText".getBytes(StandardCharsets.UTF_8), SymmetricAlgorithm.AES_CBC_192_PKCS5Padding);


        Assertions.assertThrows(SafencryptException.class, () -> {
            SafEncrypt.symmetricDecryption()
                    .key(((SymmetricCipher) symmetricCipher).key())
                    .iv(((SymmetricCipher) symmetricCipher).iv())
                    .cipherText(((SymmetricCipher) symmetricCipher).ciphertext(), "associatedData".getBytes(StandardCharsets.UTF_8))
                    .decrypt();
        });


    }

    @Test
    void testBuilderForDefaultAlgorithm() {

        SymmetricCipher symmetricCipher =
                SafEncrypt.symmetricEncryption().generateKey()
                        .plaintext("ammar".getBytes(StandardCharsets.UTF_8))
                        .encrypt();

        SafEncrypt
                .symmetricDecryption()
                .key(symmetricCipher.key())
                .iv(symmetricCipher.iv())
                .cipherText(symmetricCipher.ciphertext())
                .decrypt();
    }


}
