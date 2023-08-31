package com.safencrypt.builder;

import com.safencrypt.exceptions.SafencryptException;
import com.safencrypt.enums.SymmetricAlgorithm;
import com.safencrypt.models.SymmetricCipher;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

class SafEncryptTest {


    @Test
    void testBuilderAES_GCM() {
        Assertions.assertDoesNotThrow(() -> {
            SafEncrypt.symmetricEncryption()
                    .generateKey()
                    .plaintext("sda".getBytes(StandardCharsets.UTF_8))
                    .encrypt();
        });
    }

    @Test
    void testBuilderAES_GCMWithAssociatedData() {
        Assertions.assertDoesNotThrow(() -> {
            SafEncrypt.symmetricEncryption(SymmetricAlgorithm.AES_GCM_192_NoPadding)
                    .generateKey()
                    .plaintext("ds".getBytes(StandardCharsets.UTF_8), "ads".getBytes(StandardCharsets.UTF_8))
                    .encrypt();
        });
    }

    @Test
    void testBuilderAES_CBC() {
        Assertions.assertDoesNotThrow(() -> {
            SafEncrypt.symmetricEncryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
                    .generateKey()
                    .plaintext("ds".getBytes(StandardCharsets.UTF_8))
                    .encrypt();
        });
    }

    @Test
    void testSettingAssociatedDataIncorrectAlgorithm() {

        Assertions.assertThrows(SafencryptException.class, () -> {
            SafEncrypt.symmetricEncryption(SymmetricAlgorithm.AES_CBC_192_PKCS5Padding)
                    .generateKey()
                    .plaintext("asd".getBytes(StandardCharsets.UTF_8), "ads".getBytes(StandardCharsets.UTF_8))
                    .encrypt();
        });


        SymmetricCipher symmetricCipher = new SymmetricCipher("iv".getBytes(StandardCharsets.UTF_8), "key".getBytes(StandardCharsets.UTF_8), "cipherText".getBytes(StandardCharsets.UTF_8), SymmetricAlgorithm.AES_CBC_192_PKCS5Padding);


        Assertions.assertThrows(SafencryptException.class, () -> {
            SafEncrypt.symmetricDecryption()
                    .key(symmetricCipher.key())
                    .iv(symmetricCipher.iv())
                    .cipherText(symmetricCipher.cipherText(), "associatedData".getBytes(StandardCharsets.UTF_8))
                    .decrypt();
        });


    }

    @Test
    void testBuilderForDefaultAlgorithm() {

        SymmetricCipher symmetricCipher =
                SafEncrypt.symmetricEncryption().generateKey()
                        .plaintext("ammar".getBytes(StandardCharsets.UTF_8))
                        .encrypt();

        Assertions.assertNotNull(symmetricCipher);

        SafEncrypt
                .symmetricDecryption()
                .key(symmetricCipher.key())
                .iv(symmetricCipher.iv())
                .cipherText(symmetricCipher.cipherText())
                .decrypt();
    }


}
