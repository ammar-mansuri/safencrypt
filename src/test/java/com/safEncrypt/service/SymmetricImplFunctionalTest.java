package com.safEncrypt.service;

import com.safEncrypt.builder.SafEncrypt;
import com.safEncrypt.enums.KeyAlgorithm;
import com.safEncrypt.enums.SymmetricAlgorithm;
import com.safEncrypt.models.SymmetricCipher;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;


class SymmetricImplFunctionalTest {

    @Test
    void testSymmetricEncryptionUsingAllDefaults1() {

        byte[] plainText = "Hello World".getBytes(StandardCharsets.UTF_8);

        SymmetricCipher symmetricCipher =
                SafEncrypt.symmetricEncryption()
                        .generateKey()
                        .plaintext(plainText)
                        .encrypt();


        byte[] decryptedText =
                SafEncrypt.symmetricDecryption()
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext())
                        .decrypt();

        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(decryptedText, StandardCharsets.UTF_8));

    }


    @Test
    void testSymmetricEncryptionUsingDefaultAlgorithm() {

        byte[] plainText = "Hello World 121@#".getBytes(StandardCharsets.UTF_8);

        SymmetricCipher symmetricCipher =
                SafEncrypt.symmetricEncryption()
                        .generateKey()
                        .plaintext(plainText)
                        .encrypt();

        byte[] decryptedText =
                SafEncrypt.symmetricDecryption()
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext())
                        .decrypt();

        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(decryptedText, StandardCharsets.UTF_8));

    }

    @Test
    void testSymmetricEncryptionUsingKeyLoading2() {

        byte[] plainText = "Hello World 121@#".getBytes(StandardCharsets.UTF_8);
        byte[] key = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(key);

        SymmetricCipher symmetricCipher =
                SafEncrypt.symmetricEncryption()
                        .loadKey(key)
                        .plaintext(plainText)
                        .encrypt();

        byte[] decryptedText =
                SafEncrypt.symmetricDecryption()
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext())
                        .decrypt();

        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(decryptedText, StandardCharsets.UTF_8));
    }

    @Test
    void testSymmetricEncryptionUsingKeyLoading2_2() {

        byte[] plainText = "Hello World 121@#".getBytes(StandardCharsets.UTF_8);
        byte[] key = SymmetricKeyGenerator.generateSymmetricKey(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding);

        SymmetricCipher symmetricCipher =
                SafEncrypt.symmetricEncryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
                        .loadKey(key)
                        .plaintext(plainText)
                        .encrypt();

        byte[] decryptedText =
                SafEncrypt.symmetricDecryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext())
                        .decrypt();
        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(decryptedText, StandardCharsets.UTF_8));
    }

    @Test
    void testSymmetricEncryptionUsingDefaultKey3() {

        byte[] plainText = "1232F #$$^%$^ Hello World".getBytes(StandardCharsets.UTF_8);

        SymmetricCipher symmetricCipher =
                SafEncrypt.symmetricEncryption(SymmetricAlgorithm.AES_GCM_256_NoPadding)
                        .generateKey()
                        .plaintext(plainText)
                        .encrypt();

        byte[] decryptedText =
                SafEncrypt.symmetricDecryption(symmetricCipher.symmetricAlgorithm())
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext())
                        .decrypt();


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(decryptedText, StandardCharsets.UTF_8));

    }

    @Test
    void testSymmetricEncryptionUsingAlgoKeyLoading4() {

        byte[] plainText = "Hello World JCA WRAPPER".getBytes(StandardCharsets.UTF_8);
        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_GCM_192_NoPadding;

        SymmetricCipher symmetricCipher =
                SafEncrypt.symmetricEncryption(symmetricAlgorithm)
                        .generateKey()
                        .plaintext(plainText)
                        .encrypt();

        byte[] decryptedText =
                SafEncrypt.symmetricDecryption(symmetricCipher.symmetricAlgorithm())
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext())
                        .decrypt();


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(decryptedText, StandardCharsets.UTF_8));

    }

    @Test
    void testSymmetricEncryptionUsingGcmWithoutAssociateData() {

        byte[] plainText = "Hello World JCA WRAPPER Using GCM Without AEAD".getBytes(StandardCharsets.UTF_8);

        SymmetricCipher symmetricCipher =
                SafEncrypt.symmetricEncryption(SymmetricAlgorithm.AES_GCM_256_NoPadding)
                        .generateKey()
                        .plaintext(plainText)
                        .encrypt();

        byte[] decryptedText =
                SafEncrypt.symmetricDecryption(symmetricCipher.symmetricAlgorithm())
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext())
                        .decrypt();


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(decryptedText, StandardCharsets.UTF_8));

    }

    @Test
    void testSymmetricEncryptionUsingGcmWithAssociateData5() {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_GCM_128_NoPadding;

        byte[] plainText = "Hello World JCA WRAPPER Using GCM With AEAD".getBytes(StandardCharsets.UTF_8);
        byte[] associatedData = "I am associated data".getBytes(StandardCharsets.UTF_8);

        SymmetricCipher symmetricCipher =
                SafEncrypt.symmetricEncryption(SymmetricAlgorithm.AES_GCM_128_NoPadding)
                        .generateKey()
                        .plaintext(plainText, associatedData)
                        .encrypt();

        byte[] decryptedText =
                SafEncrypt.symmetricDecryption(symmetricCipher.symmetricAlgorithm())
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext(), associatedData)
                        .decrypt();


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(decryptedText, StandardCharsets.UTF_8));
    }

    @Test
    void testSymmetricEncryptionUsingCBC6() {

        byte[] plainText = "TESTING CBC 128 With PKCS5 PADDING".getBytes(StandardCharsets.UTF_8);

        SymmetricCipher symmetricCipher =
                SafEncrypt.symmetricEncryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
                        .generateKey()
                        .plaintext(plainText)
                        .encrypt();

        byte[] decryptedText =
                SafEncrypt.symmetricDecryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext())
                        .decrypt();

        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(decryptedText, StandardCharsets.UTF_8));

    }


    @Test
    void testSymmetricEncryptionUsingGcmWithPBKeyDefault() {


        byte[] plainText = "Hello World JCA WRAPPER Using GCM With AEAD".getBytes(StandardCharsets.UTF_8);

        SymmetricCipher symmetricCipher =
                SafEncrypt.symmetricEncryption(SymmetricAlgorithm.AES_GCM_256_NoPadding)
                        .generateKeyFromPassword("hellow testing gcm 128 with sha 512 key".getBytes())
                        .plaintext(plainText)
                        .encrypt();

        byte[] decryptedText =
                SafEncrypt.symmetricDecryption(symmetricCipher.symmetricAlgorithm())
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext())
                        .decrypt();

        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(decryptedText, StandardCharsets.UTF_8));
    }

    @Test
    void testSymmetricEncryptionUsingGcmWithPBKeyAlgo() {

        byte[] plainText = "Hello World JCA WRAPPER Using GCM With AEAD".getBytes(StandardCharsets.UTF_8);

        SymmetricCipher symmetricCipher =
                SafEncrypt.symmetricEncryption()
                        .generateKeyFromPassword("hellow testing gcm 128 and key with sha-256".getBytes(), KeyAlgorithm.PBKDF2_With_Hmac_SHA256)
                        .plaintext(plainText)
                        .encrypt();

        byte[] decryptedText =
                SafEncrypt.symmetricDecryption(symmetricCipher.symmetricAlgorithm())
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext())
                        .decrypt();

        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(decryptedText, StandardCharsets.UTF_8));
    }

}
