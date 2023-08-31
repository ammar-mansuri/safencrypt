package com.safencrypt.service;

import com.safencrypt.builder.SafEncrypt;
import com.safencrypt.enums.KeyAlgorithm;
import com.safencrypt.enums.SymmetricAlgorithm;
import com.safencrypt.models.SymmetricCipher;
import com.safencrypt.models.SymmetricStreamingCipher;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;


class SymmetricImplFunctionalTest {

    private static final String resources_path = "src/test/resources/streamingSamples/";

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
                        .cipherText(symmetricCipher.cipherText())
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
                        .cipherText(symmetricCipher.cipherText())
                        .decrypt();

        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(decryptedText, StandardCharsets.UTF_8));

    }


    @Test
    void testSymmetricEncryptionUsingPassword2_1() {

        byte[] plainText = "Hello World 121@#".getBytes(StandardCharsets.UTF_8);

        SymmetricCipher symmetricCipher =
                SafEncrypt.symmetricEncryption(SymmetricAlgorithm.AES_GCM_192_NoPadding)
                        .generateKeyFromPassword("@34StrongPassword".toCharArray())
                        .plaintext(plainText)
                        .encrypt();

        byte[] decryptedText =
                SafEncrypt.symmetricDecryption(SymmetricAlgorithm.AES_GCM_192_NoPadding)
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.cipherText())
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
                        .cipherText(symmetricCipher.cipherText())
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
                        .cipherText(symmetricCipher.cipherText())
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
                        .cipherText(symmetricCipher.cipherText())
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
                        .cipherText(symmetricCipher.cipherText(), associatedData)
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
                        .cipherText(symmetricCipher.cipherText())
                        .decrypt();

        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(decryptedText, StandardCharsets.UTF_8));

    }


    @Test
    void testSymmetricEncryptionUsingGcmWithPBKeyDefault() {


        byte[] plainText = "Hello World JCA WRAPPER Using GCM With AEAD".getBytes(StandardCharsets.UTF_8);

        SymmetricCipher symmetricCipher =
                SafEncrypt.symmetricEncryption(SymmetricAlgorithm.AES_GCM_256_NoPadding)
                        .generateKeyFromPassword("hellow testing gcm 128 with sha 512 key".toCharArray())
                        .plaintext(plainText)
                        .encrypt();

        byte[] decryptedText =
                SafEncrypt.symmetricDecryption(symmetricCipher.symmetricAlgorithm())
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.cipherText())
                        .decrypt();

        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(decryptedText, StandardCharsets.UTF_8));
    }

    @Test
    void testSymmetricEncryptionUsingGcmWithPBKeyAlgo() {

        byte[] plainText = "Hello World JCA WRAPPER Using GCM With AEAD".getBytes(StandardCharsets.UTF_8);

        SymmetricCipher symmetricCipher =
                SafEncrypt.symmetricEncryption()
                        .generateKeyFromPassword("hellow testing gcm 128 and key with sha-256".toCharArray(), KeyAlgorithm.PBKDF2_With_Hmac_SHA256)
                        .plaintext(plainText)
                        .encrypt();

        byte[] decryptedText =
                SafEncrypt.symmetricDecryption(symmetricCipher.symmetricAlgorithm())
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.cipherText())
                        .decrypt();

        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(decryptedText, StandardCharsets.UTF_8));
    }


    @Test
    void testSymmetricStreamingEncryptionTextFileUsingAllDefaults1() {


        SymmetricStreamingCipher symmetricStreamingCipher =
                SafEncrypt.symmetricEncryption()
                        .generateKey()
                        .plainFileStream(new File(resources_path + "input/plainTextFile.txt"), new File(resources_path + "output/plainTextEncFile.txt"))
                        .encrypt();

        Assertions.assertNotNull(symmetricStreamingCipher);

        SafEncrypt.symmetricDecryption()
                .key(symmetricStreamingCipher.key())
                .iv(symmetricStreamingCipher.iv())
                .cipherFileStream(new File(resources_path + "output/plainTextEncFile.txt"), new File(resources_path + "output/plainTextDecFile.txt"))
                .decrypt();
    }

    @Test
    void testSymmetricStreamingEncryptionTextFileUsingCBC() {


        SymmetricStreamingCipher symmetricStreamingCipher =
                SafEncrypt.symmetricEncryption(SymmetricAlgorithm.AES_CBC_256_PKCS5Padding)
                        .generateKey()
                        .plainFileStream(new File(resources_path + "input/dummy_image.png"), new File(resources_path + "output/cipherImage.png"))
                        .encrypt();

        Assertions.assertNotNull(symmetricStreamingCipher);

        SafEncrypt.symmetricDecryption(SymmetricAlgorithm.AES_CBC_256_PKCS5Padding)
                .key(symmetricStreamingCipher.key())
                .iv(symmetricStreamingCipher.iv())
                .cipherFileStream(new File(resources_path + "output/cipherImage.png"), new File(resources_path + "output/dummy_image_dec.png"))
                .decrypt();
    }

    @Test
    void testSymmetricStreamingEncryptionTextFileUsingPBKEY() {


        SymmetricStreamingCipher symmetricStreamingCipher =
                SafEncrypt.symmetricEncryption(SymmetricAlgorithm.AES_GCM_192_NoPadding)
                        .generateKeyFromPassword("filePassword$52#".toCharArray())
                        .plainFileStream(new File(resources_path + "input/plainTextFile.txt"), new File(resources_path + "output/plainTextEncFile.txt"))
                        .encrypt();

        Assertions.assertNotNull(symmetricStreamingCipher);

        SafEncrypt.symmetricDecryption(SymmetricAlgorithm.AES_GCM_192_NoPadding)
                .key(symmetricStreamingCipher.key())
                .iv(symmetricStreamingCipher.iv())
                .cipherFileStream(new File(resources_path + "output/plainTextEncFile.txt"), new File(resources_path + "output/plainTextDecFile.txt"))
                .decrypt();
    }


}
