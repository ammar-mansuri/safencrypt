package com.safencrypt.service;

import com.safencrypt.builder.SafEncrypt;
import com.safencrypt.enums.SymmetricAlgorithm;
import com.safencrypt.enums.SymmetricInteroperabilityLanguages;
import com.safencrypt.models.SymmetricCipherBase64;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

class SymmetricInteroperabilityTest {

    @Test
    void testSymmetricInteroperabilityWithCSharp() {

        byte[] plainText = "Test for C# Which Uses Algorithm that Doesnt Ensure Integrity".getBytes(StandardCharsets.UTF_8);

        SymmetricCipherBase64 symmetricCipherBase64 = SafEncrypt.symmetricInteroperableEncryption(SymmetricInteroperabilityLanguages.CSharp)
                .plaintext(plainText)
                .encrypt();

        byte[] decryptedText = SafEncrypt.symmetricInteroperableDecryption(SymmetricInteroperabilityLanguages.CSharp)
                .keyAlias(symmetricCipherBase64.keyAlias())
                .ivBase64(symmetricCipherBase64.iv())
                .cipherTextBase64(symmetricCipherBase64.cipherText())
                .decrypt();


        System.out.println(symmetricCipherBase64);
        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(decryptedText, StandardCharsets.UTF_8));
    }


    @Test
    void testSymmetricEncryptionInteroperabilityWithPythonWithCBC() {

        byte[] plainText = "TU Clausthal Located in Clausthal Zellerfeld".getBytes(StandardCharsets.UTF_8);

        SymmetricCipherBase64 symmetricCipherBase64 = SafEncrypt.symmetricInteroperableEncryption(SymmetricInteroperabilityLanguages.Python)
                .plaintext(plainText)
                .encrypt();

        Assertions.assertNotNull(symmetricCipherBase64);
        System.out.println(symmetricCipherBase64);
    }


    @Test
    void testSymmetricDecryptionInteroperabilityWithPythonWithCBC() {

        byte[] plainText = "TU Clausthal Located in Clausthal Zellerfeld".getBytes(StandardCharsets.UTF_8);

        SymmetricCipherBase64 symmetricCipherBase64 = SafEncrypt.symmetricInteroperableEncryption(SymmetricInteroperabilityLanguages.Python)
                .plaintext(plainText)
                .encrypt();

        Assertions.assertNotNull(symmetricCipherBase64);
        System.out.println(symmetricCipherBase64);
    }


    @Test
    void testSymmetricEncryptionInteroperabilityWithPython() {

        byte[] plainText = "TU Clausthal Located in Clausthal Zellerfeld".getBytes(StandardCharsets.UTF_8);

        SymmetricCipherBase64 symmetricCipherBase64 = SafEncrypt.symmetricInteroperableEncryption(SymmetricInteroperabilityLanguages.Python)
                .plaintext(plainText)
                .encrypt();

        Assertions.assertNotNull(symmetricCipherBase64);
        System.out.println(symmetricCipherBase64);
    }


    @Test
    void generalDecryptFromPython() {

        byte[] ciphertextBytes = Base64.getDecoder().decode("lJipwcZuQ+0no1s=".getBytes());
        byte[] tagBytes = Base64.getDecoder().decode("ypgsDoaFKGj06ljQ".getBytes());
        byte[] ciphertextTagBytes = new byte[ciphertextBytes.length + tagBytes.length];
        System.arraycopy(ciphertextBytes, 0, ciphertextTagBytes, 0, ciphertextBytes.length);
        System.arraycopy(tagBytes, 0, ciphertextTagBytes, ciphertextBytes.length, tagBytes.length);

        byte[] decryptedText = SafEncrypt.symmetricDecryption(SymmetricAlgorithm.AES_GCM_128_NoPadding)
                .key(Base64.getDecoder().decode("2Gn4xCkAioEBk21QY9BWCw==".getBytes()))
                .iv(Base64.getDecoder().decode("MXA8iL1gvl6i7Qx6".getBytes()))
                .cipherText(ciphertextTagBytes)
                .decrypt();

        Assertions.assertEquals("Hello World", new String(decryptedText, StandardCharsets.UTF_8));

    }

    @Test
    void testSymmetricEncryptionInteroperabilityWithJavaScript_GCM() {

        byte[] plainText = "TU Clausthal Located in Clausthal Zellerfeld".getBytes(StandardCharsets.UTF_8);
        byte[] associatedData = "First test using AEAD".getBytes(StandardCharsets.UTF_8);

        SymmetricCipherBase64 symmetricCipherBase64 = SafEncrypt.symmetricInteroperableEncryption(SymmetricInteroperabilityLanguages.Sample_JavaScript)
                .plaintext(plainText)
                .optionalAssociatedData(associatedData)
                .encrypt();

        byte[] decryptedText = SafEncrypt.symmetricInteroperableDecryption(SymmetricInteroperabilityLanguages.Sample_JavaScript)
                .keyAlias(symmetricCipherBase64.keyAlias())
                .ivBase64(symmetricCipherBase64.iv())
                .cipherTextBase64(symmetricCipherBase64.cipherText())
                .optionalAssociatedData(associatedData)
                .decrypt();

        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(decryptedText, StandardCharsets.UTF_8));
    }

}
