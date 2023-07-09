package symmetric.service;

import com.wrapper.symmetric.builder.SafEncrypt;
import com.wrapper.symmetric.enums.KeyAlgorithm;
import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SafEncryptContainer;
import com.wrapper.symmetric.service.SymmetricKeyGenerator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;


class SymmetricImplFunctionalTest {

    @Test
    void testSymmetricEncryptionUsingAllDefaults1() {

        byte[] plainText = "Hello World".getBytes(StandardCharsets.UTF_8);

        SafEncryptContainer safEncryptContainer =
                SafEncrypt.encryption()
                        .generateKey()
                        .plaintext(plainText)
                        .encrypt();

        safEncryptContainer =
                SafEncrypt.decryption()
                        .key(safEncryptContainer.key())
                        .iv(safEncryptContainer.iv())
                        .cipherText(safEncryptContainer.ciphertext())
                        .decrypt();

        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(safEncryptContainer.plainText(), StandardCharsets.UTF_8));

    }


    @Test
    void testSymmetricEncryptionUsingDefaultAlgorithm() {

        byte[] plainText = "Hello World 121@#".getBytes(StandardCharsets.UTF_8);

        SafEncryptContainer safEncryptContainer =
                SafEncrypt.encryption()
                        .generateKey()
                        .plaintext(plainText)
                        .encrypt();

        safEncryptContainer =
                SafEncrypt.decryption()
                        .key(safEncryptContainer.key())
                        .iv(safEncryptContainer.iv())
                        .cipherText(safEncryptContainer.ciphertext())
                        .decrypt();

        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(safEncryptContainer.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    void testSymmetricEncryptionUsingKeyLoading2() {

        byte[] plainText = "Hello World 121@#".getBytes(StandardCharsets.UTF_8);
        byte[] key = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(key);

        SafEncryptContainer safEncryptContainer =
                SafEncrypt.encryption()
                        .loadKey(key)
                        .plaintext(plainText)
                        .encrypt();

        safEncryptContainer =
                SafEncrypt.decryption()
                        .key(safEncryptContainer.key())
                        .iv(safEncryptContainer.iv())
                        .cipherText(safEncryptContainer.ciphertext())
                        .decrypt();

        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(safEncryptContainer.plainText(), StandardCharsets.UTF_8));
    }

    @Test
    void testSymmetricEncryptionUsingKeyLoading2_2() {

        byte[] plainText = "Hello World 121@#".getBytes(StandardCharsets.UTF_8);
        byte[] key = SymmetricKeyGenerator.generateSymmetricKey(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding);

        SafEncryptContainer safEncryptContainer =
                SafEncrypt.encryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
                        .loadKey(key)
                        .plaintext(plainText)
                        .encrypt();

        safEncryptContainer =
                SafEncrypt.decryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
                        .key(safEncryptContainer.key())
                        .iv(safEncryptContainer.iv())
                        .cipherText(safEncryptContainer.ciphertext())
                        .decrypt();
        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(safEncryptContainer.plainText(), StandardCharsets.UTF_8));
    }

    @Test
    void testSymmetricEncryptionUsingDefaultKey3() {

        byte[] plainText = "1232F #$$^%$^ Hello World".getBytes(StandardCharsets.UTF_8);

        SafEncryptContainer safEncryptContainer =
                SafEncrypt.encryption(SymmetricAlgorithm.AES_GCM_256_NoPadding)
                        .generateKey()
                        .plaintext(plainText)
                        .encrypt();

        safEncryptContainer =
                SafEncrypt.decryption(safEncryptContainer.symmetricAlgorithm())
                        .key(safEncryptContainer.key())
                        .iv(safEncryptContainer.iv())
                        .cipherText(safEncryptContainer.ciphertext())
                        .decrypt();


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(safEncryptContainer.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    void testSymmetricEncryptionUsingAlgoKeyLoading4() {

        byte[] plainText = "Hello World JCA WRAPPER".getBytes(StandardCharsets.UTF_8);
        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_GCM_192_NoPadding;

        SafEncryptContainer safEncryptContainer =
                SafEncrypt.encryption(symmetricAlgorithm)
                        .generateKey()
                        .plaintext(plainText)
                        .encrypt();

        safEncryptContainer =
                SafEncrypt.decryption(safEncryptContainer.symmetricAlgorithm())
                        .key(safEncryptContainer.key())
                        .iv(safEncryptContainer.iv())
                        .cipherText(safEncryptContainer.ciphertext())
                        .decrypt();


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(safEncryptContainer.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    void testSymmetricEncryptionUsingGcmithoutAssociateData() {

        byte[] plainText = "Hello World JCA WRAPPER Using GCM Without AEAD".getBytes(StandardCharsets.UTF_8);

        SafEncryptContainer safEncryptContainer =
                SafEncrypt.encryption(SymmetricAlgorithm.AES_GCM_256_NoPadding)
                        .generateKey()
                        .plaintext(plainText)
                        .encrypt();

        safEncryptContainer =
                SafEncrypt.decryption(safEncryptContainer.symmetricAlgorithm())
                        .key(safEncryptContainer.key())
                        .iv(safEncryptContainer.iv())
                        .cipherText(safEncryptContainer.ciphertext())
                        .decrypt();


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(safEncryptContainer.plainText(), StandardCharsets.UTF_8));

    }

    @Test
    void testSymmetricEncryptionUsingGcmWithAssociateData5() {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_GCM_128_NoPadding;

        byte[] plainText = "Hello World JCA WRAPPER Using GCM With AEAD".getBytes(StandardCharsets.UTF_8);
        byte[] associatedData = "I am associated data".getBytes(StandardCharsets.UTF_8);

        SafEncryptContainer safEncryptContainer =
                SafEncrypt.encryption(SymmetricAlgorithm.AES_GCM_128_NoPadding)
                        .generateKey()
                        .plaintext(plainText, associatedData)
                        .encrypt();

        safEncryptContainer =
                SafEncrypt.decryption(safEncryptContainer.symmetricAlgorithm())
                        .key(safEncryptContainer.key())
                        .iv(safEncryptContainer.iv())
                        .cipherText(safEncryptContainer.ciphertext(), associatedData)
                        .decrypt();


        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(safEncryptContainer.plainText(), StandardCharsets.UTF_8));
    }

    @Test
    void testSymmetricEncryptionUsingCBC6() {

        byte[] plainText = "TESTING CBC 128 With PKCS5 PADDING".getBytes(StandardCharsets.UTF_8);

        SafEncryptContainer safEncryptContainer =
                SafEncrypt.encryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
                        .generateKey()
                        .plaintext(plainText)
                        .encrypt();

        safEncryptContainer =
                SafEncrypt.decryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
                        .key(safEncryptContainer.key())
                        .iv(safEncryptContainer.iv())
                        .cipherText(safEncryptContainer.ciphertext())
                        .decrypt();

        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(safEncryptContainer.plainText(), StandardCharsets.UTF_8));

    }


    @Test
    void testSymmetricEncryptionUsingGcmWithPBKeyDefault() {


        byte[] plainText = "Hello World JCA WRAPPER Using GCM With AEAD".getBytes(StandardCharsets.UTF_8);

        SafEncryptContainer safEncryptContainer =
                SafEncrypt.encryption(SymmetricAlgorithm.AES_GCM_256_NoPadding)
                        .generateKeyFromPassword("hellow testing gcm 128 with sha 512 key".getBytes())
                        .plaintext(plainText)
                        .encrypt();

        safEncryptContainer =
                SafEncrypt.decryption(safEncryptContainer.symmetricAlgorithm())
                        .key(safEncryptContainer.key())
                        .iv(safEncryptContainer.iv())
                        .cipherText(safEncryptContainer.ciphertext())
                        .decrypt();

        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(safEncryptContainer.plainText(), StandardCharsets.UTF_8));
    }

    @Test
    void testSymmetricEncryptionUsingGcmWithPBKeyAlgo() {

        byte[] plainText = "Hello World JCA WRAPPER Using GCM With AEAD".getBytes(StandardCharsets.UTF_8);

        SafEncryptContainer safEncryptContainer =
                SafEncrypt.encryption()
                        .generateKeyFromPassword("hellow testing gcm 128 and key with sha-256".getBytes(), KeyAlgorithm.PBKDF2_With_Hmac_SHA256)
                        .plaintext(plainText)
                        .encrypt();

        safEncryptContainer =
                SafEncrypt.decryption(safEncryptContainer.symmetricAlgorithm())
                        .key(safEncryptContainer.key())
                        .iv(safEncryptContainer.iv())
                        .cipherText(safEncryptContainer.ciphertext())
                        .decrypt();

        Assertions.assertEquals(new String(plainText, StandardCharsets.UTF_8), new String(safEncryptContainer.plainText(), StandardCharsets.UTF_8));
    }

}
