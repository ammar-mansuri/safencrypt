package symmetric.builder;

import com.wrapper.exceptions.SafencryptException;
import com.wrapper.symmetric.builder.SafEncrypt;
import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SafEncryptContainer;
import com.wrapper.symmetric.service.SymmetricKeyGenerator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

class SafEncryptTest {


    @Test
    void testBuilderAES_GCM() {
        SafEncrypt.encryption()
                .loadKey(SymmetricKeyGenerator.generateSymmetricKey())
                .plaintext("sda".getBytes(StandardCharsets.UTF_8))
                .encrypt();
    }

    @Test
    void testBuilderAES_GCMWithAssociatedData() {
        SafEncrypt.encryption(SymmetricAlgorithm.DEFAULT)
                .loadKey(SymmetricKeyGenerator.generateSymmetricKey())
                .plaintext("ds".getBytes(StandardCharsets.UTF_8), "ads".getBytes(StandardCharsets.UTF_8))
                .encrypt();
    }

    @Test
    void testBuilderAES_CBC() {
        SafEncrypt.encryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
                .loadKey(SymmetricKeyGenerator.generateSymmetricKey(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding))
                .plaintext("ds".getBytes(StandardCharsets.UTF_8))
                .encrypt();
    }

    @Test
    void testSettingAssociatedDataIncorrectAlgorithm() {

        Assertions.assertThrows(SafencryptException.class, () -> {
            SafEncrypt.encryption(SymmetricAlgorithm.AES_CBC_192_PKCS5Padding)
                    .loadKey(SymmetricKeyGenerator.generateSymmetricKey(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding))
                    .plaintext("asd".getBytes(StandardCharsets.UTF_8), "ads".getBytes(StandardCharsets.UTF_8))
                    .encrypt();
        });


        SafEncryptContainer.SymmetricCipher symmetricCipher = new SafEncryptContainer.SymmetricCipher("iv".getBytes(StandardCharsets.UTF_8), "key".getBytes(StandardCharsets.UTF_8), "ciphertext".getBytes(StandardCharsets.UTF_8), SymmetricAlgorithm.AES_CBC_192_PKCS5Padding);


        Assertions.assertThrows(SafencryptException.class, () -> {
            SafEncrypt.decryption()
                    .key(symmetricCipher.key())
                    .iv(symmetricCipher.iv())
                    .cipherText(symmetricCipher.ciphertext(), "associatedData".getBytes(StandardCharsets.UTF_8))
                    .decrypt();
        });


    }

    @Test
    void testBuilderForDefaultAlgorithm() {

        SafEncryptContainer safEncryptContainer =
                SafEncrypt.encryption().generateKey()
                        .plaintext("ammar".getBytes(StandardCharsets.UTF_8))
                        .encrypt();

        SafEncrypt
                .decryption()
                .key(safEncryptContainer.key())
                .iv(safEncryptContainer.iv())
                .cipherText(safEncryptContainer.ciphertext())
                .decrypt();
    }


}
