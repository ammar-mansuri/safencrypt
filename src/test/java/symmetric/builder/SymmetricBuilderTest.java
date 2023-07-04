package symmetric.builder;

import com.wrapper.symmetric.builder.SymmetricBuilder;
import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SymmetricCipher;
import com.wrapper.symmetric.service.SymmetricKeyGenerator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

class SymmetricBuilderTest {


    @Test
    void testBuilderAES_GCM() {
        SymmetricBuilder.encryption()
                .loadKey(SymmetricKeyGenerator.generateSymmetricKey())
                .plaintext("sda".getBytes(StandardCharsets.UTF_8))
                .encrypt();
    }

    @Test
    void testBuilderAES_GCMWithAssociatedData() {
        SymmetricBuilder.encryption(SymmetricAlgorithm.DEFAULT)
                .loadKey(SymmetricKeyGenerator.generateSymmetricKey())
                .plaintext("ds".getBytes(StandardCharsets.UTF_8), "ads".getBytes(StandardCharsets.UTF_8))
                .encrypt();
    }

    @Test
    void testBuilderAES_CBC() {
        SymmetricBuilder.encryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
                .loadKey(SymmetricKeyGenerator.generateSymmetricKey(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding))
                .plaintext("ds".getBytes(StandardCharsets.UTF_8))
                .encrypt();
    }

    @Test
    void testSettingAssociatedDataIncorrectAlgorithm() {

        Assertions.assertThrows(Exception.class, () -> {
            SymmetricBuilder.encryption(SymmetricAlgorithm.AES_CBC_192_PKCS5Padding)
                    .loadKey(SymmetricKeyGenerator.generateSymmetricKey(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding))
                    .plaintext("asd".getBytes(StandardCharsets.UTF_8), "ads".getBytes(StandardCharsets.UTF_8))
                    .encrypt();
        });


        SymmetricCipher symmetricCipher = new SymmetricCipher("iv".getBytes(StandardCharsets.UTF_8), "key".getBytes(StandardCharsets.UTF_8), "ciphertext".getBytes(StandardCharsets.UTF_8), SymmetricAlgorithm.AES_CBC_192_PKCS5Padding);

        Assertions.assertThrows(Exception.class, () -> {
            SymmetricBuilder.decryption()
                    .key(symmetricCipher.key())
                    .iv(symmetricCipher.iv())
                    .cipherText(symmetricCipher.ciphertext(), "associatedData".getBytes(StandardCharsets.UTF_8))
                    .decrypt();
        });


    }

    @Test
    void testBuilderForDefaultAlgorithm() {

        SymmetricCipher symmetricCipher =
                SymmetricBuilder.encryption().generateKey()
                        .plaintext("ammar".getBytes(StandardCharsets.UTF_8))
                        .encrypt();

        SymmetricBuilder
                .decryption()
                .key(symmetricCipher.key())
                .iv(symmetricCipher.iv())
                .cipherText(symmetricCipher.ciphertext())
                .decrypt();
    }


}
