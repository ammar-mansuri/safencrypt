package com.safencrypt.service;

import com.safencrypt.enums.SymmetricAlgorithm;
import com.safencrypt.builder.SafEncrypt;
import com.safencrypt.config.SymmetricInteroperabilityConfig;
import com.safencrypt.models.SymmetricCipher;
import com.safencrypt.models.SymmetricCipherBase64;
import com.safencrypt.utils.Utility;
import com.safencrypt.utils.Base64Decoder;
import lombok.SneakyThrows;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Objects;

import static com.safencrypt.utils.Utility.isGCM;

public class SymmetricInteroperable {

    private final SymmetricKeyStore symmetricKeyStore;

    private final SymmetricInteroperabilityConfig symmetricInteroperabilityConfig;

    private final SymmetricImpl symmetric;

    public SymmetricInteroperable(SymmetricKeyStore symmetricKeyStore, SymmetricInteroperabilityConfig symmetricInteroperabilityConfig, SymmetricImpl symmetric) {
        this.symmetricKeyStore = symmetricKeyStore;
        this.symmetricInteroperabilityConfig = symmetricInteroperabilityConfig;
        this.symmetric = symmetric;
    }

    @SneakyThrows
    public SymmetricCipherBase64 interoperableEncrypt(SafEncrypt symmetricBuilder) {

        Objects.nonNull(symmetricBuilder.getSymmetricInteroperabilityLanguages());

        final SymmetricInteroperabilityConfig.Details languageDetails = symmetricInteroperabilityConfig.languageDetails(symmetricBuilder.getSymmetricInteroperabilityLanguages().name());

        final SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.fromLabel(languageDetails.symmetric().defaultAlgo());


        final SecretKey secretKey = new SecretKeySpec(SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm), "AES");

        final SymmetricCipher symmetricCipher;

        if (isGCM(symmetricAlgorithm)) {
            symmetricCipher = symmetric.encryptWithGCM(languageDetails.symmetric().tagSize(), languageDetails.symmetric().ivSize(), symmetricAlgorithm, secretKey, symmetricBuilder.getPlainText(), symmetricBuilder.getAssociatedData());
        } else {
            symmetricCipher = symmetric.encrypt(languageDetails.symmetric().ivSize(), symmetricAlgorithm, secretKey, symmetricBuilder.getPlainText());
        }

        final String alias = "alias_" + System.currentTimeMillis();
        symmetricKeyStore.saveKey(alias, secretKey);


        return Utility.getSymmetricEncodedResult(symmetricCipher, alias);

    }

    @SneakyThrows
    public byte[] interoperableDecrypt(SafEncrypt symmetricBuilder) {

        Objects.nonNull(symmetricBuilder.getSymmetricInteroperabilityLanguages());

        final SymmetricInteroperabilityConfig.Details languageDetails = symmetricInteroperabilityConfig.languageDetails(symmetricBuilder.getSymmetricInteroperabilityLanguages().name());

        final SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.fromLabel(languageDetails.symmetric().defaultAlgo());

        final byte[] cipherBytes;

        /**
         * Extension for providing Tag Separately for AES_GCM
         */
        /*if (symmetricAlgorithm.getLabel().startsWith("AES_GCM")) {
            byte[] ciphertextBytes = Base64Decoder.decodeBase64(symmetricBuilder.getCipherTextBase64());
            byte[] tagBytes = Base64Decoder.decodeBase64(symmetricBuilder.getTagBase64());
            cipherBytes = new byte[ciphertextBytes.length + tagBytes.length];
            System.arraycopy(ciphertextBytes, 0, cipherBytes, 0, ciphertextBytes.length);
            System.arraycopy(tagBytes, 0, cipherBytes, ciphertextBytes.length, tagBytes.length);

        }*/

        cipherBytes = Base64Decoder.decodeBase64(symmetricBuilder.getCipherTextBase64());


        return isGCM(symmetricAlgorithm) ?
                symmetric.decryptWithGCM(languageDetails.symmetric().tagSize(), languageDetails.symmetric().ivSize(), symmetricAlgorithm, symmetricKeyStore.loadKey(symmetricBuilder.getKeyAlias()), Base64Decoder.decodeBase64(symmetricBuilder.getIvBase64()), cipherBytes, symmetricBuilder.getAssociatedData()) :
                symmetric.decrypt(languageDetails.symmetric().ivSize(), symmetricAlgorithm, symmetricKeyStore.loadKey(symmetricBuilder.getKeyAlias()), Base64Decoder.decodeBase64(symmetricBuilder.getIvBase64()), cipherBytes);

    }
}
