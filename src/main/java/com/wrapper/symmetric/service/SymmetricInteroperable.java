package com.wrapper.symmetric.service;

import com.wrapper.symmetric.builder.SymmetricInteroperableBuilder;
import com.wrapper.symmetric.config.SymmetricConfig;
import com.wrapper.symmetric.config.SymmetricInteroperabilityConfig;
import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SymmetricCipher;
import com.wrapper.symmetric.models.SymmetricCipherBase64;
import com.wrapper.symmetric.models.SymmetricPlain;
import com.wrapper.symmetric.utils.Utility;
import lombok.SneakyThrows;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Objects;

import static com.wrapper.symmetric.utils.Base64Decoder.decodeBase64;
import static com.wrapper.symmetric.utils.Utility.isGCM;

public class SymmetricInteroperable {

    private final SymmetricConfig symmetricConfig;

    private final SymmetricKeyStore symmetricKeyStore;

    private final SymmetricInteroperabilityConfig symmetricInteroperabilityConfig;

    private final SymmetricImpl symmetric;

    public SymmetricInteroperable(SymmetricConfig symmetricConfig, SymmetricKeyStore symmetricKeyStore, SymmetricInteroperabilityConfig symmetricInteroperabilityConfig, SymmetricImpl symmetric) {
        this.symmetricConfig = symmetricConfig;
        this.symmetricKeyStore = symmetricKeyStore;
        this.symmetricInteroperabilityConfig = symmetricInteroperabilityConfig;
        this.symmetric = symmetric;
    }

    @SneakyThrows
    public SymmetricCipherBase64 interoperableEncrypt(SymmetricInteroperableBuilder symmetricBuilder) {

        Objects.nonNull(symmetricBuilder.getSymmetricInteroperabilityLanguages());

        SymmetricInteroperabilityConfig.Details languageDetails = symmetricInteroperabilityConfig.languageDetails(symmetricBuilder.getSymmetricInteroperabilityLanguages().name());

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.fromLabel(languageDetails.symmetric().defaultAlgo());


        SecretKey secretKey = new SecretKeySpec(SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm), "AES");

        SymmetricCipher symmetricCipher;

        if (isGCM(symmetricAlgorithm)) {
            symmetricCipher = symmetric.encryptWithGCM(languageDetails.symmetric().tagLength(), languageDetails.symmetric().ivBytes(), symmetricAlgorithm, secretKey, symmetricBuilder.getPlainText(), symmetricBuilder.getAssociatedData());
        } else {
            symmetricCipher = symmetric.encrypt(languageDetails.symmetric().ivBytes(), symmetricAlgorithm, secretKey, symmetricBuilder.getPlainText());
        }

        String alias = "alias_" + System.currentTimeMillis();
        symmetricKeyStore.saveKey(alias, secretKey);
        return Utility.getSymmetricEncodedResult(symmetricCipher, alias);

    }

    @SneakyThrows
    public SymmetricPlain interoperableDecrypt(SymmetricInteroperableBuilder symmetricBuilder) {

        Objects.nonNull(symmetricBuilder.getSymmetricInteroperabilityLanguages());

        SymmetricInteroperabilityConfig.Details languageDetails = symmetricInteroperabilityConfig.languageDetails(symmetricBuilder.getSymmetricInteroperabilityLanguages().name());

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.fromLabel(languageDetails.symmetric().defaultAlgo());

        byte[] cipherBytes;

        if (symmetricAlgorithm.getLabel().startsWith("AES_GCM")) {

            byte[] ciphertextBytes = decodeBase64(symmetricBuilder.getCipherText());
            byte[] tagBytes = decodeBase64(symmetricBuilder.getTag());
            cipherBytes = new byte[ciphertextBytes.length + tagBytes.length];
            System.arraycopy(ciphertextBytes, 0, cipherBytes, 0, ciphertextBytes.length);
            System.arraycopy(tagBytes, 0, cipherBytes, ciphertextBytes.length, tagBytes.length);

        } else {

            cipherBytes = decodeBase64(symmetricBuilder.getCipherText());
        }


        return isGCM(symmetricAlgorithm) ?
                symmetric.decryptWithGCM(languageDetails.symmetric().tagLength(), symmetricAlgorithm, symmetricKeyStore.loadKey(symmetricBuilder.getKeyAlias()), decodeBase64(symmetricBuilder.getIv()), cipherBytes, symmetricBuilder.getAssociatedData()) :
                symmetric.decrypt(symmetricAlgorithm, symmetricKeyStore.loadKey(symmetricBuilder.getKeyAlias()), decodeBase64(symmetricBuilder.getIv()), cipherBytes);

    }
}
