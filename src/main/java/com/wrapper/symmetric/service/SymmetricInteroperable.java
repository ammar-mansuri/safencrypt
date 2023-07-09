package com.wrapper.symmetric.service;

import com.wrapper.symmetric.builder.SafEncrypt;
import com.wrapper.symmetric.config.SymmetricConfig;
import com.wrapper.symmetric.config.SymmetricInteroperabilityConfig;
import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SafEncryptContainer;
import com.wrapper.symmetric.models.SymmetricCipher;
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
    public SafEncryptContainer interoperableEncrypt(SafEncrypt symmetricBuilder) {

        Objects.nonNull(symmetricBuilder.getSymmetricInteroperabilityLanguages());

        SymmetricInteroperabilityConfig.Details languageDetails = symmetricInteroperabilityConfig.languageDetails(symmetricBuilder.getSymmetricInteroperabilityLanguages().name());

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.fromLabel(languageDetails.symmetric().defaultAlgo());


        SecretKey secretKey = new SecretKeySpec(SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm), "AES");

        SafEncryptContainer safEncryptContainer;

        if (isGCM(symmetricAlgorithm)) {
            safEncryptContainer = symmetric.encryptWithGCM(languageDetails.symmetric().tagLength(), languageDetails.symmetric().ivBytes(), symmetricAlgorithm, secretKey, symmetricBuilder.getPlainText(), symmetricBuilder.getAssociatedData());
        } else {
            safEncryptContainer = symmetric.encrypt(languageDetails.symmetric().ivBytes(), symmetricAlgorithm, secretKey, symmetricBuilder.getPlainText());
        }

        String alias = "alias_" + System.currentTimeMillis();
        symmetricKeyStore.saveKey(alias, secretKey);


        return Utility.getSymmetricEncodedResult((SymmetricCipher) safEncryptContainer, alias);

    }

    @SneakyThrows
    public byte[] interoperableDecrypt(SafEncrypt symmetricBuilder) {

        Objects.nonNull(symmetricBuilder.getSymmetricInteroperabilityLanguages());

        SymmetricInteroperabilityConfig.Details languageDetails = symmetricInteroperabilityConfig.languageDetails(symmetricBuilder.getSymmetricInteroperabilityLanguages().name());

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.fromLabel(languageDetails.symmetric().defaultAlgo());

        byte[] cipherBytes;

        if (symmetricAlgorithm.getLabel().startsWith("AES_GCM")) {

            byte[] ciphertextBytes = decodeBase64(symmetricBuilder.getCipherTextBase64());
            byte[] tagBytes = decodeBase64(symmetricBuilder.getTagBase64());
            cipherBytes = new byte[ciphertextBytes.length + tagBytes.length];
            System.arraycopy(ciphertextBytes, 0, cipherBytes, 0, ciphertextBytes.length);
            System.arraycopy(tagBytes, 0, cipherBytes, ciphertextBytes.length, tagBytes.length);

        } else {

            cipherBytes = decodeBase64(symmetricBuilder.getCipherTextBase64());
        }


        return isGCM(symmetricAlgorithm) ?
                symmetric.decryptWithGCM(languageDetails.symmetric().tagLength(), symmetricAlgorithm, symmetricKeyStore.loadKey(symmetricBuilder.getKeyAlias()), decodeBase64(symmetricBuilder.getIvBase64()), cipherBytes, symmetricBuilder.getAssociatedData()) :
                symmetric.decrypt(symmetricAlgorithm, symmetricKeyStore.loadKey(symmetricBuilder.getKeyAlias()), decodeBase64(symmetricBuilder.getIvBase64()), cipherBytes);

    }
}
