package com.wrapper.symmetric.builder;

import com.wrapper.mapper.ConfigParser;
import com.wrapper.symmetric.config.*;
import com.wrapper.symmetric.enums.KeyAlgorithm;
import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.exceptions.SafencryptException;
import com.wrapper.symmetric.enums.SymmetricInteroperabilityLanguages;
import com.wrapper.symmetric.models.SafEncryptContainer;
import com.wrapper.symmetric.service.SymmetricImpl;
import com.wrapper.symmetric.service.SymmetricInteroperable;
import com.wrapper.symmetric.service.SymmetricKeyGenerator;
import com.wrapper.symmetric.service.SymmetricKeyStore;
import lombok.SneakyThrows;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

import static com.wrapper.symmetric.utils.Utility.getKeySize;
import static com.wrapper.symmetric.utils.Utility.isGCM;
import static java.util.Objects.requireNonNull;

public class SafEncrypt {

    private SymmetricAlgorithm symmetricAlgorithm;
    private SecretKey key;
    private byte[] plainText;
    private byte[] associatedData;
    private byte[] cipherText;
    private byte[] iv;


    /*  Interoperability START */
    private String keyAlias;
    private String ivBase64;
    private String cipherTextBase64;
    private String tagBase64;
    private SymmetricInteroperabilityLanguages symmetricInteroperabilityLanguages;
    private SymmetricInteroperabilityConfig symmetricInteroperabilityConfig;
    private SymmetricInteroperable symmetricInteroperable;
    private SymmetricKeyStore symmetricKeyStore;
    private KeyStoreConfig keyStoreConfig;
    /*  Interoperability  END */

    private static SafEncrypt encryption;
    private SymmetricImpl symmetricImpl;
    private SymmetricConfig symmetricConfig;
    private PBEKeyConfig pbeKeySpec;
    private ErrorConfig errorConfig;
    private ConfigParser configParser = new ConfigParser();


    private SafEncrypt() {
        this.symmetricConfig = configParser.getSymmetricConfig();
        this.errorConfig = configParser.getErrorConfig();
        this.pbeKeySpec = configParser.getPbKeyConfig();
        this.symmetricImpl = new SymmetricImpl(symmetricConfig, errorConfig);

        /*  Interoperability START */
        this.symmetricInteroperabilityConfig = configParser.getInteroperabilityConfig();
        this.keyStoreConfig = configParser.getKeystoreConfig();
        this.symmetricKeyStore = new SymmetricKeyStore(keyStoreConfig, errorConfig);
        this.symmetricInteroperable = new SymmetricInteroperable(symmetricConfig, symmetricKeyStore, symmetricInteroperabilityConfig, symmetricImpl);
        /*  Interoperability  END */


        encryption = this;
    }

    public SymmetricAlgorithm getSymmetricAlgorithm() {
        return symmetricAlgorithm;
    }

    public SecretKey getKey() {
        return key;
    }

    public byte[] getPlainText() {
        return plainText;
    }

    public byte[] getAssociatedData() {
        return associatedData;
    }

    public byte[] getCipherText() {
        return cipherText;
    }

    public byte[] getIv() {
        return iv;
    }


    /*  Interoperability START */
    public SymmetricInteroperabilityLanguages getSymmetricInteroperabilityLanguages() {
        return symmetricInteroperabilityLanguages;
    }

    public String getCipherTextBase64() {
        return cipherTextBase64;
    }

    public String getTagBase64() {
        return tagBase64;
    }

    public String getIvBase64() {
        return ivBase64;
    }

    public String getKeyAlias() {
        return keyAlias;
    }
    /*  Interoperability  END */


    public static EncryptionKeyBuilder encryption() {
        encryption = new SafEncrypt();
        return new EncryptionKeyBuilder(encryption, SymmetricAlgorithm.DEFAULT);
    }

    public static EncryptionKeyBuilder encryption(SymmetricAlgorithm symmetricAlgorithm) {
        encryption = new SafEncrypt();
        return new EncryptionKeyBuilder(encryption, symmetricAlgorithm);
    }

    public static DecryptKeyBuilder decryption() {
        encryption = new SafEncrypt();
        return new DecryptKeyBuilder(encryption, SymmetricAlgorithm.DEFAULT);
    }

    public static DecryptKeyBuilder decryption(SymmetricAlgorithm symmetricAlgorithm) {
        encryption = new SafEncrypt();
        return new DecryptKeyBuilder(encryption, symmetricAlgorithm);
    }

    public static class EncryptionKeyBuilder {

        private SafEncrypt encryption;

        private EncryptionKeyBuilder(SafEncrypt encryption, SymmetricAlgorithm symmetricAlgorithm) {
            this.encryption = encryption;
            this.encryption.symmetricAlgorithm = symmetricAlgorithm;
        }

        public PlaintextBuilder loadKey(byte[] key) {
            requireNonNull(key);
            encryption.key = new SecretKeySpec(key, "AES");
            return new PlaintextBuilder(encryption);
        }

        @SneakyThrows
        public PlaintextBuilder generateKey() {

            try {
                encryption.key = new SecretKeySpec(SymmetricKeyGenerator.generateSymmetricKey(encryption.symmetricAlgorithm), "AES");
            } catch (Exception ex) {
                if (ex instanceof NoSuchAlgorithmException)
                    throw new SafencryptException(encryption.errorConfig.message("SAF-004", ex, encryption.symmetricAlgorithm.getLabel()));
            }

            return new PlaintextBuilder(encryption);
        }

        @SneakyThrows
        public PlaintextBuilder generateKeyFromPassword(byte[] password) {

            try {
                encryption.key = new SecretKeySpec(SymmetricKeyGenerator.generateSymmetricKeyFromPassword(password, getKeySize(encryption.symmetricAlgorithm)), "AES");
            } catch (Exception ex) {
                if (ex instanceof NoSuchAlgorithmException)
                    throw new SafencryptException(encryption.errorConfig.message("SAF-004", ex, encryption.symmetricAlgorithm.getLabel()));
            }
            return new PlaintextBuilder(encryption);
        }

        @SneakyThrows
        public PlaintextBuilder generateKeyFromPassword(byte[] password, KeyAlgorithm keyAlgorithm) {

            try {
                encryption.key = new SecretKeySpec(SymmetricKeyGenerator.generateSymmetricKeyFromPassword(password, keyAlgorithm, getKeySize(encryption.symmetricAlgorithm)), "AES");
            } catch (Exception ex) {
                if (ex instanceof NoSuchAlgorithmException)
                    throw new SafencryptException(encryption.errorConfig.message("SAF-004", ex, encryption.symmetricAlgorithm.getLabel()));
            }
            return new PlaintextBuilder(encryption);
        }
    }

    public static class PlaintextBuilder {
        private SafEncrypt encryption;

        private PlaintextBuilder(SafEncrypt encryption) {
            this.encryption = encryption;
        }

        @SneakyThrows
        public EncryptionBuilder plaintext(byte[] plaintext) {
            requireNonNull(plaintext);
            encryption.plainText = plaintext;
            return new EncryptionBuilder(encryption);
        }

        @SneakyThrows
        public EncryptionBuilder plaintext(byte[] plaintext, byte[] associatedData) {
            if (!isGCM(encryption.symmetricAlgorithm))
                throw new SafencryptException(encryption.errorConfig.message("SAF-005"));
            encryption.plainText = plaintext;
            encryption.associatedData = associatedData;
            return new EncryptionBuilder(encryption);
        }

    }

    public static class DecryptKeyBuilder {
        private SafEncrypt encryption;

        private DecryptKeyBuilder(SafEncrypt encryption, SymmetricAlgorithm symmetricAlgorithm) {
            this.encryption = encryption;
            this.encryption.symmetricAlgorithm = symmetricAlgorithm;
        }

        public DecryptIVBuilder key(byte[] key) {
            requireNonNull(key);
            encryption.key = new SecretKeySpec(key, "AES");
            return new DecryptIVBuilder(encryption);
        }
    }

    public static class DecryptIVBuilder {
        private SafEncrypt encryption;

        private DecryptIVBuilder(SafEncrypt encryption) {
            this.encryption = encryption;
        }

        public CiphertextBuilder iv(byte[] iv) {
            requireNonNull(iv);
            encryption.iv = iv;
            return new CiphertextBuilder(encryption);
        }
    }

    public static class CiphertextBuilder {
        private SafEncrypt encryption;

        private CiphertextBuilder(SafEncrypt encryption) {
            this.encryption = encryption;
        }

        @SneakyThrows
        public DecryptionBuilder cipherText(byte[] cipherText) {
            requireNonNull(cipherText);
            encryption.cipherText = cipherText;
            return new DecryptionBuilder(encryption);
        }

        @SneakyThrows
        public DecryptionBuilder cipherText(byte[] cipherText, byte[] associatedData) {
            if (!isGCM(encryption.symmetricAlgorithm))
                throw new SafencryptException(encryption.errorConfig.message("SAF-005"));
            encryption.cipherText = cipherText;
            encryption.associatedData = associatedData;
            return new DecryptionBuilder(encryption);
        }

    }

    public static class EncryptionBuilder {
        private SafEncrypt encryption;

        private EncryptionBuilder(SafEncrypt encryption) {
            this.encryption = encryption;
        }

        @SneakyThrows
        public SafEncryptContainer encrypt() {

            try {
                return encryption.symmetricImpl.encrypt(encryption);
            } catch (Exception e) {

                if (e instanceof SafencryptException) {
                    throw e;
                }

                if (e instanceof BadPaddingException) {
                    throw new SafencryptException(encryption.errorConfig.message("SAF-010", e));
                }

                if (e instanceof IllegalBlockSizeException) {

                    throw new SafencryptException(encryption.errorConfig.message("SAF-009", e));
                }

                throw new SafencryptException(e.getMessage(), e);

            }

        }
    }

    public static class DecryptionBuilder {
        private SafEncrypt encryption;

        private DecryptionBuilder(SafEncrypt encryption) {
            this.encryption = encryption;
        }

        @SneakyThrows
        public byte[] decrypt() {
            if (encryption.associatedData != null && !isGCM(encryption.symmetricAlgorithm))
                throw new SafencryptException(encryption.errorConfig.message("SAF-005"));
            try {
                return encryption.symmetricImpl.decrypt(encryption);
            } catch (Exception e) {
                if (e instanceof SafencryptException) {
                    throw e;
                }

                if (e instanceof BadPaddingException) {
                    throw new SafencryptException(encryption.errorConfig.message("SAF-010", e));
                }

                if (e instanceof IllegalBlockSizeException) {

                    throw new SafencryptException(encryption.errorConfig.message("SAF-013", e));
                }

                throw new SafencryptException(e.getMessage(), e);
            }
        }
    }

    /*  Interoperability START */

    /* FOR INTEROPERABLE ENCRYPTION */
    public static InteroperableEncryptionBuilder interoperableEncryption(SymmetricInteroperabilityLanguages symmetricInteroperabilityLanguages) {
        encryption = new SafEncrypt();
        return new InteroperableEncryptionBuilder(encryption, symmetricInteroperabilityLanguages);
    }

    public static class InteroperableEncryptionBuilder {
        private SafEncrypt encryption;

        private InteroperableEncryptionBuilder(SafEncrypt encryption, SymmetricInteroperabilityLanguages symmetricInteroperabilityLanguages) {
            this.encryption = encryption;
            this.encryption.symmetricInteroperabilityLanguages = symmetricInteroperabilityLanguages;
        }

        public InteroperablePlaintextBuilder plaintext(byte[] plaintext) {
            requireNonNull(plaintext);
            encryption.plainText = plaintext;
            return new InteroperablePlaintextBuilder(encryption);
        }
    }

    public static class InteroperablePlaintextBuilder {
        private SafEncrypt encryption;

        private InteroperablePlaintextBuilder(SafEncrypt encryption) {
            this.encryption = encryption;
        }

        @SneakyThrows
        public InteroperablePlaintextBuilder optionalAssociatedData(byte[] associatedData) {


            if (!encryption.symmetricInteroperabilityConfig.languageDetails(encryption.getSymmetricInteroperabilityLanguages().name()).symmetric().defaultAlgo().startsWith("AES_GCM")) {
                throw new SafencryptException(encryption.errorConfig.message("SAF-005"));
            }

            encryption.associatedData = associatedData;
            return this;
        }

        @SneakyThrows
        public SafEncryptContainer encrypt() {
            return encryption.symmetricInteroperable.interoperableEncrypt(encryption);
        }
    }


    /* FOR INTEROPERABLE DECRYPTION */

    public static InteroperableKeyBuilder interoperableDecryption(SymmetricInteroperabilityLanguages symmetricInteroperabilityLanguages) {

        encryption = new SafEncrypt();
        return new InteroperableKeyBuilder(encryption, symmetricInteroperabilityLanguages);

    }

    public static class InteroperableKeyBuilder {
        private SafEncrypt encryption;

        private InteroperableKeyBuilder(SafEncrypt encryption, SymmetricInteroperabilityLanguages symmetricInteroperabilityLanguages) {
            this.encryption = encryption;
            this.encryption.symmetricInteroperabilityLanguages = symmetricInteroperabilityLanguages;
        }

        public InteroperableIVBuilder keyAlias(String keyAlias) {
            encryption.keyAlias = keyAlias;
            return new InteroperableIVBuilder(encryption);
        }

    }

    public static class InteroperableIVBuilder {
        private SafEncrypt encryption;

        private InteroperableIVBuilder(SafEncrypt encryption) {
            this.encryption = encryption;
        }

        public InteroperableCiphertextBuilder ivBase64(String iv) {
            encryption.ivBase64 = iv;
            return new InteroperableCiphertextBuilder(encryption);
        }

    }

    public static class InteroperableCiphertextBuilder {
        private SafEncrypt encryption;

        private InteroperableCiphertextBuilder(SafEncrypt encryption) {
            this.encryption = encryption;
        }

        @SneakyThrows
        public InteroperableDecryptionBuilder cipherTextBase64(String cipherText) {

            SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.fromLabel(encryption.symmetricInteroperabilityConfig.languageDetails(encryption.getSymmetricInteroperabilityLanguages().name()).symmetric().defaultAlgo());
            if (symmetricAlgorithm.getLabel().startsWith("AES_GCM")) {
                throw new SafencryptException(encryption.errorConfig.message("SAF-007"));
            }

            encryption.cipherTextBase64 = cipherText;
            return new InteroperableDecryptionBuilder(encryption);
        }

        @SneakyThrows
        public InteroperableDecryptionBuilder cipherTextAndTagBase64(String cipherText, String tag) {

            SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.fromLabel(encryption.symmetricInteroperabilityConfig.languageDetails(encryption.getSymmetricInteroperabilityLanguages().name()).symmetric().defaultAlgo());
            if (!symmetricAlgorithm.getLabel().startsWith("AES_GCM")) {
                throw new SafencryptException(encryption.errorConfig.message("SAF-008", symmetricAlgorithm.getLabel()));
            }

            encryption.cipherTextBase64 = cipherText;
            encryption.tagBase64 = tag;
            return new InteroperableDecryptionBuilder(encryption);
        }
    }

    public static class InteroperableDecryptionBuilder {
        private SafEncrypt encryption;

        private InteroperableDecryptionBuilder(SafEncrypt encryption) {
            this.encryption = encryption;
        }

        @SneakyThrows
        public InteroperableDecryptionBuilder optionalAssociatedData(byte[] associatedData) {

            if (!encryption.symmetricInteroperabilityConfig.languageDetails(encryption.getSymmetricInteroperabilityLanguages().name()).symmetric().defaultAlgo().startsWith("AES_GCM")) {
                throw new SafencryptException(encryption.errorConfig.message("SAF-005"));
            }

            encryption.associatedData = associatedData;
            return this;
        }

        @SneakyThrows
        public byte[] decrypt() {
            return encryption.symmetricInteroperable.interoperableDecrypt(encryption);
        }

    }
}
