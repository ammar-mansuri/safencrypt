package com.wrapper.symmetric.builder;

import com.wrapper.mapper.ConfigParser;
import com.wrapper.symmetric.config.ErrorConfig;
import com.wrapper.symmetric.config.SymmetricConfig;
import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.exceptions.SafencryptException;
import com.wrapper.symmetric.models.SymmetricCipher;
import com.wrapper.symmetric.models.SymmetricPlain;
import com.wrapper.symmetric.service.SymmetricImpl;
import com.wrapper.symmetric.service.SymmetricKeyGenerator;
import lombok.SneakyThrows;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

import static com.wrapper.symmetric.utils.Utility.isGCM;
import static java.util.Objects.requireNonNull;

public class SafEncrypt {

    private SymmetricAlgorithm symmetricAlgorithm;
    private SecretKey key;
    private byte[] plainText;
    private byte[] associatedData;
    private byte[] cipherText;
    private byte[] iv;


    private static SafEncrypt encryption;
    private SymmetricImpl symmetricImpl;
    private SymmetricConfig symmetricConfig;
    private ErrorConfig errorConfig;
    private ConfigParser configParser = new ConfigParser();


    private SafEncrypt() {
        this.symmetricConfig = configParser.getSymmetricConfig();
        this.errorConfig = configParser.getErrorConfig();
        this.symmetricImpl = new SymmetricImpl(symmetricConfig, errorConfig);
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
        public SymmetricCipher encrypt() {

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
        public SymmetricPlain decrypt() {
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
}
