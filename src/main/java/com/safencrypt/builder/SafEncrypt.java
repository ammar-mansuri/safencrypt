package com.safencrypt.builder;

import com.safencrypt.config.*;
import com.safencrypt.enums.KeyAlgorithm;
import com.safencrypt.enums.SymmetricAlgorithm;
import com.safencrypt.enums.SymmetricInteroperabilityLanguages;
import com.safencrypt.mapper.ConfigParser;
import com.safencrypt.models.SymmetricStreamingCipher;
import com.safencrypt.service.*;
import com.safencrypt.exceptions.SafencryptException;
import com.safencrypt.models.SymmetricCipher;
import com.safencrypt.models.SymmetricCipherBase64;
import com.safencrypt.utils.ErrorCodes;
import lombok.SneakyThrows;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

import static com.safencrypt.utils.Utility.getKeySize;
import static com.safencrypt.utils.Utility.isGCM;

public class SafEncrypt {

    private SymmetricAlgorithm symmetricAlgorithm;
    private SecretKey key;
    private byte[] plainText;
    private byte[] associatedData;
    private byte[] cipherText;
    private byte[] iv;

    private File plainFile;
    private File cipherFile;

    /*  Interoperability START */
    private String keyAlias;
    private String ivBase64;
    private String cipherTextBase64;
    private SymmetricInteroperabilityLanguages symmetricInteroperabilityLanguages;
    private SymmetricInteroperabilityConfig symmetricInteroperabilityConfig;
    private SymmetricInteroperable symmetricInteroperable;
    private SymmetricKeyStore symmetricKeyStore;
    private KeyStoreConfig keyStoreConfig;
    /*  Interoperability  END */

    private static SafEncrypt encryption;
    private SymmetricImpl symmetricImpl;
    private SymmetricStreamingImpl symmetricStreamingImpl;
    private SymmetricConfig symmetricConfig;
    private ErrorConfig errorConfig;


    private SafEncrypt() {
        this.symmetricConfig = ConfigParser.getSymmetricConfig();
        this.errorConfig = ConfigParser.getErrorConfig();
        this.symmetricImpl = new SymmetricImpl(symmetricConfig, errorConfig);
        this.symmetricStreamingImpl = new SymmetricStreamingImpl(symmetricConfig, errorConfig);

        /*  Interoperability START */
        this.symmetricInteroperabilityConfig = ConfigParser.getInteroperabilityConfig();
        this.keyStoreConfig = ConfigParser.getKeystoreConfig();
        this.symmetricKeyStore = new SymmetricKeyStore(keyStoreConfig, errorConfig);
        this.symmetricInteroperable = new SymmetricInteroperable(symmetricKeyStore, symmetricInteroperabilityConfig, symmetricImpl);
        /*  Interoperability  END */


//        encryption = this;
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

    public File getPlainFile() {
        return plainFile;
    }

    public File getCipherFile() {
        return cipherFile;
    }

    /*  Interoperability START */
    public SymmetricInteroperabilityLanguages getSymmetricInteroperabilityLanguages() {
        return symmetricInteroperabilityLanguages;
    }

    public String getCipherTextBase64() {
        return cipherTextBase64;
    }


    public String getIvBase64() {
        return ivBase64;
    }

    public String getKeyAlias() {
        return keyAlias;
    }
    /*  Interoperability  END */


    public static EncryptionKeyBuilder symmetricEncryption() {
        encryption = new SafEncrypt();
        return new EncryptionKeyBuilder(encryption, SymmetricAlgorithm.DEFAULT);
    }

    @SneakyThrows
    public static EncryptionKeyBuilder symmetricEncryption(SymmetricAlgorithm symmetricAlgorithm) {
        encryption = new SafEncrypt();

        if (symmetricAlgorithm == null) {
            throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_020.name()));
        }

        return new EncryptionKeyBuilder(encryption, symmetricAlgorithm);
    }

    public static DecryptKeyBuilder symmetricDecryption() {
        encryption = new SafEncrypt();
        return new DecryptKeyBuilder(encryption, SymmetricAlgorithm.DEFAULT);
    }

    @SneakyThrows
    public static DecryptKeyBuilder symmetricDecryption(SymmetricAlgorithm symmetricAlgorithm) {
        encryption = new SafEncrypt();

        if (symmetricAlgorithm == null) {
            throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_020.name()));
        }

        return new DecryptKeyBuilder(encryption, symmetricAlgorithm);
    }

    public static class EncryptionKeyBuilder {

        private SafEncrypt encryption;

        private EncryptionKeyBuilder(SafEncrypt encryption, SymmetricAlgorithm symmetricAlgorithm) {
            this.encryption = encryption;
            this.encryption.symmetricAlgorithm = symmetricAlgorithm;
        }

        /**
         * Disabling Key Loading to prevent usage of unsecure key material
         *
         * @return
         */
        /*@SneakyThrows
        public PlaintextBuilder loadKey(byte[] key) {
            if (key == null || StringUtils.isBlank(new String(key, StandardCharsets.UTF_8)))
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_018.name()));

            encryption.key = new SecretKeySpec(key, "AES");
            return new PlaintextBuilder(encryption);
        }*/
        @SneakyThrows
        public PlaintextBuilder generateKey() {

            try {
                encryption.key = new SecretKeySpec(SymmetricKeyGenerator.generateSymmetricKey(encryption.symmetricAlgorithm), "AES");
            } catch (Exception ex) {
                if (ex instanceof NoSuchAlgorithmException)
                    throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_004.name(), ex, encryption.symmetricAlgorithm.getLabel()));
            }

            return new PlaintextBuilder(encryption);
        }

        @SneakyThrows
        public PlaintextBuilder generateKeyFromPassword(byte[] password) {
            if (password == null || StringUtils.isBlank(new String(password, StandardCharsets.UTF_8)))
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_031.name()));

            try {
                encryption.key = new SecretKeySpec(SymmetricKeyGenerator.generateSymmetricKeyFromPassword(password, getKeySize(encryption.symmetricAlgorithm)), "AES");
            } catch (Exception ex) {
                if (ex instanceof SafencryptException) {
                    throw ex;
                } else if (ex instanceof NoSuchAlgorithmException)
                    throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_004.name(), ex, encryption.symmetricAlgorithm.getLabel()));
                throw new SafencryptException(ex.getMessage(), ex);
            }
            return new PlaintextBuilder(encryption);
        }

        @SneakyThrows
        public PlaintextBuilder generateKeyFromPassword(byte[] password, KeyAlgorithm keyAlgorithm) {
            if (password == null)
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_020.name()));
            if (keyAlgorithm == null)
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_021.name()));

            try {
                encryption.key = new SecretKeySpec(SymmetricKeyGenerator.generateSymmetricKeyFromPassword(password, keyAlgorithm, getKeySize(encryption.symmetricAlgorithm)), "AES");
            } catch (Exception ex) {
                if (ex instanceof SafencryptException) {
                    throw ex;
                } else if (ex instanceof NoSuchAlgorithmException)
                    throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_004.name(), ex, encryption.symmetricAlgorithm.getLabel()));
                throw new SafencryptException(ex.getMessage(), ex);
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
            if (plaintext == null || StringUtils.isBlank(new String(plaintext, StandardCharsets.UTF_8)))
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_019.name()));
            encryption.plainText = plaintext;
            return new EncryptionBuilder(encryption);
        }

        @SneakyThrows
        public EncryptionBuilder plaintext(byte[] plaintext, byte[] associatedData) {
            if (plaintext == null || StringUtils.isBlank(new String(plaintext, StandardCharsets.UTF_8)))
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_019.name()));

            if (associatedData == null || StringUtils.isBlank(new String(associatedData, StandardCharsets.UTF_8)))
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_026.name()));

            if (!isGCM(encryption.symmetricAlgorithm))
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_005.name()));
            encryption.plainText = plaintext;
            encryption.associatedData = associatedData;
            return new EncryptionBuilder(encryption);
        }

        @SneakyThrows
        public StreamingEncryptionBuilder plainFileStream(final File plainFile, final File cipherFile) {
            if (Objects.isNull(plainFile))
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_032.name()));

            encryption.plainFile = plainFile;
            encryption.cipherFile = cipherFile;
            return new StreamingEncryptionBuilder(encryption);
        }

        @SneakyThrows
        public StreamingEncryptionBuilder plainFileStream(final File plainFile, final File cipherFile, byte[] associatedData) {
            if (Objects.isNull(plainFile))
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_032.name()));

            if (associatedData == null || StringUtils.isBlank(new String(associatedData, StandardCharsets.UTF_8)))
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_026.name()));

            if (!isGCM(encryption.symmetricAlgorithm))
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_005.name()));
            encryption.plainFile = plainFile;
            encryption.cipherFile = cipherFile;
            encryption.associatedData = associatedData;
            return new StreamingEncryptionBuilder(encryption);
        }
    }

    public static class DecryptKeyBuilder {
        private SafEncrypt encryption;

        private DecryptKeyBuilder(SafEncrypt encryption, SymmetricAlgorithm symmetricAlgorithm) {
            this.encryption = encryption;
            this.encryption.symmetricAlgorithm = symmetricAlgorithm;
        }

        @SneakyThrows
        public DecryptIVBuilder key(byte[] key) {
            if (key == null || StringUtils.isBlank(new String(key, StandardCharsets.UTF_8)))
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_018.name()));

            encryption.key = new SecretKeySpec(key, "AES");
            return new DecryptIVBuilder(encryption);
        }
    }

    public static class DecryptIVBuilder {
        private SafEncrypt encryption;

        private DecryptIVBuilder(SafEncrypt encryption) {
            this.encryption = encryption;
        }

        @SneakyThrows
        public CiphertextBuilder iv(byte[] iv) {
            if (iv == null || StringUtils.isBlank(new String(iv, StandardCharsets.UTF_8)))
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_022.name()));

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
            if (cipherText == null || StringUtils.isBlank(new String(cipherText, StandardCharsets.UTF_8)))
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_023.name()));

            encryption.cipherText = cipherText;
            return new DecryptionBuilder(encryption);
        }

        @SneakyThrows
        public DecryptionBuilder cipherText(byte[] cipherText, byte[] associatedData) {

            if (cipherText == null || StringUtils.isBlank(new String(cipherText, StandardCharsets.UTF_8)))
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_023.name()));

            if (associatedData == null || StringUtils.isBlank(new String(associatedData, StandardCharsets.UTF_8)))
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_026.name()));

            if (!isGCM(encryption.symmetricAlgorithm))
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_005.name()));
            encryption.cipherText = cipherText;
            encryption.associatedData = associatedData;
            return new DecryptionBuilder(encryption);
        }

        @SneakyThrows
        public StreamingDecryptionBuilder cipherFileStream(final File cipherFile, final File plainFile) {
            if (Objects.isNull(cipherFile))
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_033.name()));

            encryption.cipherFile = cipherFile;
            encryption.plainFile = plainFile;
            return new StreamingDecryptionBuilder(encryption);
        }

        @SneakyThrows
        public StreamingDecryptionBuilder cipherFileStream(final File cipherFile, final File plainFile, byte[] associatedData) {

            if (Objects.isNull(cipherFile))
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_033.name()));

            if (associatedData == null || StringUtils.isBlank(new String(associatedData, StandardCharsets.UTF_8)))
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_026.name()));

            if (!isGCM(encryption.symmetricAlgorithm))
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_005.name()));

            encryption.cipherFile = cipherFile;
            encryption.plainFile = plainFile;
            encryption.associatedData = associatedData;
            return new StreamingDecryptionBuilder(encryption);
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
                    throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_010.name(), e));
                }

                if (e instanceof IllegalBlockSizeException) {

                    throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_009.name(), e));
                }

                throw new SafencryptException(e.getMessage(), e);

            }

        }
    }

    public static class StreamingEncryptionBuilder {
        private SafEncrypt encryption;

        private StreamingEncryptionBuilder(SafEncrypt encryption) {
            this.encryption = encryption;
        }

        @SneakyThrows
        public SymmetricStreamingCipher encrypt() {

            try {
                return encryption.symmetricStreamingImpl.encrypt(encryption);
            } catch (Exception e) {

                if (e instanceof SafencryptException) {
                    throw e;
                }

                if (e instanceof BadPaddingException) {
                    throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_010.name(), e));
                }

                if (e instanceof IllegalBlockSizeException) {

                    throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_009.name(), e));
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
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_005.name()));
            try {
                return encryption.symmetricImpl.decrypt(encryption);
            } catch (Exception e) {
                if (e instanceof SafencryptException) {
                    throw e;
                }

                if (e instanceof BadPaddingException) {
                    throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_010.name(), e));
                }

                if (e instanceof IllegalBlockSizeException) {

                    throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_013.name(), e));
                }

                throw new SafencryptException(e.getMessage(), e);
            }
        }
    }

    public static class StreamingDecryptionBuilder {
        private SafEncrypt encryption;

        private StreamingDecryptionBuilder(SafEncrypt encryption) {
            this.encryption = encryption;
        }

        @SneakyThrows
        public void decrypt() {
            if (encryption.associatedData != null && !isGCM(encryption.symmetricAlgorithm))
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_005.name()));
            try {
                encryption.symmetricStreamingImpl.decrypt(encryption);
            } catch (Exception e) {
                if (e instanceof SafencryptException) {
                    throw e;
                }

                if (e instanceof BadPaddingException) {
                    throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_010.name(), e));
                }

                if (e instanceof IllegalBlockSizeException) {

                    throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_013.name(), e));
                }

                throw new SafencryptException(e.getMessage(), e);
            }
        }
    }

    /*  Interoperability START */

    /* FOR INTEROPERABLE ENCRYPTION */
    @SneakyThrows
    public static InteroperableEncryptionBuilder symmetricInteroperableEncryption(SymmetricInteroperabilityLanguages symmetricInteroperabilityLanguages) {
        encryption = new SafEncrypt();

        if (symmetricInteroperabilityLanguages == null) {
            throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_028.name()));
        }

        return new InteroperableEncryptionBuilder(encryption, symmetricInteroperabilityLanguages);
    }

    public static class InteroperableEncryptionBuilder {
        private SafEncrypt encryption;

        private InteroperableEncryptionBuilder(SafEncrypt encryption, SymmetricInteroperabilityLanguages symmetricInteroperabilityLanguages) {
            this.encryption = encryption;
            this.encryption.symmetricInteroperabilityLanguages = symmetricInteroperabilityLanguages;
        }

        @SneakyThrows
        public InteroperablePlaintextBuilder plaintext(byte[] plaintext) {
            if (plaintext == null)
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_019.name()));

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

            if (associatedData == null || StringUtils.isBlank(new String(associatedData, StandardCharsets.UTF_8)))
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_025.name()));

            if (!encryption.symmetricInteroperabilityConfig.languageDetails(encryption.getSymmetricInteroperabilityLanguages().name()).symmetric().defaultAlgo().startsWith("AES_GCM")) {
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_005.name()));
            }

            encryption.associatedData = associatedData;
            return this;
        }

        @SneakyThrows
        public SymmetricCipherBase64 encrypt() {
            return encryption.symmetricInteroperable.interoperableEncrypt(encryption);
        }
    }


    /* FOR INTEROPERABLE DECRYPTION */
    @SneakyThrows
    public static InteroperableKeyBuilder symmetricInteroperableDecryption(SymmetricInteroperabilityLanguages symmetricInteroperabilityLanguages) {
        encryption = new SafEncrypt();

        if (symmetricInteroperabilityLanguages == null) {
            throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_028.name()));
        }

        return new InteroperableKeyBuilder(encryption, symmetricInteroperabilityLanguages);

    }

    public static class InteroperableKeyBuilder {
        private SafEncrypt encryption;

        private InteroperableKeyBuilder(SafEncrypt encryption, SymmetricInteroperabilityLanguages symmetricInteroperabilityLanguages) {
            this.encryption = encryption;
            this.encryption.symmetricInteroperabilityLanguages = symmetricInteroperabilityLanguages;
        }

        @SneakyThrows
        public InteroperableIVBuilder keyAlias(String keyAlias) {
            if (StringUtils.isBlank(keyAlias))
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_024.name()));

            encryption.keyAlias = keyAlias;
            return new InteroperableIVBuilder(encryption);
        }

    }

    public static class InteroperableIVBuilder {
        private SafEncrypt encryption;

        private InteroperableIVBuilder(SafEncrypt encryption) {
            this.encryption = encryption;
        }

        @SneakyThrows
        public InteroperableCiphertextBuilder ivBase64(String iv) {
            if (StringUtils.isBlank(iv))
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_022.name()));
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

            if (StringUtils.isBlank(cipherText))
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_023.name()));


            /**
             * Extension for providing Tag Separately for AES_GCM
             */
            /*if (symmetricAlgorithm.getLabel().startsWith("AES_GCM")) {
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_030.name(), languageName, symmetricAlgorithm.getLabel()));
            }*/

            encryption.cipherTextBase64 = cipherText;
            return new InteroperableDecryptionBuilder(encryption);
        }

        /**
         * Extension for providing Tag Separately for AES_GCM
         */
        /*@SneakyThrows
        public InteroperableDecryptionBuilder cipherTextAndTagBase64(String cipherText) {

            if (StringUtils.isBlank(cipherText))
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_023.name()));

            final String languageName = encryption.getSymmetricInteroperabilityLanguages().name();
            SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.fromLabel(encryption.symmetricInteroperabilityConfig.languageDetails(languageName).symmetric().defaultAlgo());
            if (!symmetricAlgorithm.getLabel().startsWith("AES_GCM")) {
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_029.name(), languageName, symmetricAlgorithm.getLabel()));
            }

            encryption.cipherTextBase64 = cipherText;
            return new InteroperableDecryptionBuilder(encryption);
        }*/
    }

    public static class InteroperableDecryptionBuilder {
        private SafEncrypt encryption;

        private InteroperableDecryptionBuilder(SafEncrypt encryption) {
            this.encryption = encryption;
        }

        @SneakyThrows
        public InteroperableDecryptionBuilder optionalAssociatedData(byte[] associatedData) {

            if (associatedData == null || StringUtils.isBlank(new String(associatedData, StandardCharsets.UTF_8)))
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_025.name()));

            if (!encryption.symmetricInteroperabilityConfig.languageDetails(encryption.getSymmetricInteroperabilityLanguages().name()).symmetric().defaultAlgo().startsWith("AES_GCM")) {
                throw new SafencryptException(encryption.errorConfig.message(ErrorCodes.SAF_005.name()));
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
