package com.safEncrypt.symmetric.service;

import com.safEncrypt.exceptions.SafencryptException;
import com.safEncrypt.symmetric.builder.SafEncrypt;
import com.safEncrypt.symmetric.config.ErrorConfig;
import com.safEncrypt.symmetric.config.SymmetricConfig;
import com.safEncrypt.symmetric.enums.SymmetricAlgorithm;
import com.safEncrypt.symmetric.models.SymmetricCipher;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;
import java.util.HashSet;

import static com.safEncrypt.symmetric.utils.Utility.*;

@Slf4j
public class SymmetricImpl {

    private static final int GCM_TAG_LENGTH = 96;
    private static final int GCM_IV_SIZE = 12;
    private static final int REST_IV_SIZE = 16;
    private final SymmetricConfig symmetricConfig;
    private final ErrorConfig errorConfig;

    public SymmetricImpl(SymmetricConfig symmetricConfig, ErrorConfig errorConfig) {
        this.symmetricConfig = symmetricConfig;
        this.errorConfig = errorConfig;
    }


    /**
     * Main ENCRYPT Function Call from builder
     *
     * @param safEncrypt
     * @return
     */
    @SneakyThrows
    public SymmetricCipher encrypt(SafEncrypt safEncrypt) {

        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.fromLabel(safEncrypt.getSymmetricAlgorithm().getLabel());


        SecretKey secretKey = safEncrypt.getKey();

        if (!isKeyDefined(safEncrypt)) {
            secretKey = new SecretKeySpec(SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm), "AES");
        }

        if (isGCM(symmetricAlgorithm)) {
            return encryptWithGCM(GCM_TAG_LENGTH, GCM_IV_SIZE, safEncrypt.getSymmetricAlgorithm(), secretKey, safEncrypt.getPlainText(), safEncrypt.getAssociatedData());
        }

        return encrypt(REST_IV_SIZE, safEncrypt.getSymmetricAlgorithm(), secretKey, safEncrypt.getPlainText());
    }

    /**
     * Main DECRYPT Function Call from builder
     *
     * @param safEncrypt
     * @return
     */
    @SneakyThrows
    public byte[] decrypt(SafEncrypt safEncrypt) {
        SymmetricAlgorithm algorithm = safEncrypt.getSymmetricAlgorithm();
        return isGCM(algorithm) ?
                decryptWithGCM(GCM_TAG_LENGTH, safEncrypt.getSymmetricAlgorithm(), safEncrypt.getKey(), safEncrypt.getIv(), safEncrypt.getCipherText(), safEncrypt.getAssociatedData()) :
                decrypt(safEncrypt.getSymmetricAlgorithm(), safEncrypt.getKey(), safEncrypt.getIv(), safEncrypt.getCipherText());

    }


    @SneakyThrows
    protected SymmetricCipher encrypt(int ivSize, SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] plaintext) {
        log.warn(errorConfig.message("SAF-011", getAlgorithmAndMode(symmetricAlgorithm)));
        isAlgorithmSecure(symmetricAlgorithm.getLabel());
        isKeyLengthCorrect(secretKey, symmetricAlgorithm);

        Cipher cipher;
        String algorithm = getAlgorithmForCipher(symmetricAlgorithm);
        try {
            cipher = Cipher.getInstance(getAlgorithmForCipher(symmetricAlgorithm));
        } catch (NoSuchAlgorithmException e) {
            try {
                Security.addProvider(new BouncyCastleProvider());
                cipher = Cipher.getInstance(algorithm, "BC");
            } catch (NoSuchPaddingException ex) {
                throw new SafencryptException(errorConfig.message("SAF-012", ex, symmetricAlgorithm.getLabel()));
            } catch (NoSuchAlgorithmException ex) {
                throw new SafencryptException(errorConfig.message("SAF-004", ex, symmetricAlgorithm.getLabel()));
            } catch (NoSuchProviderException ex) {
                throw new SafencryptException(errorConfig.message("SAF-004", ex, symmetricAlgorithm.getLabel()));
            } catch (Exception ex) {
                throw new SafencryptException(errorConfig.message("SAF-004", ex, symmetricAlgorithm.getLabel()));
            }
        }


        final IvParameterSpec ivSpec = generateIv(ivSize);
        isIvLengthCorrect(ivSpec.getIV(), ivSize, symmetricAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        final byte[] ciphertext = cipher.doFinal(plaintext);

        return new SymmetricCipher(ivSpec.getIV(), secretKey.getEncoded(), ciphertext, SymmetricAlgorithm.fromLabel(symmetricAlgorithm.getLabel()));
    }


    @SneakyThrows
    protected SymmetricCipher encryptWithGCM(int tagLength, int ivSize, SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] plaintext, byte[] associatedData) {
        isAlgorithmSecure(symmetricAlgorithm.getLabel());
        isKeyLengthCorrect(secretKey, symmetricAlgorithm);

        final Cipher cipher;
        try {
            cipher = Cipher.getInstance(getAlgorithmForCipher(symmetricAlgorithm));
        } catch (NoSuchAlgorithmException ex) {
            throw new SafencryptException(errorConfig.message("SAF-004", ex, symmetricAlgorithm.getLabel()));
        } catch (Exception ex) {
            throw new SafencryptException(errorConfig.message("SAF-004", ex, symmetricAlgorithm.getLabel()));
        }

        final IvParameterSpec ivSpec = generateIv(ivSize);
        isIvLengthCorrect(ivSpec.getIV(), ivSize, symmetricAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(tagLength, ivSpec.getIV()));

        if (associatedData != null && associatedData.length > 0) {
            cipher.updateAAD(associatedData);
        }

        final byte[] ciphertext = cipher.doFinal(plaintext);
        return new SymmetricCipher(ivSpec.getIV(), secretKey.getEncoded(), ciphertext, SymmetricAlgorithm.fromLabel(symmetricAlgorithm.getLabel()));
    }


    @SneakyThrows
    protected byte[] decrypt(SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] iv, byte[] cipherText) {
        log.warn(errorConfig.message("SAF-011", getAlgorithmAndMode(symmetricAlgorithm)));
        isAlgorithmSecure(symmetricAlgorithm.getLabel());
        isKeyLengthCorrect(secretKey, symmetricAlgorithm);
        isIvLengthCorrect(iv, REST_IV_SIZE, symmetricAlgorithm);

        Cipher cipher;
        String algorithm = getAlgorithmForCipher(symmetricAlgorithm);
        try {
            cipher = Cipher.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            try {
                Security.addProvider(new BouncyCastleProvider());
                cipher = Cipher.getInstance(algorithm, "BC");
            } catch (NoSuchPaddingException ex) {
                throw new SafencryptException(errorConfig.message("SAF-012", ex, symmetricAlgorithm.getLabel()));
            } catch (NoSuchAlgorithmException ex) {
                throw new SafencryptException(errorConfig.message("SAF-004", ex, symmetricAlgorithm.getLabel()));
            } catch (NoSuchProviderException ex) {
                throw new SafencryptException(errorConfig.message("SAF-004", ex, symmetricAlgorithm.getLabel()));
            } catch (Exception ex) {
                throw new SafencryptException(errorConfig.message("SAF-004", ex, symmetricAlgorithm.getLabel()));
            }
        }
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return cipher.doFinal(cipherText);
    }

    protected byte[] decryptWithGCM(int tagLength, SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] iv, byte[] cipherText, byte[] associatedData) throws Exception {
        isAlgorithmSecure(symmetricAlgorithm.getLabel());
        isKeyLengthCorrect(secretKey, symmetricAlgorithm);
        isIvLengthCorrect(iv, GCM_IV_SIZE, symmetricAlgorithm);

        final Cipher cipher;
        try {
            cipher = Cipher.getInstance(getAlgorithmForCipher(symmetricAlgorithm));
        } catch (NoSuchAlgorithmException ex) {
            throw new SafencryptException(errorConfig.message("SAF-004", ex, symmetricAlgorithm.getLabel()));
        } catch (Exception ex) {
            throw new SafencryptException(errorConfig.message("SAF-004", ex, symmetricAlgorithm.getLabel()));
        }

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(tagLength, iv));
        if (associatedData != null && associatedData.length > 0) cipher.updateAAD(associatedData);
        try {
            return cipher.doFinal(cipherText);
        } catch (AEADBadTagException e) {
            throw new SafencryptException(errorConfig.message("SAF-002", e));
        }
    }

    @SneakyThrows
    protected void isAlgorithmSecure(String symmetricAlgorithm) {
        if (symmetricConfig.algorithms().contains(symmetricAlgorithm))
            return;

        throw new SafencryptException(errorConfig.message("SAF-001", symmetricAlgorithm));
    }

    @SneakyThrows
    protected void isKeyLengthCorrect(SecretKey secretKey, SymmetricAlgorithm symmetricAlgorithm) {

        final int keyLength = secretKey.getEncoded().length * 8;
        HashSet<Integer> allowedKeyLength = new HashSet<>() {{
            add(128);
            add(192);
            add(256);
        }};


        if (Arrays.equals(secretKey.getEncoded(), new byte[secretKey.getEncoded().length])) {
            throw new SafencryptException(errorConfig.message("SAF-015"));
        }

        if (!allowedKeyLength.contains(keyLength) || keyLength != getKeySize(symmetricAlgorithm)) {
            throw new SafencryptException(errorConfig.message("SAF-003", String.valueOf(secretKey.getEncoded().length), symmetricAlgorithm.getLabel(), String.valueOf(getKeySize(symmetricAlgorithm) / 8)));
        }
    }


    @SneakyThrows
    protected void isIvLengthCorrect(byte[] iv, int IV_SIZE, SymmetricAlgorithm symmetricAlgorithm) {

        if (iv.length != IV_SIZE) {
            throw new SafencryptException(errorConfig.message("SAF-014", String.valueOf(iv.length), symmetricAlgorithm.getLabel(), String.valueOf(IV_SIZE)));
        }
    }
}
