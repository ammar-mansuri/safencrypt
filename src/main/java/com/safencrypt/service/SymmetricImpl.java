package com.safencrypt.service;

import com.safencrypt.builder.SafEncrypt;
import com.safencrypt.config.ErrorConfig;
import com.safencrypt.config.SymmetricConfig;
import com.safencrypt.enums.SymmetricAlgorithm;
import com.safencrypt.exceptions.SafencryptException;
import com.safencrypt.models.SymmetricCipher;
import com.safencrypt.utils.ErrorCodes;
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
import java.util.List;

import static com.safencrypt.utils.Utility.*;

@Slf4j
public class SymmetricImpl {

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

        final SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.fromLabel(safEncrypt.getSymmetricAlgorithm().getLabel());

        final SymmetricConfig.Constraints constraints = symmetricConfig.getConstraint(getAlgoForConstraints(symmetricAlgorithm));

        SecretKey secretKey = safEncrypt.getKey();

        if (!isKeyDefined(safEncrypt)) {
            secretKey = new SecretKeySpec(SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm), "AES");
        }

        if (isGCM(symmetricAlgorithm)) {
            return encryptWithGCM(constraints.tagSize(), constraints.ivSize(), safEncrypt.getSymmetricAlgorithm(), secretKey, safEncrypt.getPlainText(), safEncrypt.getAssociatedData());
        }

        return encrypt(constraints.ivSize(), safEncrypt.getSymmetricAlgorithm(), secretKey, safEncrypt.getPlainText());
    }

    /**
     * Main DECRYPT Function Call from builder
     *
     * @param safEncrypt
     * @return
     */
    @SneakyThrows
    public byte[] decrypt(SafEncrypt safEncrypt) {
        final SymmetricAlgorithm algorithm = safEncrypt.getSymmetricAlgorithm();
        final SymmetricConfig.Constraints constraints = symmetricConfig.getConstraint(getAlgoForConstraints(algorithm));

        return isGCM(algorithm) ?
                decryptWithGCM(constraints.tagSize(), constraints.ivSize(), safEncrypt.getSymmetricAlgorithm(), safEncrypt.getKey(), safEncrypt.getIv(), safEncrypt.getCipherText(), safEncrypt.getAssociatedData()) :
                decrypt(constraints.ivSize(), safEncrypt.getSymmetricAlgorithm(), safEncrypt.getKey(), safEncrypt.getIv(), safEncrypt.getCipherText());

    }


    @SneakyThrows
    protected SymmetricCipher encrypt(int ivSize, SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] plaintext) {
        log.warn(errorConfig.message(ErrorCodes.SAF_011.name(), getAlgorithmAndMode(symmetricAlgorithm)));
        isAlgorithmSecure(symmetricAlgorithm.getLabel());
        isKeyLengthCorrect(secretKey, symmetricAlgorithm);
        final Cipher cipher = cbcCipherHelper(symmetricAlgorithm);
        final IvParameterSpec ivSpec = new IvParameterSpec(generateIv(ivSize));
        isIvLengthCorrect(ivSpec.getIV(), ivSize, symmetricAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        final byte[] ciphertext = cipher.doFinal(plaintext);

        return new SymmetricCipher(ivSpec.getIV(), secretKey.getEncoded(), ciphertext, SymmetricAlgorithm.fromLabel(symmetricAlgorithm.getLabel()));
    }

    protected Cipher cbcCipherHelper(SymmetricAlgorithm symmetricAlgorithm) throws NoSuchPaddingException, SafencryptException {
        final String algorithm = getAlgorithmForCipher(symmetricAlgorithm);
        try {
            return Cipher.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            try {
                Security.addProvider(new BouncyCastleProvider());
                return Cipher.getInstance(algorithm, "BC");
            } catch (NoSuchPaddingException ex) {
                throw new SafencryptException(errorConfig.message(ErrorCodes.SAF_012.name(), ex, symmetricAlgorithm.getLabel()));
            } catch (Exception ex) {
                throw new SafencryptException(errorConfig.message(ErrorCodes.SAF_004.name(), ex, symmetricAlgorithm.getLabel()));
            }
        }
    }


    @SneakyThrows
    protected SymmetricCipher encryptWithGCM(int tagLength, int ivSize, SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] plaintext, byte[] associatedData) {
        isAlgorithmSecure(symmetricAlgorithm.getLabel());
        isKeyLengthCorrect(secretKey, symmetricAlgorithm);

        final Cipher cipher = gcmCipherHelper(symmetricAlgorithm);

        final IvParameterSpec ivSpec = new IvParameterSpec(generateIv(ivSize));
        isIvLengthCorrect(ivSpec.getIV(), ivSize, symmetricAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(tagLength, ivSpec.getIV()));

        if (associatedData != null && associatedData.length > 0) {
            cipher.updateAAD(associatedData);
        }

        final byte[] ciphertext = cipher.doFinal(plaintext);
        return new SymmetricCipher(ivSpec.getIV(), secretKey.getEncoded(), ciphertext, SymmetricAlgorithm.fromLabel(symmetricAlgorithm.getLabel()));
    }

    protected Cipher gcmCipherHelper(SymmetricAlgorithm symmetricAlgorithm) throws SafencryptException {
        try {
            return Cipher.getInstance(getAlgorithmForCipher(symmetricAlgorithm));

        } catch (Exception ex) {
            throw new SafencryptException(errorConfig.message(ErrorCodes.SAF_004.name(), ex, symmetricAlgorithm.getLabel()));
        }
    }


    @SneakyThrows
    protected byte[] decrypt(int ivSize, SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] iv, byte[] cipherText) {
        log.warn(errorConfig.message(ErrorCodes.SAF_011.name(), getAlgorithmAndMode(symmetricAlgorithm)));
        isAlgorithmSecure(symmetricAlgorithm.getLabel());
        isKeyLengthCorrect(secretKey, symmetricAlgorithm);
        isIvLengthCorrect(iv, ivSize, symmetricAlgorithm);

        final Cipher cipher = cbcCipherHelper(symmetricAlgorithm);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return cipher.doFinal(cipherText);
    }

    @SneakyThrows
    protected byte[] decryptWithGCM(int tagLength, int ivSize, SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] iv, byte[] cipherText, byte[] associatedData) {
        isAlgorithmSecure(symmetricAlgorithm.getLabel());
        isKeyLengthCorrect(secretKey, symmetricAlgorithm);
        isIvLengthCorrect(iv, ivSize, symmetricAlgorithm);

        final Cipher cipher = gcmCipherHelper(symmetricAlgorithm);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(tagLength, iv));
        if (associatedData != null && associatedData.length > 0) cipher.updateAAD(associatedData);
        try {
            return cipher.doFinal(cipherText);
        } catch (AEADBadTagException e) {
            throw new SafencryptException(errorConfig.message(ErrorCodes.SAF_002.name(), e));
        }
    }


    @SneakyThrows
    protected void isAlgorithmSecure(String symmetricAlgorithm) {
        if (symmetricConfig.algorithms().contains(symmetricAlgorithm))
            return;

        throw new SafencryptException(errorConfig.message(ErrorCodes.SAF_001.name(), symmetricAlgorithm));
    }

    @SneakyThrows
    protected void isKeyLengthCorrect(SecretKey secretKey, SymmetricAlgorithm symmetricAlgorithm) {

        final int keyLength = secretKey.getEncoded().length * 8;
        final HashSet<Integer> allowedKeyLength = new HashSet<>();
        allowedKeyLength.addAll(List.of(128, 192, 256));


        if (Arrays.equals(secretKey.getEncoded(), new byte[secretKey.getEncoded().length])) {
            throw new SafencryptException(errorConfig.message(ErrorCodes.SAF_015.name()));
        }

        if (!allowedKeyLength.contains(keyLength) || keyLength != getKeySize(symmetricAlgorithm)) {
            throw new SafencryptException(errorConfig.message(ErrorCodes.SAF_003.name(), String.valueOf(secretKey.getEncoded().length), symmetricAlgorithm.getLabel(), String.valueOf(getKeySize(symmetricAlgorithm) / 8)));
        }
    }


    @SneakyThrows
    protected void isIvLengthCorrect(byte[] iv, int ivSize, SymmetricAlgorithm symmetricAlgorithm) {

        if (iv.length != ivSize) {
            throw new SafencryptException(errorConfig.message(ErrorCodes.SAF_014.name(), String.valueOf(iv.length), symmetricAlgorithm.getLabel(), String.valueOf(ivSize)));
        }
    }
}
