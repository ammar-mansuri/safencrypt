package com.safencrypt.service;

import com.safencrypt.builder.SafEncrypt;
import com.safencrypt.config.ErrorConfig;
import com.safencrypt.config.SymmetricConfig;
import com.safencrypt.enums.SymmetricAlgorithm;
import com.safencrypt.exceptions.SafencryptException;
import com.safencrypt.models.SymmetricStreamingCipher;
import com.safencrypt.utils.ErrorCodes;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

import static com.safencrypt.utils.Utility.*;

@Slf4j
public class SymmetricStreamingImpl {

    private final SymmetricConfig symmetricConfig;
    private final ErrorConfig errorConfig;

    public SymmetricStreamingImpl(SymmetricConfig symmetricConfig, ErrorConfig errorConfig) {
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
    public SymmetricStreamingCipher encrypt(SafEncrypt safEncrypt) {

        final SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.fromLabel(safEncrypt.getSymmetricAlgorithm().getLabel());

        final SymmetricConfig.Constraints constraints = symmetricConfig.getConstraint(getAlgoForConstraints(symmetricAlgorithm));

        SecretKey secretKey = safEncrypt.getKey();

        if (!isKeyDefined(safEncrypt)) {
            secretKey = new SecretKeySpec(SymmetricKeyGenerator.generateSymmetricKey(symmetricAlgorithm), "AES");
        }

        if (isGCM(symmetricAlgorithm)) {
            return encryptWithGCM(constraints.tagSize(), constraints.ivSize(), safEncrypt.getSymmetricAlgorithm(), secretKey, safEncrypt.getPlainFile(), safEncrypt.getCipherFile(), safEncrypt.getAssociatedData());
        }

        return encrypt(constraints.ivSize(), safEncrypt.getSymmetricAlgorithm(), secretKey, safEncrypt.getPlainFile(), safEncrypt.getCipherFile());
    }

    /**
     * Main DECRYPT Function Call from builder
     *
     * @param safEncrypt
     * @return
     */
    @SneakyThrows
    public void decrypt(SafEncrypt safEncrypt) {
        final SymmetricAlgorithm algorithm = safEncrypt.getSymmetricAlgorithm();
        final SymmetricConfig.Constraints constraints = symmetricConfig.getConstraint(getAlgoForConstraints(algorithm));
        if (isGCM(algorithm)) {
            decryptWithGCM(constraints.tagSize(), constraints.ivSize(), safEncrypt.getSymmetricAlgorithm(), safEncrypt.getKey(), safEncrypt.getIv(), safEncrypt.getCipherFile(), safEncrypt.getPlainFile(), safEncrypt.getAssociatedData());
        } else {
            decrypt(constraints.ivSize(), safEncrypt.getSymmetricAlgorithm(), safEncrypt.getKey(), safEncrypt.getIv(), safEncrypt.getCipherFile(), safEncrypt.getPlainFile());
        }
    }


    @SneakyThrows
    protected SymmetricStreamingCipher encrypt(int ivSize, SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, final File inputFile, final File outputFile) {
        log.warn(errorConfig.message(ErrorCodes.SAF_011.name(), getAlgorithmAndMode(symmetricAlgorithm)));
        isAlgorithmSecure(symmetricAlgorithm.getLabel());
        isKeyLengthCorrect(secretKey, symmetricAlgorithm);

        final Cipher cipher = cbcCipherHelper(symmetricAlgorithm);
        final IvParameterSpec ivSpec = new IvParameterSpec(generateIv(ivSize));
        isIvLengthCorrect(ivSpec.getIV(), ivSize, symmetricAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        streamingCipherHelper(inputFile, outputFile, cipher);
        return new SymmetricStreamingCipher(ivSpec.getIV(), secretKey.getEncoded(), SymmetricAlgorithm.fromLabel(symmetricAlgorithm.getLabel()));
    }


    @SneakyThrows
    protected SymmetricStreamingCipher encryptWithGCM(int tagLength, int ivSize, SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, final File inputFile, final File outputFile, byte[] associatedData) {
        isAlgorithmSecure(symmetricAlgorithm.getLabel());
        isKeyLengthCorrect(secretKey, symmetricAlgorithm);

        final Cipher cipher = gcmCipherHelper(symmetricAlgorithm);

        final IvParameterSpec ivSpec = new IvParameterSpec(generateIv(ivSize));
        isIvLengthCorrect(ivSpec.getIV(), ivSize, symmetricAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(tagLength, ivSpec.getIV()));

        if (associatedData != null && associatedData.length > 0) {
            cipher.updateAAD(associatedData);
        }
        streamingCipherHelper(inputFile, outputFile, cipher);
        return new SymmetricStreamingCipher(ivSpec.getIV(), secretKey.getEncoded(), SymmetricAlgorithm.fromLabel(symmetricAlgorithm.getLabel()));
    }


    @SneakyThrows
    protected void decrypt(int ivSize, SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] iv, final File inputFile, final File outputFile) {
        log.warn(errorConfig.message(ErrorCodes.SAF_011.name(), getAlgorithmAndMode(symmetricAlgorithm)));
        isAlgorithmSecure(symmetricAlgorithm.getLabel());
        isKeyLengthCorrect(secretKey, symmetricAlgorithm);
        isIvLengthCorrect(iv, ivSize, symmetricAlgorithm);
        final Cipher cipher = cbcCipherHelper(symmetricAlgorithm);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        streamingCipherHelper(inputFile, outputFile, cipher);

    }

    @SneakyThrows
    protected void decryptWithGCM(int tagLength, int ivSize, SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] iv, final File inputFile, final File outputFile, byte[] associatedData) {
        isAlgorithmSecure(symmetricAlgorithm.getLabel());
        isKeyLengthCorrect(secretKey, symmetricAlgorithm);
        isIvLengthCorrect(iv, ivSize, symmetricAlgorithm);
        final Cipher cipher = gcmCipherHelper(symmetricAlgorithm);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(tagLength, iv));
        if (associatedData != null && associatedData.length > 0) cipher.updateAAD(associatedData);
        streamingCipherHelper(inputFile, outputFile, cipher);
    }

    private void streamingCipherHelper(File inputFile, File outputFile, Cipher cipher) throws SafencryptException {
        try (InputStream inputStream = new FileInputStream(inputFile)) {
            try (OutputStream outputStream = new FileOutputStream(outputFile)) {
                try (CipherInputStream cipherInputStream = new CipherInputStream(inputStream, cipher)) {
                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = cipherInputStream.read(buffer)) != -1) {
                        outputStream.write(buffer, 0, bytesRead);
                    }
                }
            }
        } catch (IOException e) {
            throw new SafencryptException(e);
        }
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

    protected Cipher gcmCipherHelper(SymmetricAlgorithm symmetricAlgorithm) throws SafencryptException {
        try {
            return Cipher.getInstance(getAlgorithmForCipher(symmetricAlgorithm));

        } catch (Exception ex) {
            throw new SafencryptException(errorConfig.message(ErrorCodes.SAF_004.name(), ex, symmetricAlgorithm.getLabel()));
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
