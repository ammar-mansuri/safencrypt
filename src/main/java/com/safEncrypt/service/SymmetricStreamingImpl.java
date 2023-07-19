package com.safEncrypt.service;

import com.safEncrypt.builder.SafEncrypt;
import com.safEncrypt.config.ErrorConfig;
import com.safEncrypt.config.SymmetricConfig;
import com.safEncrypt.enums.SymmetricAlgorithm;
import com.safEncrypt.exceptions.SafencryptException;
import com.safEncrypt.models.SymmetricCipher;
import com.safEncrypt.models.SymmetricStreamingCipher;
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

import static com.safEncrypt.utils.Utility.*;

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
        log.warn(errorConfig.message("SAF-011", getAlgorithmAndMode(symmetricAlgorithm)));
        isAlgorithmSecure(symmetricAlgorithm.getLabel());
        isKeyLengthCorrect(secretKey, symmetricAlgorithm);

        final Cipher cipher = cbcCipherHelper(symmetricAlgorithm);
        final IvParameterSpec ivSpec = generateIv(ivSize);
        isIvLengthCorrect(ivSpec.getIV(), ivSize, symmetricAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        try (InputStream inputStream = new FileInputStream(inputFile)) {
            try (OutputStream outputStream = new FileOutputStream(outputFile)) {
                CipherInputStream cipherInputStream = new CipherInputStream(inputStream, cipher);
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = cipherInputStream.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, bytesRead);
                }
                cipherInputStream.close();
            }
        } catch (FileNotFoundException e) {
            throw new SafencryptException(e);
        } catch (IOException e) {
            throw new SafencryptException(e);
        }
        return new SymmetricStreamingCipher(ivSpec.getIV(), secretKey.getEncoded(), SymmetricAlgorithm.fromLabel(symmetricAlgorithm.getLabel()));
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
                throw new SafencryptException(errorConfig.message("SAF-012", ex, symmetricAlgorithm.getLabel()));
            } catch (NoSuchAlgorithmException ex) {
                throw new SafencryptException(errorConfig.message("SAF-004", ex, symmetricAlgorithm.getLabel()));
            } catch (NoSuchProviderException ex) {
                throw new SafencryptException(errorConfig.message("SAF-004", ex, symmetricAlgorithm.getLabel()));
            } catch (Exception ex) {
                throw new SafencryptException(errorConfig.message("SAF-004", ex, symmetricAlgorithm.getLabel()));
            }
        }
    }


    @SneakyThrows
    protected SymmetricStreamingCipher encryptWithGCM(int tagLength, int ivSize, SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, final File inputFile, final File outputFile, byte[] associatedData) {
        isAlgorithmSecure(symmetricAlgorithm.getLabel());
        isKeyLengthCorrect(secretKey, symmetricAlgorithm);

        final Cipher cipher = gcmCipherHelper(symmetricAlgorithm);

        final IvParameterSpec ivSpec = generateIv(ivSize);
        isIvLengthCorrect(ivSpec.getIV(), ivSize, symmetricAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(tagLength, ivSpec.getIV()));

        if (associatedData != null && associatedData.length > 0) {
            cipher.updateAAD(associatedData);
        }
        try (InputStream inputStream = new FileInputStream(inputFile)) {
            try (OutputStream outputStream = new FileOutputStream(outputFile)) {
                CipherInputStream cipherInputStream = new CipherInputStream(inputStream, cipher);
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = cipherInputStream.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, bytesRead);
                }
                cipherInputStream.close();
            }
        } catch (FileNotFoundException e) {
            throw new SafencryptException(e);
        } catch (IOException e) {
            throw new SafencryptException(e);
        }
        return new SymmetricStreamingCipher(ivSpec.getIV(), secretKey.getEncoded(), SymmetricAlgorithm.fromLabel(symmetricAlgorithm.getLabel()));
    }

    protected Cipher gcmCipherHelper(SymmetricAlgorithm symmetricAlgorithm) throws SafencryptException {
        try {
            return Cipher.getInstance(getAlgorithmForCipher(symmetricAlgorithm));

        } catch (NoSuchAlgorithmException ex) {
            throw new SafencryptException(errorConfig.message("SAF-004", ex, symmetricAlgorithm.getLabel()));
        } catch (Exception ex) {
            throw new SafencryptException(errorConfig.message("SAF-004", ex, symmetricAlgorithm.getLabel()));
        }
    }


    @SneakyThrows
    protected void decrypt(int ivSize, SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] iv, final File inputFile, final File outputFile) {
        log.warn(errorConfig.message("SAF-011", getAlgorithmAndMode(symmetricAlgorithm)));
        isAlgorithmSecure(symmetricAlgorithm.getLabel());
        isKeyLengthCorrect(secretKey, symmetricAlgorithm);
        isIvLengthCorrect(iv, ivSize, symmetricAlgorithm);
        final Cipher cipher = cbcCipherHelper(symmetricAlgorithm);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        try (InputStream inputStream = new FileInputStream(inputFile)) {
            try (OutputStream outputStream = new FileOutputStream(outputFile)) {
                try (CipherInputStream cipherInputStream = new CipherInputStream(inputStream, cipher)) {
                    byte[] buffer = new byte[8192];
                    int bytesRead;
                    while ((bytesRead = cipherInputStream.read(buffer)) != -1) {
                        outputStream.write(buffer, 0, bytesRead);
                    }
                }
            }
        } catch (FileNotFoundException e) {
            throw new SafencryptException(e);
        } catch (IOException e) {
            throw new SafencryptException(e);
        }

    }

    protected void decryptWithGCM(int tagLength, int ivSize, SymmetricAlgorithm symmetricAlgorithm, SecretKey secretKey, byte[] iv, final File inputFile, final File outputFile, byte[] associatedData) throws Exception {
        isAlgorithmSecure(symmetricAlgorithm.getLabel());
        isKeyLengthCorrect(secretKey, symmetricAlgorithm);
        isIvLengthCorrect(iv, ivSize, symmetricAlgorithm);
        final Cipher cipher = gcmCipherHelper(symmetricAlgorithm);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(tagLength, iv));
        if (associatedData != null && associatedData.length > 0) cipher.updateAAD(associatedData);
        try (InputStream inputStream = new FileInputStream(inputFile)) {
            try (OutputStream outputStream = new FileOutputStream(outputFile)) {
                try (CipherInputStream cipherInputStream = new CipherInputStream(inputStream, cipher)) {
                    byte[] buffer = new byte[8192];
                    int bytesRead;
                    while ((bytesRead = cipherInputStream.read(buffer)) != -1) {
                        outputStream.write(buffer, 0, bytesRead);
                    }
                }
            }
        } catch (FileNotFoundException e) {
            throw new SafencryptException(e);
        } catch (IOException e) {
            throw new SafencryptException(e);
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
        final HashSet<Integer> allowedKeyLength = new HashSet<>() {{
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
