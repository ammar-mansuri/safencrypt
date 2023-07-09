package com.wrapper.symmetric.utils;

import com.wrapper.symmetric.builder.SafEncrypt;
import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.models.SafEncryptContainer;
import com.wrapper.symmetric.models.SymmetricCipher;
import com.wrapper.symmetric.models.SymmetricCipherBase64;

import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Random;

public class Utility {

    public static String getKeyAlgorithm(SymmetricAlgorithm symmetricAlgorithm) {

        return symmetricAlgorithm.getLabel().split("_")[0];
    }


    public static String getAlgorithmForCipher(SymmetricAlgorithm symmetricAlgorithm) {

        final String[] algo = symmetricAlgorithm.getLabel().split("_");
        return algo[0] + "/" + algo[1] + "/" + algo[3];
    }

    public static String getAlgorithmAndMode(SymmetricAlgorithm symmetricAlgorithm) {

        final String[] algo = symmetricAlgorithm.getLabel().split("_");
        return algo[0] + "/" + algo[1];
    }

    public static String getModeOfOperation(SymmetricAlgorithm symmetricAlgorithm) {

        return symmetricAlgorithm.getLabel().split("_")[1];
    }

    public static Integer getKeySize(SymmetricAlgorithm symmetricAlgorithm) {

        return Integer.valueOf(symmetricAlgorithm.getLabel().split("_")[2]);
    }

    public static String getPadding(SymmetricAlgorithm symmetricAlgorithm) {

        return symmetricAlgorithm.getLabel().split("_")[3];
    }

    public static SafEncryptContainer getSymmetricEncodedResult(final SymmetricCipher symmetricCipher, String keyAlias) {
        return new SymmetricCipherBase64(
                Base64.getEncoder().encodeToString(symmetricCipher.iv()),
                keyAlias,
                Base64.getEncoder().encodeToString(symmetricCipher.ciphertext()),
                symmetricCipher.symmetricAlgorithm());
    }

    public static boolean isGCM(SymmetricAlgorithm symmetricAlgorithm) {

        return symmetricAlgorithm.getLabel().startsWith("AES_GCM");
    }

    public static boolean isKeyDefined(SafEncrypt safEncrypt) {
        return safEncrypt.getKey() != null && safEncrypt.getKey().getEncoded().length > 0;
    }

    public static IvParameterSpec generateIv(int IV_LENGTH) {

        final byte[] iv = new byte[IV_LENGTH];
        final Random random = new SecureRandom();
        random.nextBytes(iv);
        return new IvParameterSpec(iv);
    }


}
