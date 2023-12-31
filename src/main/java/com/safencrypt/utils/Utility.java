package com.safencrypt.utils;

import com.safencrypt.builder.SafEncrypt;
import com.safencrypt.enums.SymmetricAlgorithm;
import com.safencrypt.models.SymmetricCipher;
import com.safencrypt.models.SymmetricCipherBase64;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Random;

public class Utility {

    public static String getKeyAlgorithm(final SymmetricAlgorithm symmetricAlgorithm) {

        return symmetricAlgorithm.getLabel().split("_")[0];
    }


    public static String getAlgorithmForCipher(final SymmetricAlgorithm symmetricAlgorithm) {

        final String[] algo = symmetricAlgorithm.getLabel().split("_");
        return algo[0] + "/" + algo[1] + "/" + algo[3];
    }

    public static String getAlgorithmAndMode(final SymmetricAlgorithm symmetricAlgorithm) {

        final String[] algo = symmetricAlgorithm.getLabel().split("_");
        return algo[0] + "/" + algo[1];
    }

    public static String getAlgoForConstraints(final SymmetricAlgorithm symmetricAlgorithm) {

        final String[] algo = symmetricAlgorithm.getLabel().split("_");
        return algo[0] + "_" + algo[1];
    }

    public static Integer getKeySize(final SymmetricAlgorithm symmetricAlgorithm) {

        return Integer.valueOf(symmetricAlgorithm.getLabel().split("_")[2]);
    }

    public static String getPadding(final SymmetricAlgorithm symmetricAlgorithm) {

        return symmetricAlgorithm.getLabel().split("_")[3];
    }

    public static SymmetricCipherBase64 getSymmetricEncodedResult(final SymmetricCipher symmetricCipher, final String keyAlias) {
        return new SymmetricCipherBase64(
                Base64.getEncoder().encodeToString(symmetricCipher.iv()),
                keyAlias,
                Base64.getEncoder().encodeToString(symmetricCipher.cipherText()),
                symmetricCipher.symmetricAlgorithm());
    }

    public static boolean isGCM(final SymmetricAlgorithm symmetricAlgorithm) {

        return symmetricAlgorithm.getLabel().startsWith("AES_GCM");
    }

    public static boolean isKeyDefined(final SafEncrypt safEncrypt) {
        return safEncrypt.getKey() != null && safEncrypt.getKey().getEncoded().length > 0;
    }

    public static byte[] generateIv(final int IV_LENGTH) {

        final byte[] iv = new byte[IV_LENGTH];
        final Random random = new SecureRandom();
        random.nextBytes(iv);
        return iv;
    }


}
