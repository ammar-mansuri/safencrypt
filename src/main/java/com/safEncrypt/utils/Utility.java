package com.safEncrypt.utils;

import com.safEncrypt.builder.SafEncrypt;
import com.safEncrypt.enums.SymmetricAlgorithm;
import com.safEncrypt.models.SymmetricCipher;
import com.safEncrypt.models.SymmetricCipherBase64;

import javax.crypto.spec.IvParameterSpec;
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
                Base64.getEncoder().encodeToString(symmetricCipher.ciphertext()),
                symmetricCipher.symmetricAlgorithm());
    }

    public static boolean isGCM(final SymmetricAlgorithm symmetricAlgorithm) {

        return symmetricAlgorithm.getLabel().startsWith("AES_GCM");
    }

    public static boolean isKeyDefined(final SafEncrypt safEncrypt) {
        return safEncrypt.getKey() != null && safEncrypt.getKey().getEncoded().length > 0;
    }

    public static IvParameterSpec generateIv(final int IV_LENGTH) {

        final byte[] iv = new byte[IV_LENGTH];
        final Random random = new SecureRandom();
        random.nextBytes(iv);
        return new IvParameterSpec(iv);
    }


}
