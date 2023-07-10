package com.safEncrypt.symmetric.models;

import com.safEncrypt.symmetric.enums.SymmetricAlgorithm;

public record SymmetricCipherBase64(String iv, String keyAlias, String cipherText,
                                    SymmetricAlgorithm symmetricAlgorithm) {
}
