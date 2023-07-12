package com.safEncrypt.models;

import com.safEncrypt.enums.SymmetricAlgorithm;

public record SymmetricCipherBase64(String iv, String keyAlias, String cipherText,
                                    SymmetricAlgorithm symmetricAlgorithm) {
}
