package com.safencrypt.models;

import com.safencrypt.enums.SymmetricAlgorithm;

public record SymmetricCipherBase64(String iv, String keyAlias, String cipherText,
                                    SymmetricAlgorithm symmetricAlgorithm) {
}
