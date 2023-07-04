package com.wrapper.symmetric.models;

import com.wrapper.symmetric.enums.SymmetricAlgorithm;

public record SymmetricCipherBase64(String iv, String keyAlias, String ciphertext,
                                    SymmetricAlgorithm symmetricAlgorithm) {
}