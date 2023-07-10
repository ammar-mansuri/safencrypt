package com.safEncrypt.symmetric.models;

import com.safEncrypt.symmetric.enums.SymmetricAlgorithm;

public record SymmetricCipher(byte[] iv, byte[] key, byte[] ciphertext, SymmetricAlgorithm symmetricAlgorithm) {
}