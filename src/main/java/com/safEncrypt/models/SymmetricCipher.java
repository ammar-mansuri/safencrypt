package com.safEncrypt.models;

import com.safEncrypt.enums.SymmetricAlgorithm;

public record SymmetricCipher(byte[] iv, byte[] key, byte[] ciphertext, SymmetricAlgorithm symmetricAlgorithm) {
}