package com.safencrypt.models;

import com.safencrypt.enums.SymmetricAlgorithm;

public record SymmetricCipher(byte[] iv, byte[] key, byte[] cipherText, SymmetricAlgorithm symmetricAlgorithm) {
}