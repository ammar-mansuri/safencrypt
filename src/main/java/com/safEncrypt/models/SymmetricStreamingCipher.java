package com.safEncrypt.models;

import com.safEncrypt.enums.SymmetricAlgorithm;

public record SymmetricStreamingCipher(byte[] iv, byte[] key, SymmetricAlgorithm symmetricAlgorithm) {
}