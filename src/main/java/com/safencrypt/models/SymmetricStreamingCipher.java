package com.safencrypt.models;

import com.safencrypt.enums.SymmetricAlgorithm;

public record SymmetricStreamingCipher(byte[] iv, byte[] key, SymmetricAlgorithm symmetricAlgorithm) {
}