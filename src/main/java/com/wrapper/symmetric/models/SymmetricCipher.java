package com.wrapper.symmetric.models;

import com.wrapper.symmetric.enums.SymmetricAlgorithm;

public record SymmetricCipher(byte[] iv, byte[] key, byte[] ciphertext,
                              SymmetricAlgorithm symmetricAlgorithm) implements SafEncryptContainer<byte[]> {

    @Override
    public byte[] cipherText() {
        return ciphertext;
    }
}
