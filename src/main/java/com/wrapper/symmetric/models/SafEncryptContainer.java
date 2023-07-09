package com.wrapper.symmetric.models;

import com.wrapper.symmetric.enums.SymmetricAlgorithm;

public record SafEncryptContainer(SymmetricCipher symmetricCipher, SymmetricCipherBase64 symmetricCipherBase64,
                                  SymmetricPlain symmetricPlain) {

    public record SymmetricCipher(byte[] iv, byte[] key, byte[] ciphertext,
                                  SymmetricAlgorithm symmetricAlgorithm) {

    }

    public record SymmetricCipherBase64(String iv, String keyAlias, String ciphertext,
                                        SymmetricAlgorithm symmetricAlgorithm) {


    }

    public record SymmetricPlain(byte[] plainText, SymmetricAlgorithm symmetricAlgorithm) {


    }

    public byte[] iv() {
        if (symmetricCipher != null) {
            return symmetricCipher.iv;
        }
        return null;
    }

    public byte[] key() {
        if (symmetricCipher != null) {
            return symmetricCipher.key;
        }
        return null;
    }

    public byte[] ciphertext() {
        if (symmetricCipher != null) {
            return symmetricCipher.ciphertext;
        }
        return null;
    }

    public SymmetricAlgorithm symmetricAlgorithm() {
        if (symmetricCipher != null) {
            return symmetricCipher.symmetricAlgorithm;
        }
        return null;
    }

    public byte[] plainText() {
        if (symmetricPlain != null) {
            return symmetricPlain.plainText;
        }
        return null;
    }

    
    public String ivBase64() {
        if (symmetricCipherBase64 != null) {
            return symmetricCipherBase64.iv;
        }
        return null;
    }

    public String keyAlias() {
        if (symmetricCipherBase64 != null) {
            return symmetricCipherBase64.keyAlias;
        }
        return null;
    }

    public String ciphertextBase64() {
        if (symmetricCipherBase64 != null) {
            return symmetricCipherBase64.ciphertext;
        }
        return null;
    }


}
