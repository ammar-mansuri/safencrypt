package com.wrapper.symmetric.service;

import com.wrapper.symmetric.enums.SymmetricAlgorithm;
import com.wrapper.symmetric.utils.Utility;
import lombok.SneakyThrows;

import javax.crypto.KeyGenerator;

public class SymmetricKeyGenerator {

    public static byte[] generateSymmetricKey() {
        return generateSymmetricKey(SymmetricAlgorithm.DEFAULT);
    }

    @SneakyThrows
    public static byte[] generateSymmetricKey(SymmetricAlgorithm symmetricAlgorithm) {

        KeyGenerator kg = KeyGenerator.getInstance(Utility.getKeyAlgorithm(symmetricAlgorithm));
        kg.init(Utility.getKeySize(symmetricAlgorithm));
        return kg.generateKey().getEncoded();
    }
}
