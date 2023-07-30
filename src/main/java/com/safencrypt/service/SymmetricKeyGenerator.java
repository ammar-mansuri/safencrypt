package com.safencrypt.service;

import com.safencrypt.mapper.ConfigParser;
import com.safencrypt.config.PBEKeyConfig;
import com.safencrypt.enums.KeyAlgorithm;
import com.safencrypt.enums.SymmetricAlgorithm;
import com.safencrypt.utils.Utility;
import lombok.SneakyThrows;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class SymmetricKeyGenerator {

    private static PBEKeyConfig pbeKeyConfig = ConfigParser.getPbKeyConfig();

    public static byte[] generateSymmetricKey() {
        return generateSymmetricKey(SymmetricAlgorithm.DEFAULT);
    }

    @SneakyThrows
    public static byte[] generateSymmetricKey(SymmetricAlgorithm symmetricAlgorithm) {

        final KeyGenerator kg = KeyGenerator.getInstance(Utility.getKeyAlgorithm(symmetricAlgorithm));
        kg.init(Utility.getKeySize(symmetricAlgorithm));
        return kg.generateKey().getEncoded();
    }


    public static byte[] generateSymmetricKeyFromPassword(byte[] password, int keyLength) {
        return generateSymmetricKeyFromPassword(password, KeyAlgorithm.DEFAULT, keyLength);
    }


    @SneakyThrows
    public static byte[] generateSymmetricKeyFromPassword(byte[] password, KeyAlgorithm keyAlgorithm, int keyLength) {

        final byte[] salts = new byte[pbeKeyConfig.saltLength()];
        final SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(salts);

        final SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(keyAlgorithm.getLabel());
        final PBEKeySpec pbeKeySpec = new PBEKeySpec(new String(password, StandardCharsets.UTF_8).toCharArray(), salts, pbeKeyConfig.iterations(), keyLength);
        final SecretKey key = secretKeyFactory.generateSecret(pbeKeySpec);
        return key.getEncoded();

    }

}
