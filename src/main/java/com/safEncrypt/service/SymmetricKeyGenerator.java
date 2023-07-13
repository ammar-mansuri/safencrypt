package com.safEncrypt.service;

import com.safEncrypt.mapper.ConfigParser;
import com.safEncrypt.config.PBEKeyConfig;
import com.safEncrypt.enums.KeyAlgorithm;
import com.safEncrypt.enums.SymmetricAlgorithm;
import com.safEncrypt.utils.Utility;
import lombok.SneakyThrows;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class SymmetricKeyGenerator {

    private static ConfigParser configParser = new ConfigParser();
    private static PBEKeyConfig pbeKeyConfig = configParser.getPbKeyConfig();

    public static byte[] generateSymmetricKey() {
        return generateSymmetricKey(SymmetricAlgorithm.DEFAULT);
    }

    @SneakyThrows
    public static byte[] generateSymmetricKey(SymmetricAlgorithm symmetricAlgorithm) {

        KeyGenerator kg = KeyGenerator.getInstance(Utility.getKeyAlgorithm(symmetricAlgorithm));
        kg.init(Utility.getKeySize(symmetricAlgorithm));
        return kg.generateKey().getEncoded();
    }


    public static byte[] generateSymmetricKeyFromPassword(byte[] password, int keyLength) {
        return generateSymmetricKeyFromPassword(password, KeyAlgorithm.DEFAULT, keyLength);
    }


    @SneakyThrows
    public static byte[] generateSymmetricKeyFromPassword(byte[] password, KeyAlgorithm keyAlgorithm, int keyLength) {

        byte[] salts = new byte[pbeKeyConfig.saltLength()];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(salts);

        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(keyAlgorithm.getLabel());
        PBEKeySpec pbeKeySpec = new PBEKeySpec(new String(password, StandardCharsets.UTF_8).toCharArray(), salts, pbeKeyConfig.iterations(), keyLength);
        SecretKey key = secretKeyFactory.generateSecret(pbeKeySpec);
        return key.getEncoded();
        
    }

}