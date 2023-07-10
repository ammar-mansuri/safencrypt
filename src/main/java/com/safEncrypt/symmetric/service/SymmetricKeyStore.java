package com.safEncrypt.symmetric.service;

import com.safEncrypt.exceptions.SafencryptException;
import com.safEncrypt.symmetric.config.ErrorConfig;
import com.safEncrypt.symmetric.config.KeyStoreConfig;
import lombok.SneakyThrows;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.util.Objects;

public class SymmetricKeyStore {

    private static String KEY_STORE_FORMAT = "JCEKS";
    private final KeyStoreConfig keyStoreConfig;

    private final ErrorConfig errorConfig;

    public SymmetricKeyStore(KeyStoreConfig keyStoreConfig, ErrorConfig errorConfig) {
        this.keyStoreConfig = keyStoreConfig;
        this.errorConfig = errorConfig;
    }

    @SneakyThrows
    protected void saveKey(String alias, SecretKey secretKey) {


        File keystoreFile = new File(keyStoreConfig.filePath());

        KeyStore keyStore = KeyStore.getInstance(KEY_STORE_FORMAT);

        if (!keystoreFile.exists()) {
            keyStore.load(null, keyStoreConfig.password().toCharArray());
        } else {
            keyStore.load(new FileInputStream(keystoreFile), keyStoreConfig.password().toCharArray());
        }


        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
        KeyStore.PasswordProtection keyPasswordProtection = new KeyStore.PasswordProtection(keyStoreConfig.password().toCharArray());
        keyStore.setEntry(alias, secretKeyEntry, keyPasswordProtection);

        try (FileOutputStream fileOutputStream = new FileOutputStream(keystoreFile)) {
            keyStore.store(fileOutputStream, keyStoreConfig.password().toCharArray());
        }

    }

    @SneakyThrows
    public SecretKey loadKey(String alias) {

        char[] password = keyStoreConfig.password().toCharArray();
        KeyStore keyStore = KeyStore.getInstance(KEY_STORE_FORMAT);

        try (FileInputStream fis = new FileInputStream(keyStoreConfig.filePath())) {
            keyStore.load(fis, password);
            SecretKey secretKey = (SecretKey) keyStore.getKey(alias, password);

            Objects.requireNonNull(secretKey);

            return secretKey;
        } catch (Exception e) {
            throw new SafencryptException(errorConfig.message("SAF-006", e, alias));
        }

    }
}
