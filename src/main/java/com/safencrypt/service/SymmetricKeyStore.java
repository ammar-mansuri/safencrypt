package com.safencrypt.service;

import com.safencrypt.config.ErrorConfig;
import com.safencrypt.config.KeyStoreConfig;
import com.safencrypt.exceptions.SafencryptException;
import com.safencrypt.utils.ErrorCodes;
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


        final File keystoreFile = new File(keyStoreConfig.filePath());

        final KeyStore keyStore = KeyStore.getInstance(KEY_STORE_FORMAT);

        if (!keystoreFile.exists()) {
            keyStore.load(null, keyStoreConfig.password().toCharArray());
        } else {
            keyStore.load(new FileInputStream(keystoreFile), keyStoreConfig.password().toCharArray());
        }


        final KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
        final KeyStore.PasswordProtection keyPasswordProtection = new KeyStore.PasswordProtection(keyStoreConfig.password().toCharArray());
        keyStore.setEntry(alias, secretKeyEntry, keyPasswordProtection);

        try (FileOutputStream fileOutputStream = new FileOutputStream(keystoreFile)) {
            keyStore.store(fileOutputStream, keyStoreConfig.password().toCharArray());
        }

    }

    @SneakyThrows
    public SecretKey loadKey(String alias) {

        final char[] password = keyStoreConfig.password().toCharArray();
        final KeyStore keyStore = KeyStore.getInstance(KEY_STORE_FORMAT);

        try (FileInputStream fis = new FileInputStream(keyStoreConfig.filePath())) {
            keyStore.load(fis, password);
            final SecretKey secretKey = (SecretKey) keyStore.getKey(alias, password);

            Objects.requireNonNull(secretKey);

            return secretKey;
        } catch (Exception e) {
            throw new SafencryptException(errorConfig.message(ErrorCodes.SAF_006.name(), e, alias));
        }

    }
}
