package com.safEncrypt.mapper;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.safEncrypt.config.*;
import com.safEncrypt.exceptions.SafencryptException;
import lombok.SneakyThrows;

import java.io.InputStream;
import java.util.Map;

import static com.safEncrypt.utils.Constants.*;


public class ConfigParser {

    private static SymmetricConfig symmetricConfig;
    private static SymmetricInteroperabilityConfig interoperabilityConfig;
    private static KeyStoreConfig keystoreConfig;

    private static com.safEncrypt.config.PBEKeyConfig PBEKeyConfig;
    private static ErrorConfig errorConfig;


    public static SymmetricConfig getSymmetricConfig() {
        return symmetricConfig;
    }

    public static SymmetricInteroperabilityConfig getInteroperabilityConfig() {
        return interoperabilityConfig;
    }

    public static KeyStoreConfig getKeystoreConfig() {
        return keystoreConfig;
    }

    public static PBEKeyConfig getPbKeyConfig() {
        return PBEKeyConfig;
    }

    public static ErrorConfig getErrorConfig() {
        return errorConfig;
    }

    static {
        parseConfigFiles();
    }

    @SneakyThrows
    public static void parseConfigFiles() {

        final ObjectMapper objectMapper = new ObjectMapper();

        symmetricConfig = objectMapper.readValue(getFile(SYMMETRIC_ALGORITHMS_CONFIG), SymmetricConfig.class);
        interoperabilityConfig = objectMapper.readValue(getFile(SYMMETRIC_INTEROPERABILITY_CONFIG), SymmetricInteroperabilityConfig.class);
        keystoreConfig = objectMapper.readValue(getFile(SYMMETRIC_KEYSTORE_CONFIG), KeyStoreConfig.class);
        PBEKeyConfig = objectMapper.readValue(getFile(SYMMETRIC_PBEKEY_CONFIG), PBEKeyConfig.class);

        final ObjectMapper objectMapperYaml = new ObjectMapper(new YAMLFactory());
        Map<String, String> configMap = objectMapperYaml.readValue(getFile(SAFENCRYPT_ERROR_CONFIG), new TypeReference<>() {
        });
        errorConfig = new ErrorConfig(configMap);

    }

    @SneakyThrows
    private static byte[] getFile(String fileName) {
        final InputStream stream = Thread.currentThread().getContextClassLoader().getResourceAsStream(fileName);
        try {
            if (stream == null) {
                throw new SafencryptException("Unable to load Config file " + fileName);
            }
            return stream.readAllBytes();
        } catch (Exception e) {
            throw new SafencryptException("Unable to load Config file " + fileName);
        }
    }


}
