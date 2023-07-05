package com.wrapper.mapper;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.wrapper.exceptions.SafencryptException;
import com.wrapper.symmetric.config.ErrorConfig;
import com.wrapper.symmetric.config.KeyStoreConfig;
import com.wrapper.symmetric.config.SymmetricConfig;
import com.wrapper.symmetric.config.SymmetricInteroperabilityConfig;
import lombok.SneakyThrows;

import java.io.InputStream;
import java.util.Map;

import static com.wrapper.symmetric.utils.Constants.*;


public class ConfigParser {

    private static SymmetricConfig symmetricConfig;
    private static SymmetricInteroperabilityConfig interoperabilityConfig;
    private static KeyStoreConfig keystoreConfig;

    private static ErrorConfig errorConfig;

    static {
        parseConfigFiles();
    }

    @SneakyThrows
    public static void parseConfigFiles() {

        final ObjectMapper objectMapper = new ObjectMapper();

        symmetricConfig = objectMapper.readValue(getFile(SYMMETRIC_ALGORITHMS_CONFIG), SymmetricConfig.class);
        interoperabilityConfig = objectMapper.readValue(getFile(SYMMETRIC_INTEROPERABILITY_CONFIG), SymmetricInteroperabilityConfig.class);
        keystoreConfig = objectMapper.readValue(getFile(SYMMETRIC_KEYSTORE_CONFIG), KeyStoreConfig.class);

        final ObjectMapper objectMapperYaml = new ObjectMapper(new YAMLFactory());
        Map<String, String> configMap = objectMapperYaml.readValue(getFile(SAFENCRYPT_ERROR_CONFIG), new TypeReference<>() {
        });
        errorConfig = new ErrorConfig(configMap);
        
    }

    @SneakyThrows
    private static byte[] getFile(String fileName) {
        InputStream stream = Thread.currentThread().getContextClassLoader().getResourceAsStream(fileName);
        try {
            if (stream == null) {
                throw new SafencryptException("Unable to load Config file " + fileName);
            }
            return stream.readAllBytes();
        } catch (Exception e) {
            throw new SafencryptException("Unable to load Config file " + fileName);
        }
    }

    public static SymmetricConfig getSymmetricConfig() {
        return symmetricConfig;
    }

    public static SymmetricInteroperabilityConfig getInteroperabilityConfig() {
        return interoperabilityConfig;
    }

    public static KeyStoreConfig getKeystoreConfig() {
        return keystoreConfig;
    }

    public static ErrorConfig getErrorConfig() {
        return errorConfig;
    }
}
