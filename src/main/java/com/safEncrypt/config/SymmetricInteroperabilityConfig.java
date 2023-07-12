package com.safEncrypt.config;


import com.fasterxml.jackson.annotation.JsonProperty;
import com.safEncrypt.exceptions.SafencryptException;

import java.text.MessageFormat;
import java.util.Map;

public record SymmetricInteroperabilityConfig(@JsonProperty("interoperable-languages") Map<String, Details> languages) {

    public Details languageDetails(String key) throws SafencryptException {
        return languages.entrySet().stream().filter(x -> x.getKey().equalsIgnoreCase(key))
                .map(Map.Entry::getValue)
                .findFirst()
                .orElseThrow(() -> new SafencryptException(MessageFormat.format("SAF-016 : Unable to find Interoperability Configuration for the selected language [{0}]", key)));
    }

    public record Details(@JsonProperty("library-Provider") String libraryProvider, Symmetric symmetric) {

        public record Symmetric(@JsonProperty("default-algo") String defaultAlgo,
                                @JsonProperty("iv-bytes") Integer ivSize,
                                @JsonProperty("tag-bits") Integer tagSize) {
        }
    }

}
