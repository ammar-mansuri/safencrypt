package com.wrapper.symmetric.config;


import com.fasterxml.jackson.annotation.JsonProperty;
import com.wrapper.exceptions.SafencryptException;

import java.util.Map;

public record SymmetricInteroperabilityConfig(@JsonProperty("interoperable-languages") Map<String, Details> languages) {

    public Details languageDetails(String key) throws SafencryptException {
        return languages.entrySet().stream().filter(x -> x.getKey().equalsIgnoreCase(key))
                .map(Map.Entry::getValue)
                .findFirst()
                .orElseThrow(() -> new SafencryptException("Unable to find Interoperability Configuration for the selected language"));
    }

    public record Details(@JsonProperty("library-Provider") String libraryProvider, Symmetric symmetric) {

        public record Symmetric(@JsonProperty("default-algo") String defaultAlgo,
                                @JsonProperty("iv-bytes") Integer ivBytes,
                                @JsonProperty("tag-length") Integer tagLength,
                                String resultant) {
        }
    }

}
