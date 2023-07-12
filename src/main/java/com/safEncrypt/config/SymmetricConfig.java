package com.safEncrypt.config;


import com.fasterxml.jackson.annotation.*;
import com.safEncrypt.exceptions.SafencryptException;

import java.text.MessageFormat;
import java.util.Map;
import java.util.Set;

public record SymmetricConfig(@JsonProperty("symmetric-algorithms") Set<String> algorithms,
                              @JsonProperty("constraints") Map<String, Constraints> constraints) {

    public Constraints getConstraint(String key) throws SafencryptException {
        return constraints.entrySet().stream().filter(x -> x.getKey().equalsIgnoreCase(key))
                .map(Map.Entry::getValue)
                .findFirst()
                .orElseThrow(() -> new SafencryptException(MessageFormat.format("SAF-017 : Unable to find Constraints Mapping for the selected Algorithm [{0}]", key)));
    }

    public record Constraints(@JsonProperty("iv-bytes") Integer ivSize, @JsonProperty("tag-bits") Integer tagSize) {
    }
}
