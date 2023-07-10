package com.safEncrypt.symmetric.config;


import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Set;

public record PBEKeyConfig(Set<String> algorithms, @JsonProperty("salt-length") int saltLength, int iterations) {
}
