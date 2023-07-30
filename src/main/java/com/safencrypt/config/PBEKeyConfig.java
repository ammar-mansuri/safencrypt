package com.safencrypt.config;


import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Set;

public record PBEKeyConfig(Set<String> algorithms, @JsonProperty("salt-bytes") int saltLength, int iterations) {
}
