package com.wrapper.symmetric.config;


import com.fasterxml.jackson.annotation.*;

import java.util.Set;

public record SymmetricConfig(@JsonProperty("default-algo") String defaultAlgo,
                              @JsonProperty("symmetric-algorithms") Set<String> algorithms) {
}
