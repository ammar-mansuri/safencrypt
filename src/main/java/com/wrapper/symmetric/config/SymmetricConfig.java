package com.wrapper.symmetric.config;


import com.fasterxml.jackson.annotation.*;

import java.util.Set;

public record SymmetricConfig(@JsonProperty("symmetric-algorithms") Set<String> algorithms) {
}
