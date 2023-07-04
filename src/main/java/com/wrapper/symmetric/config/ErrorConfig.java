package com.wrapper.symmetric.config;


import java.text.MessageFormat;
import java.util.Map;

public record ErrorConfig(Map<String, String> error) {

    public String message(String errorCode, Exception e, String... args) {
        return MessageFormat.format(
                "[{0}] | [{1} : {2}]",
                e.getClass().getCanonicalName() + ": " + e.getMessage(),
                errorCode,
                MessageFormat.format(error.get(errorCode), args)
        );
    }

    public String message(String errorCode, String... args) {
        return MessageFormat.format(
                "[{0} : {1}]",
                errorCode,
                MessageFormat.format(error.get(errorCode), args)
        );
    }
}
