package com.safEncrypt.enums;


import java.util.Arrays;


public enum KeyAlgorithm {

    PBKDF2_With_Hmac_SHA256("PBKDF2WithHmacSHA256"),
    PBKDF2_With_Hmac_SHA512("PBKDF2WithHmacSHA512"),
    DEFAULT("PBKDF2WithHmacSHA512"); //Default should be in the last of all the ENUM's


    public String getLabel() {
        return label;
    }

    private final String label;

    public static KeyAlgorithm fromLabel(String label) {

        return Arrays.stream(KeyAlgorithm.values()).filter(val -> val.getLabel().equals(label)).findFirst().orElseThrow(() -> new IllegalArgumentException("The Selected Algorithm is Currently Not Supported " + label));
    }

    private KeyAlgorithm(String label) {
        this.label = label;
    }


}

