package com.wrapper.symmetric.models;

import com.wrapper.symmetric.enums.SymmetricAlgorithm;

public record SymmetricPlain(byte[] plainText, SymmetricAlgorithm symmetricAlgorithm) {


}