package com.wrapper.symmetric.models;

public interface SafEncryptContainer<T> {
    T cipherText();

    T key();

}


