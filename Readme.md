
# Safencrypt

A cryptographic library that aims to ease down the process of symmetric encryption/decryption for the developers. 





## Run Locally

Clone the project

```bash
  git clone https://link-to-project
```

Go to the project directory

```bash
  cd my-project
```

Install dependencies

```bash
  mvn clean install
```




## Notes

1. Throught the library, the algorithms are used in the specified notation "AES_GCM_128_NoPadding". The breakdown of which is Algorithm+Mode+KeyLenght+Padding. 

2. The library uses safe defaults for the creation of Initialization Vector (IV) during encryption, which is returned back to the user for further usage (decryption).

3. The default Algorithm of the library, unless specified by the user, is "AES_GCM_128_NoPadding". If you dont specify the algorithm in parameter of the encryption/decryption builder, it will automatically pick the DEFAULT one. 

```java
    SymmetricBuilder.encryption()
```

```java
    SymmetricBuilder.decryption()
```

4. Enum class SymmetricAlgorithm contains a list of the algorithms that are supported currently by the library, provided that they are set as SECURE in the configuration file. 

5. When you dont want to use the DEFAULT algorithm for encryption/decryption purposes, please make sure to specify the correct ALGORITHM from the SymmetricAlgorithm class while creating the builder.

```java
    SymmetricBuilder.encryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
```

```java
    SymmetricBuilder.decryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
```

5. Only the Algorithms in SymmetricAlgorithm class are currently supported. The algorithms in SymmetricAlgorithm class must also be declared as secure in the applications.yml file when extending the library. 
## IMPORTANT: Encoding/Decoding

In order to make sure you have seamless experience while encryption and decryption it is very IMPORTANT to make sure the encoding and decoding is done correctly. It should be done everytime you convert from String to bytes[] and vice versa. 


1. When providing an input to the builder for Encryption, make sure to ENCODE it using the correct encoding format. 

```java
    byte[] plainText = "Hello World 121@#".getBytes(StandardCharsets.UTF_8);
```

OR (As the default encoding in java is UTF-8)

```java
    byte[] plainText = "Hello World 121@#".getBytes();
```

2. When you get the plainText bytes[] back after the Decryption process, simlary it should be DECODED to get back the correct plain text. 

```java
    new String(plainTextBytes[] , StandardCharsets.UTF_8);
```
## Usage Examples [Symmetric Key Generation]

1. You want to geneate a symmetric key using the library defaults?

```java
SecretKey secretKey = KeyGenerator.generateSymmetricKey();
```

2. You want to geneate a symmetric key specifying an algorithm for which the you want to use the key?

```java
SecretKey secretKey = KeyGenerator.generateSymmetricKey(SymmetricAlgorithm.AES_GCM_128_NoPadding);
```

## Usage Examples [Symmetric Encryption/Decryption]

1. You want to encrypt/decrypt the data using the Safe Defaults from the library without worrying about the Safe Algorithm, Key?

```java
        byte[] plainText = "Hello World".getBytes(StandardCharsets.UTF_8);

        SymmetricCipher symmetricCipher =
                SymmetricBuilder.encryption()
                        .generateKey()
                        .plaintext(plainText)
                        .encrypt();

        SymmetricPlain symmetricPlain =
                SymmetricBuilder.decryption()
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext())
                        .decrypt();
```

2. You want to encrypt/decrypt the data using the Safe Default Algorithm from the library, but you want to specify the key yourself? [Allowed but not Recommended! Should only be used if the secure key is already generated, Prefer using the Library Default Key Generation]

Example1: Generating the key yourself, and loading any key using the loadKey method
```java
        byte[] plainText = "Hello World 121@#".getBytes(StandardCharsets.UTF_8);
        byte[] key = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(key);

        SymmetricCipher symmetricCipher =
                SymmetricBuilder.encryption()
                        .loadKey(key)
                        .plaintext(plainText)
                        .encrypt();

        SymmetricPlain symmetricPlain =
                SymmetricBuilder.decryption()
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext())
                        .decrypt();
```

Example2: Generating the key from the library, and loading any key using the loadKey method [Fine, but PREFFERED is to use the generateKey method]

```java
        byte[] plainText = "Hello World 121@#".getBytes(StandardCharsets.UTF_8);
        byte[] key = SymmetricKeyGenerator.generateSymmetricKey(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding);

        SymmetricCipher symmetricCipher =
                SymmetricBuilder.encryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
                        .loadKey(key)
                        .plaintext(plainText)
                        .encrypt();

        SymmetricPlain symmetricPlain =
                SymmetricBuilder.decryption()
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext())
                        .decrypt();
```

3. You want to encrypt/decrypt the data providing a specific Algorithm from the library, but you want to use the key generated by the library ?

```java
        byte[] plainText = "1232F #$$^%$^ Hello World".getBytes(StandardCharsets.UTF_8);

        SymmetricCipher symmetricCipher =
                SymmetricBuilder.encryption(SymmetricAlgorithm.AES_GCM_256_NoPadding)
                        .generateKey()
                        .plaintext(plainText)
                        .encrypt();

        SymmetricPlain symmetricPlain =
                SymmetricBuilder.decryption(symmetricCipher.symmetricAlgorithm())
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext())
                        .decrypt();
```

4. You want to encrypt/decrypt the data providing a specific Algorithm from the library and providing the Key ?

```java
        byte[] plainText = "Hello World JCA WRAPPER".getBytes(StandardCharsets.UTF_8);
        SymmetricAlgorithm symmetricAlgorithm = SymmetricAlgorithm.AES_GCM_192_NoPadding;
        SecretKey secretKey = KeyGenerator.generateSymmetricKey(symmetricAlgorithm);

        SymmetricCipher symmetricCipher =
                SymmetricBuilder.encryption(symmetricAlgorithm)
                        .generateKey()
                        .plaintext(plainText)
                        .encrypt();

        SymmetricPlain symmetricPlain =
                SymmetricBuilder.decryption(symmetricCipher.symmetricAlgorithm())
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext())
                        .decrypt();
```

5. You want to encrypt/decrypt the data using AES_GCM and also want to sepcify the Associated Data ?

```java
        byte[] plainText = "Hello World JCA WRAPPER Using GCM With AEAD".getBytes(StandardCharsets.UTF_8);
        byte[] associatedData = "I am associated data".getBytes(StandardCharsets.UTF_8);

        SymmetricCipher symmetricCipher =
                SymmetricBuilder.encryption(SymmetricAlgorithm.AES_GCM_128_NoPadding)
                        .generateKey()
                        .plaintext(plainText, associatedData)
                        .encrypt();

        SymmetricPlain symmetricPlain =
                SymmetricBuilder.decryption(symmetricCipher.symmetricAlgorithm())
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext(), associatedData)
                        .decrypt();
```

6. You want to encrypt/decrypt the data using AES_CBC algorithm ?

```java
        byte[] plainText = "TESTING CBC 128 With PKCS5 PADDING".getBytes(StandardCharsets.UTF_8);

        SymmetricCipher symmetricCipher =
                SymmetricBuilder.encryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
                        .generateKey()
                        .plaintext(plainText)
                        .encrypt();
        
        SymmetricPlain symmetricPlain =
                SymmetricBuilder.decryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext())
                        .decrypt();

```