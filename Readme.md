
# Safencrypt

A cryptographic library that aims to ease down the process of symmetric encryption/decryption for the developers. 



## Run Locally

**Option#1:**

Place the provided 'safencrypt-1.0-SNAPSHOT.jar' JAR directly as a library in your project.

IntelliJ: https://www.jetbrains.com/help/idea/working-with-module-dependencies.html

Eclipse: https://www.testingdocs.com/adding-an-external-library-to-an-eclipse-project/

Visual Studio Code: https://code.visualstudio.com/docs/java/java-project


After you have imported the JAR, start with importing the SafEncrypt builder class which is the starting point of the library:

```java
import com.safencrypt.builder.SafEncrypt;
```

**Option#2:**

Clone the project from Github: https://github.com/ammar-mansuri/safencrypt.git

```bash
  git clone https://github.com/ammar-mansuri/safencrypt.git
```

Go to the project directory

```bash
  cd my-project
```

Create a local Snapshot

```bash
  mvn clean install
```

Import using maven in your project

```bash
<dependency>
    <groupId>org.tu.clausthal</groupId>
    <artifactId>safencrypt</artifactId>
    <version>1.0-SNAPSHOT</version>
</dependency>
```

After you have imported the JAR, start with importing the SafEncrypt builder class which is the starting point of the library:

```java
import com.safencrypt.builder.SafEncrypt;
```



## Notes

1. Through out the library, the algorithms are used in the specified notation "AES_GCM_128_NoPadding". The breakdown of which is Algorithm+Mode+KeyLength+Padding. 
 

2. The library doesn't allow to use a custom generated key. When using the library user is just provided with options from generate a secure random symmetric key or generating a key from a password. Please refer to  Key Generation section to have a practical overview.


3. The library uses safe defaults for the creation of Initialization Vector (IV) during encryption, which is returned back to the user for further usage (decryption).


4. The default Algorithm of the library, unless specified by the user, is "AES_GCM_128_NoPadding". If you dont specify the algorithm in parameter of the encryption/decryption builder, it will automatically pick the DEFAULT one. 

```java
    SafEncrypt.symmetricEncryption()
```

```java
    SafEncrypt.symmetricDecryption()
```


5. Enum class SymmetricAlgorithm contains a list of the algorithms that are supported currently by the library, provided that they are set as SECURE in the configuration file. 


6. When you dont want to use the DEFAULT algorithm for encryption/decryption purposes, please make sure to specify the correct ALGORITHM from the SymmetricAlgorithm class while creating the builder.

```java
    SafEncrypt.symmetricEncryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
```

```java
    SafEncrypt.symmetricDecryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
```

7. Only the Algorithms in SymmetricAlgorithm class are currently supported. The algorithms in SymmetricAlgorithm class must also be declared as secure in the applications.yml file when extending the library. 

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

2. When you get the plainText bytes[] back after the Decryption process, similarly it should be DECODED to get back the correct plain text. 

```java
    new String(plainTextBytes[] , StandardCharsets.UTF_8);
```


## Configurations [Skip if you dont want to update the DEFAULT configurations]

SafEncrypt is developed configurable, the provides the user ease of Safe Defaults using Safe Defaults.

1. Password Based Key Generation [Symmetric_PBEKEY_Config.json]

```java
{
  "algorithms": [
    "PBKDF2WithHmacSHA256",
    "PBKDF2WithHmacSHA512"
  ],
  "salt-bytes": 64,
  "iterations": 1024
}
```

This file contains the list of algorithms currently supported by SafEncrypt and their associated attributes for Password Based Key Generation. SafEncrypt will use these values by DEFAULT. 

2. Symmetric Encryption [Symmetric_Algorithms_Config.json]

```java
{
  "symmetric-algorithms": [
    "AES_CBC_128_PKCS5Padding",
    "AES_CBC_192_PKCS5Padding",
    "AES_CBC_256_PKCS5Padding",
    "AES_CBC_128_PKCS7Padding",
    "AES_CBC_192_PKCS7Padding",
    "AES_CBC_256_PKCS7Padding",
    "AES_GCM_128_NoPadding",
    "AES_GCM_192_NoPadding",
    "AES_GCM_256_NoPadding"
  ],
  "constraints": {
    "AES_CBC": {
      "iv-bytes": 16
    },
    "AES_GCM": {
      "iv-bytes": 12,
      "tag-bits": 96
    }
  }
}
```

This file contains the list of algorithms currently supported by SafEncrypt and their associated constraints for Symmetric Encryption. SafEncrypt will use these values by DEFAULT. The algorithms defined here works in conjunction with the ENUMS in SymmetricAlgorithm class. Any new ENUM for algorithm added in SymmetricAlgorithm class has to be whitelist here in the configuration file as well. 

3. Interoperable Symmetric Encryption [Symmetric_Interoperability_Config.json]

```java
{
  "interoperable-languages": {
    "Python": {
      "library-Provider": "Crypto",
      "symmetric": {
        "default-algo": "AES_CBC_256_PKCS7Padding",
        "iv-bytes": 16
      }
    },
    "CSharp": {
      "library-Provider": "Microsoft",
      "symmetric": {
        "default-algo": "AES_CBC_128_PKCS7Padding",
        "iv-bytes": 16
      }
    },
    "Sample_JavaScript": {
      "library-Provider": "New Library",
      "symmetric": {
        "default-algo": "AES_GCM_256_NoPadding",
        "iv-bytes": 12,
        "tag-bits": 96
      }
    }
  }
}
```

This file contains the list of algorithms currently supported by SafEncrypt w.r.t. Interoperability, and their associated constraints for Interoperable Symmetric Encryption. SafEncrypt will use the values associated for each language from this config class when performing Interoperable Symmetric Encryption. Any new Language added here must also be defined as an ENUM in SymmetricInteroperabilityLanguages class. 

4. Interoperable Symmetric Encryption Keystore [Symmetric_Keystore_Config.json]

```java
{
  "filePath": "keystore.jceks",
  "password": "changeit"
}
```
This file contains the kyestore configuration that is used for Interoperable Symmetric Encryption. filePath is the path where the user want to have the keystore created OR the path where the keystore exists. Password is the keystore password and well as each of the entry is keystore is protected with this password. When doing Interoperable Symmetric Encryption, SafEncrypt will save the keys in this keystore and return the key alias to the user which will be required to fetch the key in future during decryption process in another language. 
## Usage Examples [Symmetric Key Generation]

1. You want SafEncrypt to generate a secure random symmetric key and use it for encryption purpose? 
The generateKey() method doesn't require any parameter, and it automatically picks the algorithm set for the 'symmetricEncryption'.
If the algorithm isn't defined, then it chooses the default algorithm and generates a 128-bit key for AES.

```java
SymmetricCipher symmetricCipher =
                SafEncrypt.symmetricEncryption()
                        .generateKey()
                        .plaintext(plainText)
                        .encrypt();
```

Respectively, in this case below, it automatically picks the algorithm and generates a AES 256-bit key  

```java
SymmetricCipher symmetricCipher =
                SafEncrypt.symmetricEncryption(SymmetricAlgorithm.AES_GCM_256_NoPadding)
                        .generateKey()
                        .plaintext(plainText)
                        .encrypt();
```

3. You want to provide safEncrypt a password to generate the key? The wrapper support a default method for password based key generate as per the algorithm PBKDF2WithHmacSHA256. The usage is as follows:

```java
SymmetricCipher symmetricCipher =
                SafEncrypt.symmetricEncryption(SymmetricAlgorithm.AES_GCM_192_NoPadding)
                        .generateKeyFromPassword("strongPassword".toCharArray())
                        .plaintext(plainText)
                        .encrypt();
```

4. You want to provide safEncrypt a password to generate the key specify a key derivation algorithm as well? The wrapper supports two algorithm [PBKDF2WithHmacSHA256, PBKDF2WithHmacSHA512] currently for password based key generation. The algorithm can be specified as below:

```java
SymmetricCipher symmetricCipher =
                SafEncrypt.symmetricEncryption(SymmetricAlgorithm.AES_GCM_192_NoPadding)
                        .generateKeyFromPassword("strongPassword".toCharArray(), KeyAlgorithm.PBKDF2_With_Hmac_SHA512)
                        .plaintext(plainText)
                        .encrypt();
```


## Usage Examples [Symmetric Encryption/Decryption]

1. You want to encrypt/decrypt the data using the Safe Defaults from the library without worrying about the Safe Algorithm, Key?

```java
        byte[] plainText = "Hello World".getBytes(StandardCharsets.UTF_8);

        SymmetricCipher symmetricCipher =
                SafEncrypt.symmetricEncryption()
                        .generateKey()
                        .plaintext(plainText)
                        .encrypt();

        byte[] decryptedText =
                SafEncrypt.symmetricDecryption()
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext())
                        .decrypt();
```

2. You want to encrypt/decrypt the data using the Safe Default Algorithm from the library, but you want to use password based key deviation ?

```java
        byte[] plainText = "Hello World 121@#".getBytes(StandardCharsets.UTF_8);

        SymmetricCipher symmetricCipher =
                SafEncrypt.symmetricEncryption()
                        .generateKeyFromPassword("strongPassword".toCharArray())
                        .plaintext(plainText)
                        .encrypt();

        byte[] decryptedText =
                SafEncrypt.symmetricDecryption()
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext())
                        .decrypt();
```


3. You want to encrypt/decrypt the data providing a specific Algorithm from the library, but you want to use the key generated by the library ?

```java
        byte[] plainText = "1232F #$$^%$^ Hello World".getBytes(StandardCharsets.UTF_8);

        SymmetricCipher symmetricCipher =
                SafEncrypt.symmetricEncryption(SymmetricAlgorithm.AES_GCM_256_NoPadding)
                        .generateKey()
                        .plaintext(plainText)
                        .encrypt();

        byte[] decryptedText =
                SafEncrypt.symmetricDecryption(symmetricCipher.symmetricAlgorithm())
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext())
                        .decrypt();
```


4. You want to encrypt/decrypt the data using AES_GCM and also want to specify the Associated Data ?

```java
        byte[] plainText = "Hello World JCA WRAPPER Using GCM With AEAD".getBytes(StandardCharsets.UTF_8);
        byte[] associatedData = "I am associated data".getBytes(StandardCharsets.UTF_8);

        SymmetricCipher symmetricCipher =
                SafEncrypt.symmetricEncryption(SymmetricAlgorithm.AES_GCM_128_NoPadding)
                        .generateKey()
                        .plaintext(plainText, associatedData)
                        .encrypt();

        byte[] decryptedText =
                SafEncrypt.symmetricDecryption(symmetricCipher.symmetricAlgorithm())
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext(), associatedData)
                        .decrypt();
```

5. You want to encrypt/decrypt the data using AES_CBC algorithm ?

```java
        byte[] plainText = "TESTING CBC 128 With PKCS5 PADDING".getBytes(StandardCharsets.UTF_8);

        SymmetricCipher symmetricCipher =
                SafEncrypt.symmetricEncryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
                        .generateKey()
                        .plaintext(plainText)
                        .encrypt();
        
        byte[] decryptedText =
                SafEncrypt.symmetricDecryption(SymmetricAlgorithm.AES_CBC_128_PKCS5Padding)
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.ciphertext())
                        .decrypt();
```

## Usage Examples [Streaming Symmetric Encryption/Decryption]

1. You want to encrypt/decrypt the data in FILE using the Safe Defaults from the library?

```java
        SymmetricStreamingCipher symmetricStreamingCipher =
                SafEncrypt.symmetricEncryption()
                        .generateKey()
                        .plainFileStream(new File(resources_path + "input/plainTextFile.txt"), new File(resources_path + "output/cipherTextFile.txt"))
                        .encrypt();


        SafEncrypt.symmetricDecryption()
                .key(symmetricStreamingCipher.key())
                .iv(symmetricStreamingCipher.iv())
                .cipherFileStream(new File(resources_path + "output/cipherTextFile.txt"), new File(resources_path + "output/plainTextDecFile.txt"))
                .decrypt();
```

2. You want to encrypt/decrypt an image in FILE using the AES_CBC algorithm?

```java
        SymmetricStreamingCipher symmetricStreamingCipher =
                SafEncrypt.symmetricEncryption(SymmetricAlgorithm.AES_CBC_256_PKCS5Padding)
                        .generateKey()
                        .plainFileStream(new File(resources_path + "input/dummy_image.png"), new File(resources_path + "output/cipherImage.png"))
                        .encrypt();


        SafEncrypt.symmetricDecryption(SymmetricAlgorithm.AES_CBC_256_PKCS5Padding)
                .key(symmetricStreamingCipher.key())
                .iv(symmetricStreamingCipher.iv())
                .cipherFileStream(new File(resources_path + "output/cipherImage.png"), new File(resources_path + "output/dummy_image_dec.png"))
                .decrypt();
```


3. You want to encrypt/decrypt the data in FILE using Password Based Key Generation ?

```java
        SymmetricStreamingCipher symmetricStreamingCipher =
                SafEncrypt.symmetricEncryption(SymmetricAlgorithm.AES_GCM_192_NoPadding)
                        .generateKeyFromPassword("filePassword".toCharArray())
                        .plainFileStream(new File(resources_path + "input/plainTextFile.txt"), new File(resources_path + "output/plainTextEncFile.txt"))
                        .encrypt();


        SafEncrypt.symmetricDecryption(SymmetricAlgorithm.AES_GCM_192_NoPadding)
                .key(symmetricStreamingCipher.key())
                .iv(symmetricStreamingCipher.iv())
                .cipherFileStream(new File(resources_path + "output/plainTextEncFile.txt"), new File(resources_path + "output/plainTextDecFile.txt"))
                .decrypt();
```


## Interoperability

1. You want to do encryption, and then decrypt it later in Python ?

```java
        SymmetricCipherBase64 symmetricCipherBase64 = SafEncrypt.symmetricInteroperableEncryption(SymmetricInteroperabilityLanguages.Python)
                .plaintext(plainText)
                .encrypt();

```

2. You want to do encryption, and then decrypt it later in C# ?

```java
        SymmetricCipherBase64 symmetricCipherBase64 = SafEncrypt.symmetricInteroperableEncryption(SymmetricInteroperabilityLanguages.CSharp)
                .plaintext(plainText)
                .encrypt();
```

3. You want to do encryption, and then decrypt it later in JavaScript ?

```java
        SymmetricCipherBase64 symmetricCipherBase64 = SafEncrypt.symmetricInteroperableEncryption(SymmetricInteroperabilityLanguages.Sample_JavaScript)
                .plaintext(plainText)
                .optionalAssociatedData(associatedData)
                .encrypt();
```

3. You did encryption earlier for some a desired language, but later like to decrypt it using SafEncrypt in Java Only ?


```java
        byte[] plainText = "TU Clausthal Located in Clausthal Zellerfeld".getBytes(StandardCharsets.UTF_8);
        byte[] associatedData = "First test using AEAD".getBytes(StandardCharsets.UTF_8);

        SymmetricCipherBase64 symmetricCipherBase64 = SafEncrypt.symmetricInteroperableEncryption(SymmetricInteroperabilityLanguages.Sample_JavaScript)
                .plaintext(plainText)
                .optionalAssociatedData(associatedData)
                .encrypt();

        byte[] decryptedText = SafEncrypt.symmetricInteroperableDecryption(SymmetricInteroperabilityLanguages.Sample_JavaScript)
                .keyAlias(symmetricCipherBase64.keyAlias())
                .ivBase64(symmetricCipherBase64.iv())
                .cipherTextBase64(symmetricCipherBase64.cipherText())
                .optionalAssociatedData(associatedData)
                .decrypt();
```
            



## FAQs

There are a number of questions asked by users on StackOverflow pertaining to the usage of JCA. We will try to address them here in SafEncrypt's context.

1. What happens if I do not  specify the IV although it is required?	


    IV are a source to create randomness in the ciphertext. Algorithms such as AES in ECB mode doesn’t necessarily require the user to enter IV, which is the reason its declared as insecure because the same plaintext and key will always lead to the same ciphertext. Safecrypt allows two variants of AES, one is CBC and the other one is GCM. IV is mandatory for both the variants, however users dont need to worry about its creation. SafEncrypt will create secure IV during the encryption preocess and return it back to the user in order to be used further for decryption purposes. 
    
2. How can I derive a key from a password?


    In order to derive the key from a password, you just need to use the method ".generateKeyFromPassword("strongPassword".toCharArray())" and provide the password in bytes when using the SafEncrypt builder. SafEncrypt will generate the key from the user provided password and use it for encryption purposes. The default algorithm for password based key generation is "PBKDF2WithHmacSHA512". However, if you want to change the key derviation algorithm you can provide an Enum from the KeyAlgorithm class in the second paramater when specifying the password. 

3. What is the default value if I do not specify padding?


    In SafEncrypt AES_CBC supports (PKCS5 and PKCS7) and AES_GCM (NoPadding). The default algorithm is AES_GCM_128_NoPadding, where 128 is the key size. 

4. What kind of parameters do I have to pass to the decryption methods (update / doFinal)?	


    Using SafEncrypt you don’t have to worry about calling the update and final methods. The SafEncrypt builder will simply prompt to ask whats required for decryption (such as key, iv, ciphertext ..)

5. Which of the provided key derivation functions are standardized?	


    Besides the usual Key Generation from a secure random source, SafEncrypt supports Password based key derivation with two variants PBKDF2WithHmacSHA256 and PBKDF2WithHmacSHA512 [default]. 

6. Are there any external dependencies for the implementation of AES-256?	


    There are no external dependencies when using SafEncrypt. 

7. What parameters does a Cipher object require for initialization?	


    When using SafEncrypt you don’t have to worrry about initialization, parameters.  The SafEncrypt builder will simply prompt to ask whats required for encryption/decryption. 

8. When do I have to call update(), when do I have to call doFinal()?	


    When using SafEncrypt you don’t have to worrry about calling the update and doFinal methods.  The SafEncrypt builder will simply prompt to ask whats required for encryption/decryption and return the necessary data. 

9. Are Cipher objects thread safe?	


    Cipher objects are not threas safe, and its recommended to generate a new instance each time. SafEncrypt internally handles this is a safe and secure manner, therefore the users don’t need to worry about it. 

10. How to specify PKCS#7 padding in Java?	


    Using SafEncrypt, while encrption and decryption you can simply specify the algorithm as an Enum from the SymmetricAlgorithm class as a paramater. 

11. How to specify SecretKeySpec correctly?	


    You can simply use the SafEncrypt methods such as "SymmetricKeyGenerator.generateSymmetricKey()" to generate key securely or use the SafEncrypt builder method generateKey(). Besides, if you want to use SecretKeySpec you can simply use like below. 
    
    final SecretKeySpec secretKey = new SecretKeySpec("key".getBytes(), "AES");
    

12. How to correctly specify key derivation using PBKDF2?


    When using SafEncrypt you don’t have to worrry about interacting with PBKDF2 directly. In order to derive the key from a password, you just need to use the method ".generateKeyFromPassword("strongPassword".toCharArray())" and provide the password in bytes when using the SafEncrypt builder. SafEncrypt will generate the key from the user provided password and use it for encryption purposes. The default algorithm for password based key generation is "PBKDF2WithHmacSHA512". However, if you want to change the key derviation algorithm you can provide an Enum from the KeyAlgorithm class in the second paramater when specifying the password. 

13. How can I securely store a key after encryption?	


    There are multiple solutions to storing the key after encryption, such as using key management systems, or storing securely in a file systems etc. 

14. How can I restore the key for decryption?


    When using SafEncrypt, the builder will return all the required details for decryption such as (key, iv, cipherText ..) in an SymmetricCipher object after encryption process. 

15. What schemes are supported by platform X?


    SafEncrypt currently support Symmetric Encryption in CBC and GCM modes of operation inclusing key generation/derivation. 

16. What key derivation functions are available for platform X?


    SafEncrypt supports Key Generation from a secure random source for AES. Moreover, password based key derivation with two variants PBKDF2WithHmacSHA256 and PBKDF2WithHmacSHA512 [default] are also supported. 

17. What size is the authentication tag generated by AES-GCM encryption?	


    The default configuration for AES-GCM in SafEncrypt generates a tag size of 96 bits (12 bytes).

18. How do I specify my Cipher object to use DESede?


    SafEncrypt doesn’t support unsecure encryption scheme such as DES. 

19. How can I specify DESede with only 2 keys ( = 16B)?


    SafEncrypt doesn’t support unsecure encryption scheme such as DES. 

20. What kind of parameters does a Cipher object require for encryption?	


    When using SafEncrypt you don’t have to worrry about interaction with Cipher object. The SafEncrypt builder will simply prompt to ask whats required for encryption/decryption. 

21. How can I derive the key for decryption in the same way as for encryption?	


    You have to save the key returned in an SymmetricCipher object when encrypting using SafEncrypt. There's no way to derive the same key again that was used for encryption.  

22. How can I store or transmit the IV?	


    You can store the IV in the same place as the ciphertext. IV's iteself aren't secret but its just that they shouldn't be re-used to avoid prediction of plaintext. 

23. What are the default values for platform X?	


    The default algorithm for encryption/decryption in SafEncrypt is AES_GCM_128_NoPadding. The default for secure symmetric key generation is 16 bytes AES key. The default for password based key generation is PBKDF2WithHmacSHA512. 

24. How can I encrypt large amount of data?	


    If your large amount lf data is present inside a file, you can use SafEncrypt streaming encryption to easily encrypt/decrypt data. 

25. How is password based encryption implemented in JCA?


    When using SafEncrypt you don’t have to worrry about interacting with PBKDF2 directly. In order to derive the key from a password, you just need to use the method ".generateKeyFromPassword("strongPassword".toCharArray())" and provide the password in bytes when using the SafEncrypt builder. SafEncrypt will generate the key from the user provided password and use it for encryption purposes. The default algorithm for password based key generation is "PBKDF2WithHmacSHA512". However, if you want to change the key derviation algorithm you can provide an Enum from the KeyAlgorithm class in the second paramater when specifying the password. 

26. What size is the output generated by AES-GCM encryption?


    As the AES-GCM uses NoPadding, the resultant size of the ciphertext is [The size of plaintext + TagSize]. Default Tag Size for AES-GCM is 96 bits (12 bytes) in SafEncrypt. 

27. What is the difference between TripleDES and DESede?


    SafEncrypt doesn’t support unsecure encryption scheme such as DES. 
    
28. What is the default value if I do not specify the encryption mode?	

    
    SafEncrpyt promotes the usage of algorithms in a safe manner. You can use AES either in CBC or in GCM mode. 

29. How can I generate a random key?


    SafEncrypt supports Key Generation from a secure random source for AES. You can simply use the SafEncrypt methods such as "SymmetricKeyGenerator.generateSymmetricKey()" to generate key securely. Optionally you can also specify the algorithm from the SymmetricAlgorithm class as a paramater for which you want to use the key. If you are using the SafEncrypt builder method generateKey(), it will automatically generate the key as per the respective encryption algorithm selected for encryption.

30. How can I specify PBEKeySpec correctly?	


    When using SafEncrypt you don’t have to worrry about interacting with PBEKeySpec directly. In order to derive the key from a password, you just need to use the method ".generateKeyFromPassword("strongPassword".toCharArray())" and provide the password in bytes when using the SafEncrypt builder. SafEncrypt will generate the key from the user provided password and use it for encryption purposes. The default algorithm for password based key generation is "PBKDF2WithHmacSHA512". However, if you want to change the key derviation algorithm you can provide an Enum from the KeyAlgorithm class in the second paramater when specifying the password. 

31. How can I specify DESedeKeySpec correctly?	


    SafEncrypt doesn’t support unsecure encryption scheme such as DES. 

32. How can I generate an IV?	


    When using SafEncrypt you don’t have to worrry about IV generation. SafEncrypt generate a secure random IV itself as per the algorithm requirements. SafEncrypt builder will return all the required details for decryption such as (key, iv, cipherText ..) in an SymmetricCipher object after encryption process. 

33. How can I properly set up a Cipher object and ask it for encryption?	


    When using SafEncrypt you don’t have to worrry about interaction with Cipher object. The SafEncrypt builder simply prompts to ask from the user whats required for encryption/decryption. 

34. How can I encrypt several items in a row?


    Convert each item in byte array representation ( byte[] ) and use SafEncryt builder to encrypt each of them. 

35. What is the data type of a key?	


    The data type for key is byte[] when using SafEncrypt. 

36. Is the IV appended to cipher text after encryption?	


    No, SafEncrypt doesn’t append the Ciphertext and IV together after encryption. SafEncrypt builder will return all the required details separately for decryption such as (key, iv, cipherText ..) in an SymmetricCipher object after encryption process. 

37. How is the authentication data concatenated to cipher text after encryption?	


    Authentication Data (Authentication Tag) is a fixed size data generated during encryption and appended to the end of the ciphertext. It’s basically the hash of plaintext and the associated data (optional) that is used for integrity and authentication purposes at the time of decryption. The resultant size of the ciphertext in AES_GCM is [The size of plaintext + TagSize]. Default Tag Size for AES-GCM is 96 bits (12 bytes) in SafEncrypt. 

38. What is the output of update()?	


    The update() method is used for streaming encryption and the output depends on the AES mode of operation. For e.g. AES-CBC will return the ecnrypted/decrypted text when calling the update() method, while AES-GCM doesn’t return anything. Streaming encryption is supported in SafEncrypt. 

39. Can I speed up Cipher.getInstance()?


    While using SafEncrypt, there's no need to interact directly with the Cipher object. 

40. What classes for AlgorithmParameterSpec should be used on platform X?	


    While using SafEncrypt, there's no need to interact directly with the AlgorithmParameterSpec. Use the SafEncrypt builder to encrypt/decrypt the data and it will handle everything required for you in cases of AES-CBC and AES-GCM. 

41. How can I test encryption?	


    In order to test encryption, you can first use SafEncrypt builder to encrypted some plaintext. Secondly, you can use the SafEncrypt builder to decrypted the ciphertext providing the key and iv returned after encryption process. And finally compare the decrypted result and the orignal plaintext if they match. 

42. What does "BadPaddingException: unknown block type" mean?


    This exception can possibly occur during decryption due to tampered ciphertext. 

43. How can I specify a Cipher object such that it does not apply padding?


    Using SafEncrpyt you can use AES-CBC with PKCS5 or PKCS7 padding, while AES-GCM uses NoPadding. AES-CBC requires the plaintext to be multiple of 16 bytes so its mandatory to apply padding if it doesn’t meet the AES block size requirement.   