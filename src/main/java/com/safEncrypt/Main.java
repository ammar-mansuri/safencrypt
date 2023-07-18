package com.safEncrypt;


import com.safEncrypt.builder.SafEncrypt;
import com.safEncrypt.enums.SymmetricAlgorithm;
import com.safEncrypt.enums.SymmetricInteroperabilityLanguages;
import com.safEncrypt.models.SymmetricCipher;
import com.safEncrypt.models.SymmetricStreamingCipher;

import java.io.*;

public class Main {
    public static void main(String[] args) {
        SymmetricStreamingCipher symmetricStreamingCipher = SafEncrypt.symmetricEncryption()
                .generateKey()
                .streamingPlaintext(new File("plaintext.txt"), new File("encrypted.txt")).encrypt();

        SafEncrypt.symmetricDecryption()
                .key(symmetricStreamingCipher.key())
                .iv(symmetricStreamingCipher.iv())
                .streamingCipherText(new File("encrypted.txt"), new File("decrypted.txt"))
                .decrypt();



       /* SafEncrypt.symmetricInteroperableEncryption(SymmetricInteroperabilityLanguages.Python)
                .plaintext("ds".getBytes())
                .optionalAssociatedData(null)
                .encrypt();

        SafEncrypt.symmetricInteroperableDecryption(SymmetricInteroperabilityLanguages.Python)
                .keyAlias("sds")
                .ivBase64("ddfadad")
                .cipherTextBase64("sddas");
*/
        /*Cipher xx = SafeEncrypt.SymmetricEncryption()
                .loadKey("dsadasdsa".getBytes())
                .plaintext("adads".getBytes())
                .encrypt();*/


//        SafEncrypt.createEncryptionBuilder();
//        SymmetricInteroperableBuilder.createEncryptionBuilder()

       /*

        SymmetricCipherBase64 symmetricCipherBase64 = SafEncrypt.interoperableEncryption(SymmetricInteroperabilityLanguages.CSharp)
                .plaintext("DAsad".getBytes())
                .encrypt();

        SafEncrypt.interoperableDecryption(SymmetricInteroperabilityLanguages.CSharp)
                .keyAlias(symmetricCipherBase64.keyAlias())
                .ivBase64(symmetricCipherBase64.iv())
                .cipherTextBase64(symmetricCipherBase64.cipherText())
                .decrypt();

                */

    }
}