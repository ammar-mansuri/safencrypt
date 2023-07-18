package com.safEncrypt;


import com.safEncrypt.builder.SafEncrypt;
import com.safEncrypt.enums.SymmetricAlgorithm;
import com.safEncrypt.enums.SymmetricInteroperabilityLanguages;
import com.safEncrypt.models.SymmetricCipher;

import java.io.*;

public class Main {
    public static void main(String[] args) {

        SymmetricCipher symmetricCipher;

        try (InputStream inputStream = new FileInputStream("plaintext.txt")) {

            try (OutputStream outputStream = new FileOutputStream("encrypted.txt")) {

                symmetricCipher = SafEncrypt.symmetricEncryption()
                        .generateKey()
                        .streamingPlaintext(inputStream, outputStream)
                        .encrypt();
            }

        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }


        try (InputStream inputStream = new FileInputStream("encrypted.txt")) {

            try (OutputStream outputStream = new FileOutputStream("decrypted.txt")) {

                SafEncrypt.symmetricDecryption()
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .streamingCipherText(inputStream, outputStream)
                        .decrypt();
            }

        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }



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