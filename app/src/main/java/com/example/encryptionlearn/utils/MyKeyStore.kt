package com.example.encryptionlearn.utils

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.annotation.RequiresApi
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.*
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.security.auth.x500.X500Principal


object MyKeyStore {

    val TAG = "KEY-UTIL"

    @RequiresApi(Build.VERSION_CODES.M)
    fun storeKeys() {
        val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        val alias = "key11"
        val nBefore = keyStore.size()

        // Create the keys if necessary
        if (!keyStore.containsAlias(alias)) {
            val notBefore: Calendar = Calendar.getInstance()
            val notAfter: Calendar = Calendar.getInstance()
            notAfter.add(Calendar.YEAR, 1)

            // *** Replaced deprecated KeyPairGeneratorSpec with KeyPairGenerator
            val spec: KeyPairGenerator =
                KeyPairGenerator.getInstance( // *** Specified algorithm here
                    // *** Specified: Purpose of key here
                    KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore"
                )
            spec.initialize(
                KeyGenParameterSpec.Builder(
                    alias, KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_ENCRYPT
                )
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1) //  RSA/ECB/PKCS1Padding
                    .setKeySize(2048) // *** Replaced: setStartDate
                    .setKeyValidityStart(notBefore.getTime()) // *** Replaced: setEndDate
                    .setKeyValidityEnd(notAfter.getTime()) // *** Replaced: setSubject
                    .setCertificateSubject(X500Principal("CN=test")) // *** Replaced: setSerialNumber
                    .setCertificateSerialNumber(BigInteger.ONE)
                    .build()
            )
            val keyPair: KeyPair = spec.generateKeyPair()
            Log.i(TAG, keyPair.toString())
        }

        val nAfter = keyStore.size()
        Log.v(TAG, "Before = $nBefore After = $nAfter")

        // Retrieve the keys
        val privateKeyEntry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
        val privateKey: PrivateKey = privateKeyEntry.privateKey
        val publicKey: PublicKey = privateKeyEntry.certificate.publicKey

        Log.v(TAG, "private key = " + privateKey.toString())
        Log.v(TAG, "public key = " + publicKey.toString())

    }

    fun encryptString(secretText: String, alias: String?, keyStore: KeyStore): String {
        val privateKeyEntry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
        val publicKey = privateKeyEntry.certificate.publicKey

        // Encrypt the text
        val initialText: String = secretText

        val input: Cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL")
        input.init(Cipher.ENCRYPT_MODE, publicKey)
        val outputStream = ByteArrayOutputStream()
        val cipherOutputStream = CipherOutputStream(
            outputStream, input
        )
        cipherOutputStream.write(initialText.toByteArray(charset("UTF-8")))
        cipherOutputStream.close()
        val vals: ByteArray = outputStream.toByteArray()
        return Base64.encodeToString(vals, Base64.DEFAULT)

    }

    fun decrypt(encryptedText: String, keyStore: KeyStore, alias: String?): String{
        val privateKeyEntry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
        val privateKey = privateKeyEntry.privateKey as Key

        val output = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL")
        output.init(Cipher.DECRYPT_MODE, privateKey)

        val cipherText: String = encryptedText
        val cipherInputStream = CipherInputStream(
            ByteArrayInputStream(Base64.decode(cipherText, Base64.DEFAULT)), output
        )
        val values: ArrayList<Byte> = ArrayList()
        var nextByte: Int
        while (cipherInputStream.read().also { nextByte = it } != -1) {
            values.add(nextByte.toByte())
        }

        val bytes = ByteArray(values.size)
        for (i in bytes.indices) {
            bytes[i] = values[i]
        }

        val finalText = String(bytes, 0, bytes.size)
        return finalText
    }

}