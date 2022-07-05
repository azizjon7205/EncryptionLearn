package com.example.encryptionlearn

import android.os.Build
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import androidx.annotation.RequiresApi
import com.example.encryptionlearn.utils.Asymmetric
import com.example.encryptionlearn.utils.Asymmetric.Companion.decryptMessage
import com.example.encryptionlearn.utils.Asymmetric.Companion.encryptMessage
import com.example.encryptionlearn.utils.MyKeyStore
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.util.*

class MainActivity : AppCompatActivity() {

    val privateServerKey = "MIIEoAIBADANBgkqhkiG9w0BAQEFAASCBIowggSGAgEAAoH8Nx/GJcFfILU7+Z8+zZ0YwIwTcVGjlopixDJkKdyYdTWyV+TPClNU00LPmOnOnv850YwRFHLd+LYL7bejdEKcOEgDlMhjEYfaUaPU6lK6lgwv7wg7GDPsW2IqSdCVoyBHBfBYmk1U5UU5kHrRi5hKX9hpZ73RQvGIvxsdEDCeF6cLPy7mDjN1VIaeJmrv9lbBM+8PplkarRgZv38FW4lzTkUFEBk7Go6YEZZ+v6peWAgXAErCaora6bTK3juZvqM8aErj2yjWG5pMj0itMsDbHpGqmKYoAuO+8hWFOnscLAtc1HQWpD5h1r5ZvCDwcyu4cqzgdNLaMotESeZVAgMBAAECgfwODTlzcmGPcuOA9EkMHNmsa4ihQFBVFZ2rqbTCvwrWBgQaR6dHWIqs98D3l9Il0aWpduz7q3RN7AoKZN9zyW8NIb5X9OTcGSdb3ElwGfqaOS0W36BAwSuk99cTzen3FUlFiEjtvHzBnO3ZmJVF4mJDIGVuHoLzb6KOJJk6AUpu53U9Nsvg2kkGCrDrKrUkkTx19KU0YoADloyoyP9xO/zPBJRlN7cJGt4Ajjg+lDQyO6QuFqwR3yWPMgRd1mezdMS3WAWdPKvGuD2ZeCS89YUlTgrtLdtXhlizId+TGEWZoHxOqRTHzg/O1t0lwAbmwGDwBR23PL3fuNpxAIECfnhUKf+kvJ57DjupzA1cbs6T0qhJ0ZTZeIaDDYloJ6EeLCPDKKYbH19E3wmsJj5gtSUprCrP2JoQZt7fUUFwBR6q/H32m4QVzDKfuWF5cuM9BAbdFW/PUJkRU6m3J6ZMhZBGsgkfzG+iB85wE5EwOocX7oPw5D2pp3CruQCWEQJ+dUbdIZDTiU8B3OOzouKNDscdYzRJurV5qe3z6volUU5oQAgDzKVRccQFSopAxYCpYDrYKIWy6oKdQhkfBStckonyMO4ehHWOMdvUleSWBa5JHrScGQsuAKTXsQWJqn7vlIi4qPuK81F8QIiwUmV/uaRrgD+m0113VvaG/3gFAn5PsQ4PrX7uRvlqMk5eGvWYAvblVd5kApN8Ipd4hW6Zmm4JUVs+h4ADjI1azpSVg171OeA4imcdwfcfbC9Yc2Qwp3WJxyXAGN+gN4CDOfgI34QnN4zW/CqY9Yy/PfoYfV2H7ApFWLYAyQL6ieerpJFen07sO0IuRIoMaO6hoMECfhuWJ74ViyzpYM7M4RyXngaz373ONumsdon6Zz4GyXBuuScWu44P9TCFo5j9HG9Y7H6uWNpvWL7BKqy5rApTQNtXh5jq6lLONDyWMVNxCbkcXibS5UUe1BtiqzoAy3lHkqOl5YoaYX0K1ed4P8GiDoFko8TvNBbUDZZvNyIw4QJ+YOoqxQPsluOZNxdY4GmZKEQCAwec+dcESq3G1CYb5P+ebmg5zjau+GtLHrlkVL8xQuV2NNkUGS6cfwOkOUcu3p6I1Qdyq4P80tfe1HNARwyPhQ4I846Z8hprbxX2ku8sZRWUGghSaA0UxQn9QOToCyST0BJdCihsmiHZT1kO"
    val publicMobileKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7SrR7pvsp1rMDVn4R9XjZp4q6IVSit9XAKvAMgTIml7vAp2H81RA9V4jDyrFlASrvxq0uGi5W/bZj+AdYGu1ceTDeLK8OvH90GyKXaPiHjuPAeRCGyTBkn+7nogVxqpmrGVGUJfcslr4JawU/9Vou7LjdraNStCnldRJzKvcY+wIDAQAB"

    @RequiresApi(Build.VERSION_CODES.O)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        MyKeyStore.storeKeys()
        testAsymmetric()

    }

    @RequiresApi(Build.VERSION_CODES.O)
    private fun testAsymmetric() {

        val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        val alias = "key11"
        // Retrieve the keys
        val privateKeyEntry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
        val privateKey: PrivateKey = privateKeyEntry.privateKey
        val publicKey: PublicKey = privateKeyEntry.certificate.publicKey

        val secretText = "Best mobile team"

        Log.d("@@@", "Private Key: ${privateKey.toString()}")
        Log.d("@@@", "Public Key: ${publicKey.toString()}")


        // Encrypt secret text using public key
        val encryptedValue = MyKeyStore.encryptString(secretText, alias, keyStore)
        Log.d("@@@", "Encrypted Value: $encryptedValue")
        // Decrypt
        val decryptedText = MyKeyStore.decrypt(encryptedValue, keyStore, alias)
        Log.d("@@@", "Decrypted output: $decryptedText")

    }
}