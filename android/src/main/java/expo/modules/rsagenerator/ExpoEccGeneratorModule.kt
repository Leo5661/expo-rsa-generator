package expo.modules.eccgenerator

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import expo.modules.kotlin.Promise
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.security.KeyPairGenerator
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom
import javax.crypto.SecretKey
import java.security.PublicKey
import java.security.PrivateKey

class ExpoEccGeneratorModule : Module() {

    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    override fun definition() = ModuleDefinition {
        Name("ExpoEccGenerator")

        AsyncFunction("generateKeyPair") { keyAlias: String, promise: Promise ->
           try {
        if (!keyStore.containsAlias(keyAlias)) {
            val keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY or
                        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_AGREE_KEY // Add PURPOSE_AGREE_KEY
            )
                .setKeySize(256)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .build()

            keyPairGenerator.initialize(keyGenParameterSpec)
            val keyPair = keyPairGenerator.generateKeyPair()

            val publicKeyBytes = keyPair.public.encoded
            val publicKeyBase64 = Base64.encodeToString(publicKeyBytes, Base64.DEFAULT)

            promise.resolve(publicKeyBase64)
        } else {
            val publicKey = keyStore.getCertificate(keyAlias).publicKey.encoded
            val publicKeyBase64 = Base64.encodeToString(publicKey, Base64.DEFAULT)
            promise.resolve(publicKeyBase64)
        }

    } catch (e: Exception) {
        Log.e(TAG, "ECC Key Generation failed: ${e.message}", e)
        e.printStackTrace()
        promise.reject("ECC_KEY_GEN_ERROR", "ECC Key Generation failed: ${e.message}", e)
    }
        }

        AsyncFunction("encrypt") { keyAlias: String, data: String, promise: Promise ->
            try {
                val publicKeyBytes = keyStore.getCertificate(keyAlias).publicKey.encoded
                val publicKey = java.security.KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC).generatePublic(java.security.spec.X509EncodedKeySpec(publicKeyBytes))

                val sharedSecret = generateSharedSecret(keyAlias, publicKey)

                val encryptedData = encryptAesGcm(data.toByteArray(Charsets.UTF_8), sharedSecret)
                val encryptedBase64 = Base64.encodeToString(encryptedData, Base64.DEFAULT)
                promise.resolve(encryptedBase64)

            } catch (e: Exception) {
                Log.e(TAG, "ECC Encryption failed: ${e.message}", e)
                e.printStackTrace()
                promise.reject("ECC_ENCRYPT_ERROR", "ECC Encryption failed: ${e.message}", e)
            }
        }

        AsyncFunction("decrypt") { keyAlias: String, encryptedBase64: String, promise: Promise ->
            try {
                val encryptedBytes = Base64.decode(encryptedBase64, Base64.DEFAULT)

                val privateKey = keyStore.getKey(keyAlias, null) as PrivateKey
                val publicKeyBytes = keyStore.getCertificate(keyAlias).publicKey.encoded
                val publicKey = java.security.KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC).generatePublic(java.security.spec.X509EncodedKeySpec(publicKeyBytes))

                val sharedSecret = generateSharedSecret(keyAlias, publicKey)

                val decryptedData = decryptAesGcm(encryptedBytes, sharedSecret)
                val decryptedString = String(decryptedData, Charsets.UTF_8)
                promise.resolve(decryptedString)

            } catch (e: Exception) {
                Log.e(TAG, "ECC Decryption failed: ${e.message}", e)
                e.printStackTrace()
                promise.reject("ECC_DECRYPT_ERROR", "ECC Decryption failed: ${e.message}", e)
            }
        }
    }

    private fun generateSharedSecret(alias: String, otherPublicKey: PublicKey): SecretKey {
        val keyAgreement = KeyAgreement.getInstance("ECDH")
        val privateKey = keyStore.getKey(alias, null) as PrivateKey
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(otherPublicKey, true)
        val secretBytes = keyAgreement.generateSecret()
        return SecretKeySpec(secretBytes, "AES")
    }

    private fun encryptAesGcm(data: ByteArray, secretKey: SecretKey): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val iv = ByteArray(12)
        SecureRandom().nextBytes(iv)
        val parameterSpec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec)
        val encryptedData = cipher.doFinal(data)
        return iv + encryptedData
    }

    private fun decryptAesGcm(encryptedData: ByteArray, secretKey: SecretKey): ByteArray {
        val iv = encryptedData.copyOfRange(0, 12)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val parameterSpec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec)
        return cipher.doFinal(encryptedData.copyOfRange(12, encryptedData.size))
    }

    companion object {
        private const val TAG = "ExpoEccGenerator"
    }
}