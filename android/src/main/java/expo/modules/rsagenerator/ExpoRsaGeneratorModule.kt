package expo.modules.rsagenerator

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

class ExpoRsaGeneratorModule : Module() {

    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    override fun definition() = ModuleDefinition {
        Name("ExpoRsaGenerator")

        AsyncFunction("generateRSAKeyPair") { keyAlias: String, promise: Promise ->
            try {
                if (!keyStore.containsAlias(keyAlias)) {
                    val keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
                    val parameterSpec = KeyGenParameterSpec.Builder(
                        keyAlias,
                        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                    )
                        .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                        .build()

                    keyPairGenerator.initialize(parameterSpec)
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
                Log.e(TAG, "RSA Key Generation failed", e)
                promise.reject("RSA_KEY_GEN_ERROR", "RSA Key Generation failed: ${e.message}", e)
            }
        }

        AsyncFunction("encryptRSA") { keyAlias: String, data: String, promise: Promise ->
            try {
                val publicKey = keyStore.getCertificate(keyAlias).publicKey
                val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
                cipher.init(Cipher.ENCRYPT_MODE, publicKey)
                val encryptedBytes = cipher.doFinal(data.toByteArray())
                val encryptedBase64 = Base64.encodeToString(encryptedBytes, Base64.DEFAULT)
                promise.resolve(encryptedBase64)
            } catch (e: Exception) {
                Log.e(TAG, "RSA Encryption failed", e)
                promise.reject("RSA_ENCRYPT_ERROR", "RSA Encryption failed: ${e.message}", e)
            }
        }

        AsyncFunction("decryptRSA") { keyAlias: String, encryptedBase64: String, promise: Promise ->
            try {
                val privateKey = keyStore.getKey(keyAlias, null)
                val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
                cipher.init(Cipher.DECRYPT_MODE, privateKey)
                val encryptedBytes = Base64.decode(encryptedBase64, Base64.DEFAULT)
                val decryptedBytes = cipher.doFinal(encryptedBytes)
                val decryptedString = String(decryptedBytes)
                promise.resolve(decryptedString)
            } catch (e: Exception) {
                Log.e(TAG, "RSA Decryption failed", e)
                promise.reject("RSA_DECRYPT_ERROR", "RSA Decryption failed: ${e.message}", e)
            }
        }
    } 

    companion object {
        private const val TAG = "ExpoRsaGenerator"
    }
}