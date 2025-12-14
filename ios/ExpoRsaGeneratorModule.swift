import Foundation
import Security
import ExpoModulesCore

public class ExpoRsaGeneratorModule: Module {
    public func definition() -> ModuleDefinition {
        Name("ExpoRsaGenerator")

        AsyncFunction("generateRSAKeyPair") { (keyAlias: String, promise: Promise) in
            self.generateRSAKeyPair(keyAlias: keyAlias, promise: promise)
        }

        AsyncFunction("encryptRSA") { (keyAlias: String, data: String, promise: Promise) in
            self.encryptRSA(keyAlias: keyAlias, data: data, promise: promise)
        }

        AsyncFunction("decryptRSA") { (keyAlias: String, encryptedBase64: String, promise: Promise) in
            self.decryptRSA(keyAlias: keyAlias, encryptedBase64: encryptedBase64, promise: promise)
        }
    }

    // New, fixed implementation for generating keys
    private func generateRSAKeyPair(keyAlias: String, promise: Promise) {
        do {
            // Explicitly delete both Public and Private keys to ensure cleanup
            let deleteQueryPrivate: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrLabel as String: keyAlias,
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate
            ]
            let statusPriv = SecItemDelete(deleteQueryPrivate as CFDictionary)
            
            let deleteQueryPublic: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrLabel as String: keyAlias,
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass as String: kSecAttrKeyClassPublic
            ]
            let statusPub = SecItemDelete(deleteQueryPublic as CFDictionary)
            
            print("Deleted old RSA keys for alias '\(keyAlias)': Private=\(statusPriv), Public=\(statusPub)")

            let attributes: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrKeySizeInBits as String: 2048,
                kSecPrivateKeyAttrs as String: [
                    kSecAttrIsPermanent as String: true,
                    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                    kSecAttrLabel as String: keyAlias
                ],
                kSecPublicKeyAttrs as String: [
                    kSecAttrIsPermanent as String: true,
                    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                    kSecAttrLabel as String: keyAlias
                ]
            ]

            var error: Unmanaged<CFError>?
            // Using the modern SecKeyCreateRandomKey API
            guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
                throw error!.takeRetainedValue() as Error
            }
            
            // Getting the public key from the private key
            guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
                throw NSError(domain: "ExpoRsaGeneratorModule", code: 0, userInfo: [NSLocalizedDescriptionKey: "Failed to get public key from private key."])
            }

            let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data?
            guard let publicKeyBase64 = publicKeyData?.base64EncodedString() else {
                throw error!.takeRetainedValue() as Error
            }

            promise.resolve(publicKeyBase64)
        } catch {
            // Fixing promise.reject to accept a String
            promise.reject("KEY_GENERATION_ERROR", error.localizedDescription)
        }
    }

    // Fixed implementation for encryption
    private func encryptRSA(keyAlias: String, data: String, promise: Promise) {
        do {
            // STRICTLY query for Public Key
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrLabel as String: keyAlias,
                kSecAttrKeyClass as String: kSecAttrKeyClassPublic, // Strict Class
                kSecReturnRef as String: true
            ]

            var item: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &item)

            // Using force unwrap as downcast will always succeed with errSecSuccess
            guard status == errSecSuccess, let publicKey = item as! SecKey? else {
                // Fallback: If Public key not found (maybe only Private saved?), try Private ref (it has public component)
                // BUT better to fail and force user to regenerate correctly.
                throw NSError(domain: "ExpoRsaGeneratorModule", code: 0, userInfo: [NSLocalizedDescriptionKey: "Public key not found for alias \(keyAlias)."])
            }
            
            // Using the correct SecKeyAlgorithm
            let algorithm: SecKeyAlgorithm = .rsaEncryptionPKCS1
            
            guard let encryptedData = SecKeyCreateEncryptedData(publicKey, algorithm, data.data(using: .utf8)! as CFData, nil) as Data? else {
                throw NSError(domain: "ExpoRsaGeneratorModule", code: 0, userInfo: [NSLocalizedDescriptionKey: "Encryption failed."])
            }

            let encryptedBase64 = encryptedData.base64EncodedString()
            promise.resolve(encryptedBase64)
        } catch {
            // Fixing promise.reject to accept a String
            promise.reject("ENCRYPTION_ERROR", error.localizedDescription)
        }
    }

    // Fixed implementation for decryption
    private func decryptRSA(keyAlias: String, encryptedBase64: String, promise: Promise) {
        do {
            // STRICTLY query for Private Key
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrLabel as String: keyAlias,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate, // Strict Class
                kSecReturnRef as String: true
            ]

            var item: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &item)

            // Using force unwrap as downcast will always succeed with errSecSuccess
            guard status == errSecSuccess, let privateKey = item as! SecKey? else {
                throw NSError(domain: "ExpoRsaGeneratorModule", code: 0, userInfo: [NSLocalizedDescriptionKey: "Private key not found for alias \(keyAlias)."])
            }

            // Using the correct SecKeyAlgorithm
            let algorithm: SecKeyAlgorithm = .rsaEncryptionPKCS1
            
            guard let encryptedData = Data(base64Encoded: encryptedBase64) else {
                throw NSError(domain: "ExpoRsaGeneratorModule", code: 0, userInfo: [NSLocalizedDescriptionKey: "Invalid base64 data."])
            }

            var error: Unmanaged<CFError>?
            guard let decryptedData = SecKeyCreateDecryptedData(privateKey, algorithm, encryptedData as CFData, &error) as Data? else {
                let errorDesc = error?.takeRetainedValue().localizedDescription ?? "Unknown"
                 throw NSError(domain: "ExpoRsaGeneratorModule", code: 0, userInfo: [NSLocalizedDescriptionKey: "Decryption failed: \(errorDesc)"])
            }

            guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
                throw NSError(domain: "ExpoRsaGeneratorModule", code: 0, userInfo: [NSLocalizedDescriptionKey: "Decrypted data is not valid UTF-8."])
            }

            promise.resolve(decryptedString)
        } catch {
            // Fixing promise.reject to accept a String
            promise.reject("DECRYPTION_ERROR", error.localizedDescription)
        }
    }

}