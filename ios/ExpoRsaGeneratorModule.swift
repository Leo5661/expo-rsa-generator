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

    private func generateRSAKeyPair(keyAlias: String, promise: Promise) {
        do {
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
            guard let keyPair = SecKeyGeneratePair(attributes as CFDictionary, &error) else {
                throw error!.takeRetainedValue() as Error
            }

            let publicKeyData = SecKeyCopyExternalRepresentation(keyPair.publicKey, &error) as Data?
            guard let publicKeyBase64 = publicKeyData?.base64EncodedString() else {
                throw error!.takeRetainedValue() as Error
            }

            promise.resolve(publicKeyBase64)
        } catch {
            promise.reject("KEY_GENERATION_ERROR", error)
        }
    }

    private func encryptRSA(keyAlias: String, data: String, promise: Promise) {
        do {
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrLabel as String: keyAlias,
                kSecReturnRef as String: true
            ]

            var item: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &item)

            guard status == errSecSuccess, let publicKey = item as? SecKey else {
                throw NSError(domain: "ExpoRsaGeneratorModule", code: 0, userInfo: [NSLocalizedDescriptionKey: "Public key not found."])
            }

            let padding: SecPadding = .PKCS1
            guard let encryptedData = SecKeyCreateEncryptedData(publicKey, padding, data.data(using: .utf8)! as CFData, nil) as Data? else {
                throw NSError(domain: "ExpoRsaGeneratorModule", code: 0, userInfo: [NSLocalizedDescriptionKey: "Encryption failed."])
            }

            let encryptedBase64 = encryptedData.base64EncodedString()
            promise.resolve(encryptedBase64)

        } catch {
            promise.reject("ENCRYPTION_ERROR", error)
        }
    }

    private func decryptRSA(keyAlias: String, encryptedBase64: String, promise: Promise) {
        do {
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrLabel as String: keyAlias,
                kSecReturnRef as String: true
            ]

            var item: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &item)

            guard status == errSecSuccess, let privateKey = item as? SecKey else {
                throw NSError(domain: "ExpoRsaGeneratorModule", code: 0, userInfo: [NSLocalizedDescriptionKey: "Private key not found."])
            }

            let padding: SecPadding = .PKCS1
            guard let encryptedData = Data(base64Encoded: encryptedBase64) else {
                throw NSError(domain: "ExpoRsaGeneratorModule", code: 0, userInfo: [NSLocalizedDescriptionKey: "Invalid base64 data."])
            }

            guard let decryptedData = SecKeyCreateDecryptedData(privateKey, padding, encryptedData as CFData, nil) as Data? else {
                throw NSError(domain: "ExpoRsaGeneratorModule", code: 0, userInfo: [NSLocalizedDescriptionKey: "Decryption failed."])
            }

            guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
                throw NSError(domain: "ExpoRsaGeneratorModule", code: 0, userInfo: [NSLocalizedDescriptionKey: "Decrypted data is not valid UTF-8."])
            }

            promise.resolve(decryptedString)
        } catch {
            promise.reject("DECRYPTION_ERROR", error)
        }
    }
}