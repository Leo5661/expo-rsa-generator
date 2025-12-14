import ExpoModulesCore
import Security
import Foundation

public class ExpoEccGeneratorModule: Module {
  public func definition() -> ModuleDefinition {
    Name("ExpoEccGenerator")

    AsyncFunction("generateECCKeyPair") { (keyAlias: String, promise: Promise) in
      self.generateECCKeyPair(keyAlias: keyAlias, promise: promise)
    }

    AsyncFunction("encryptECC") { (keyAlias: String, data: String, promise: Promise) in
      self.encryptECC(keyAlias: keyAlias, data: data, promise: promise)
    }

    AsyncFunction("decryptECC") { (keyAlias: String, encryptedBase64: String, promise: Promise) in
      self.decryptECC(keyAlias: keyAlias, encryptedBase64: encryptedBase64, promise: promise)
    }
    
    OnDestroy {
        print("ExpoEccGenerator module destroyed")
    }
  }

  private func generateECCKeyPair(keyAlias: String, promise: Promise) {
    do {
      // Delete existing key with same alias if any
      let deleteQuery: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: keyAlias.data(using: .utf8)!,
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom
      ]
      SecItemDelete(deleteQuery as CFDictionary)

      // Create new key pair
      let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: keyAlias.data(using: .utf8)!,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
      ]

      var error: Unmanaged<CFError>?
      guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        throw error!.takeRetainedValue() as Error
      }
      
      guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
         throw NSError(domain: "ExpoEccGenerator", code: 0, userInfo: [NSLocalizedDescriptionKey: "Failed to copy public key"])
      }

      var errorRef: Unmanaged<CFError>?
      guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &errorRef) as Data? else {
         throw errorRef!.takeRetainedValue() as Error
      }

      promise.resolve(publicKeyData.base64EncodedString())
    } catch {
      print("ECC Key Gen Error: \(error)")
      promise.reject("ECC_KEY_GEN_ERROR", "\(error)")
    }
  }

  private func encryptECC(keyAlias: String, data: String, promise: Promise) {
    do {
      // Retrieve Public Key
      // Note: We usually don't store Public Key permanently in Keychain by tag unless explicitly added. 
      // But we can get it from Private Key if we find the Private Key.
      // Or we assume 'generateECCKeyPair' stored it?
      // Actually SecKeyCreateRandomKey stored the Private Key because of kSecAttrIsPermanent: true.
      
      // Let's find the private key and derive public key, OR find public key if stored (often isn't by default unless ref'd).
      // Best bet: Find Private Key, get Public Key from it.
      
      let tag = keyAlias.data(using: .utf8)!
      let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: tag,
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecReturnRef as String: true
      ]
      
      var item: CFTypeRef?
      let status = SecItemCopyMatching(query as CFDictionary, &item)
      guard status == errSecSuccess, let privateKey = item as! SecKey? else {
         throw NSError(domain: "ExpoEccGenerator", code: 0, userInfo: [NSLocalizedDescriptionKey: "Key not found for alias: \(keyAlias)"])
      }
      
      guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
         throw NSError(domain: "ExpoEccGenerator", code: 0, userInfo: [NSLocalizedDescriptionKey: "Failed to derive public key"])
      }

      // ECIES Encryption
      // Algorithm: We need to choose one compatible with iOS and standard usage.
      // .eciesEncryptionCofactorVariableIVX963SHA256AESGCM is a common one for P256.
      
      let algorithm: SecKeyAlgorithm = .eciesEncryptionStandardVariableIVX963SHA256AESGCM
      
      guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm) else {
         throw NSError(domain: "ExpoEccGenerator", code: 0, userInfo: [NSLocalizedDescriptionKey: "Algorithm not supported"])
      }

      var error: Unmanaged<CFError>?
      guard let encryptedData = SecKeyCreateEncryptedData(publicKey, algorithm, data.data(using: .utf8)! as CFData, &error) as Data? else {
         throw error!.takeRetainedValue() as Error
      }
      
      promise.resolve(encryptedData.base64EncodedString())

    } catch {
      print("ECC Encryption Error: \(error)")
      promise.reject("ECC_ENCRYPT_ERROR", "\(error)")
    }
  }

  private func decryptECC(keyAlias: String, encryptedBase64: String, promise: Promise) {
     do {
      guard let encryptedData = Data(base64Encoded: encryptedBase64) else {
         throw NSError(domain: "ExpoEccGenerator", code: 0, userInfo: [NSLocalizedDescriptionKey: "Invalid base64"])
      }

      let tag = keyAlias.data(using: .utf8)!
      let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: tag,
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecReturnRef as String: true
      ]
      
      var item: CFTypeRef?
      let status = SecItemCopyMatching(query as CFDictionary, &item)
      guard status == errSecSuccess, let privateKey = item as! SecKey? else {
         throw NSError(domain: "ExpoEccGenerator", code: 0, userInfo: [NSLocalizedDescriptionKey: "Key not found"])
      }

      let algorithm: SecKeyAlgorithm = .eciesEncryptionStandardVariableIVX963SHA256AESGCM
      
      guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, algorithm) else {
         throw NSError(domain: "ExpoEccGenerator", code: 0, userInfo: [NSLocalizedDescriptionKey: "Algorithm not supported"])
      }

      var error: Unmanaged<CFError>?
      guard let decryptedData = SecKeyCreateDecryptedData(privateKey, algorithm, encryptedData as CFData, &error) as Data? else {
         throw error!.takeRetainedValue() as Error
      }
      
      guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
         throw NSError(domain: "ExpoEccGenerator", code: 0, userInfo: [NSLocalizedDescriptionKey: "Decrypted data is not UTF8"])
      }

      promise.resolve(decryptedString)

    } catch {
      print("ECC Decryption Error: \(error)")
      promise.reject("ECC_DECRYPT_ERROR", "\(error)")
    }
  }
}