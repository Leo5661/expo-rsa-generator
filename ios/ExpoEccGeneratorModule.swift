import ExpoModulesCore
import CryptoKit
import Security

public class ExpoEccGeneratorModule: Module {
  public func definition() -> ModuleDefinition {
    Name("ExpoEccGenerator")

    AsyncFunction("generateKeyPair") { (keyAlias: String, promise: Promise) in
      Task {
        do {
          if let publicKeyData = try await self.generateKeyPair(keyAlias: keyAlias) {
            let publicKeyBase64 = publicKeyData.base64EncodedString()
            promise.resolve(publicKeyBase64)
          } else {
            let publicKeyData = try await self.getPublicKey(keyAlias: keyAlias)
            let publicKeyBase64 = publicKeyData.base64EncodedString()
            promise.resolve(publicKeyBase64)
          }
        } catch {
          Log.error("ECC Key Generation failed: \(error)")
          promise.reject("ECC_KEY_GEN_ERROR", error)
        }
      }
    }

    AsyncFunction("encrypt") { (keyAlias: String, data: String, promise: Promise) in
      Task {
        do {
          let encryptedData = try await self.encrypt(keyAlias: keyAlias, data: data)
          let encryptedBase64 = encryptedData.base64EncodedString()
          promise.resolve(encryptedBase64)
        } catch {
          Log.error("ECC Encryption failed: \(error)")
          promise.reject("ECC_ENCRYPT_ERROR", error)
        }
      }
    }

    AsyncFunction("decrypt") { (keyAlias: String, encryptedBase64: String, promise: Promise) in
      Task {
        do {
          let decryptedString = try await self.decrypt(keyAlias: keyAlias, encryptedBase64: encryptedBase64)
          promise.resolve(decryptedString)
        } catch {
          Log.error("ECC Decryption failed: \(error)")
          promise.reject("ECC_DECRYPT_ERROR", error)
        }
      }
    }
    OnDestroy {
        Log.info("ExpoEccGenerator module destroyed")
    }
  }

  private func generateKeyPair(keyAlias: String) async throws -> Data? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: keyAlias.data(using: .utf8)!,
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
      kSecAttrIsPermanent as String: true,
      kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
      kSecAttrKeyUsageSign as String: true,
      kSecAttrKeyUsageVerify as String: true,
      kSecAttrKeyUsageEncrypt as String: true,
      kSecAttrKeyUsageDecrypt as String: true,
      kSecAttrKeyUsageKeyAgreement as String: true,
      kSecReturnAttributes as String: true,
      kSecReturnPersistentRef as String: true,
    ]

    var item: CFTypeRef?
    let status = SecItemAdd(query as CFDictionary, &item)

    guard status == errSecSuccess else {
      if status == errSecDuplicateItem {
        Log.info("Key already exists for alias: \(keyAlias)")
        return nil;
      }
      throw NSError(domain: NSOSStatusErrorDomain, code: Int(status), userInfo: nil)
    }

    Log.info("ECC Key pair generated successfully for alias: \(keyAlias)")
    let publicKeyAttributes = (item as! [String: Any])[kSecAttrPublicKeyAttrs as String] as! [String: Any]
    let publicKeyData = publicKeyAttributes[kSecValueData as String] as! Data
    return publicKeyData
  }

    private func getPublicKey(keyAlias: String) async throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyAlias.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecReturnData as String: true
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status), userInfo: nil)
        }
        return item as! Data
    }

  private func encrypt(keyAlias: String, data: String) async throws -> Data {
    let publicKeyData = try await getPublicKey(keyAlias: keyAlias)
    guard let publicKey = try? P256.KeyAgreement.PublicKey(rawRepresentation: publicKeyData) else {
        throw NSError(domain: "ECC_ENCRYPT_ERROR", code: 0, userInfo: [NSLocalizedDescriptionKey: "Invalid public key"])
    }
    let sharedSecret = try await generateSharedSecret(keyAlias: keyAlias, otherPublicKey: publicKey)
    let symmetricKey = SymmetricKey(data: sharedSecret)
    let sealedBox = try AES.GCM.seal(Data(data.utf8), using: symmetricKey)
    Log.info("ECC Encryption successful for alias: \(keyAlias)")
    return sealedBox.combined
  }

  private func decrypt(keyAlias: String, encryptedBase64: String) async throws -> String {
    guard let encryptedData = Data(base64Encoded: encryptedBase64) else {
      throw NSError(domain: "ECC_DECRYPT_ERROR", code: 0, userInfo: [NSLocalizedDescriptionKey: "Invalid base64 encoded data"])
    }
    let publicKeyData = try await getPublicKey(keyAlias: keyAlias)
    guard let publicKey = try? P256.KeyAgreement.PublicKey(rawRepresentation: publicKeyData) else {
        throw NSError(domain: "ECC_DECRYPT_ERROR", code: 0, userInfo: [NSLocalizedDescriptionKey: "Invalid public key"])
    }
    let sharedSecret = try await generateSharedSecret(keyAlias: keyAlias, otherPublicKey: publicKey)
    let symmetricKey = SymmetricKey(data: sharedSecret)
    guard let sealedBox = try? AES.GCM.SealedBox(combined: encryptedData) else {
        throw NSError(domain: "ECC_DECRYPT_ERROR", code: 0, userInfo: [NSLocalizedDescriptionKey: "Invalid sealed box data"])
    }
    let decryptedData = try AES.GCM.open(sealedBox, using: symmetricKey)
    Log.info("ECC Decryption successful for alias: \(keyAlias)")
    return String(data: decryptedData, encoding: .utf8) ?? ""
  }

  private func generateSharedSecret(keyAlias: String, otherPublicKey: P256.KeyAgreement.PublicKey) async throws -> Data {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: keyAlias.data(using: .utf8)!,
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
      kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
      kSecReturnRef as String: true
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status == errSecSuccess else {
      throw NSError(domain: NSOSStatusErrorDomain, code: Int(status), userInfo: nil)
    }

    guard let privateKeyRef = item as? SecKey else {
        throw NSError(domain: "ECC_KEY_AGREEMENT_ERROR", code:0, userInfo: [NSLocalizedDescriptionKey: "Private key not found"])
    }

    let privateKey = try P256.KeyAgreement.PrivateKey(privateKey: privateKeyRef)
    let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: otherPublicKey)
    return sharedSecret.rawRepresentation
  }
}