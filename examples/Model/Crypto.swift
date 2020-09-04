//
//  Crypto.swift
//  NodejsCryptoExample
//
//  Created by fuzzcore on 22/8/20.
//  Copyright © 2020 Fuzznets P.C. All rights reserved.
//

import Foundation
import CryptoKit
import Security

fileprivate func generateRandomBytes(length: Int) throws -> Data? {
  var keyData = Data(count: length)
  let result = keyData.withUnsafeMutableBytes {
    SecRandomCopyBytes(kSecRandomDefault, length, $0.baseAddress!)
  }
  if result == errSecSuccess {
    return keyData
  } else {
    return nil
  }
}

// String between PEM headers
let nodejsP256PublicKeyBase64 = "myeIjJ2QtbnA9xs5CEjTUEEpZ9yYuzTLSQnwZknCJVnzunlddQBcTpIynGLqaFM+ar+Gpyc45t7jjRcHzzGdMQ=="
let nodejsEd25519PublicKeyBase64 = "bDdCKL1MtrVuLKyf0YCsKYFlhMlgtJRFACu2CShKVoY="
let nodejsX25519PublicKeyBase64 = "KbH8dSp1frTmLPp+LGPpM5fLnncR7J3xSQDSJKPZg0o="

struct Crypto {
  
  static let symmetricKeySaltLength = 64
  
  struct NIST_P256 {
    
    static func nodejsSigningPublicKey() -> P256.Signing.PublicKey {
      let nodejsP256PublicKeyData = Data(base64Encoded: nodejsP256PublicKeyBase64)!
      
      return try! P256.Signing.PublicKey.init(rawRepresentation: nodejsP256PublicKeyData)
    }
    
    static func nodejsKeyAgreementPublicKey() -> P256.KeyAgreement.PublicKey {
      let nodejsP256PublicKeyData = Data(base64Encoded: nodejsP256PublicKeyBase64)!
      
      return try! P256.KeyAgreement.PublicKey.init(rawRepresentation: nodejsP256PublicKeyData)
    }
    
    #if targetEnvironment(simulator)
    
    static func generate() -> P256.KeyAgreement.PrivateKey {
      let P256Key = P256.KeyAgreement.PrivateKey()
      
      return P256Key
    }
    
    static func getSigningPrivateKey(representation: Data) throws -> P256.Signing.PrivateKey {
      do {
        let privateKey = try P256.Signing.PrivateKey.init(x963Representation: representation)
        
        return privateKey
      } catch {
        throw error
      }
    }
    
    static func getKeyAgreementPrivateKey(representation: Data) throws -> P256.KeyAgreement.PrivateKey {
      do {
        let privateKey = try P256.KeyAgreement.PrivateKey.init(x963Representation: representation)
        
        return privateKey
      } catch {
        throw error
      }
    }
    
    #else
    
    static func generate() -> SecureEnclave.P256.KeyAgreement.PrivateKey {
      let P256Key = SecureEnclave.P256.KeyAgreement.PrivateKey()
      
      return P256Key
    }
    
    static func getSigningPrivateKey(representation: Data) throws -> SecureEnclave.P256.Signing.PrivateKey {
      do {
        let privateKey = try SecureEnclave.P256.Signing.PrivateKey.init(dataRepresentation: representation)
        
        return privateKey
      } catch {
        throw error
      }
    }
    
    static func getKeyAgreementPrivateKey(representation: Data) throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
      do {
        let privateKey = try SecureEnclave.P256.KeyAgreement.PrivateKey.init(dataRepresentation: representation)
        
        return privateKey
      } catch {
        throw error
      }
    }
    
    #endif
    
    static func signMessage(message: String, privateKeyRepresentation: Data) throws -> String {
      let messageData = message.data(using: .utf8)!
      
      do {
        let privateKey = try getSigningPrivateKey(representation: privateKeyRepresentation)
        let messageSignature = try privateKey.signature(for: messageData)
        
        return messageSignature.derRepresentation.base64EncodedString()
      } catch {
        throw error
      }
    }
    
    static func verifyMessageSignature(
      message: String,
      signature: String,
      publicKey: P256.Signing.PublicKey
    ) throws -> Bool {
      let messageData = message.data(using: .utf8)!
      let signatureData = Data(base64Encoded: signature)!
      
      do {
        let signatureECDSA = try P256.Signing.ECDSASignature.init(derRepresentation: signatureData)
        let verification = publicKey.isValidSignature(signatureECDSA, for: messageData)
        
        return verification
      } catch {
        throw error
      }
    }
    
    static func verifyMessageSignatureFromNodejs(message: String, nodejsSignatureBase64: String) throws -> Bool {
      let messageData = message.data(using: .utf8)!
      let nodejsSignatureData = Data(base64Encoded: nodejsSignatureBase64)!
      
      do {
        let nodejsSignatureECDSA = try P256.Signing.ECDSASignature.init(derRepresentation: nodejsSignatureData)
        let verification = nodejsSigningPublicKey().isValidSignature(nodejsSignatureECDSA, for: messageData)
        
        return verification
      } catch {
        throw error
      }
    }
    
    static func encryptMessageWithSymmetricKey(
      message: String,
      privateKeyRepresentation: Data,
      publicKey: P256.KeyAgreement.PublicKey
    ) throws -> (encryptedMessage: String, symmetricKeySalt: String) {
      let messageData = message.data(using: .utf8)!
      
      do {
        let privateKey = try getKeyAgreementPrivateKey(representation: privateKeyRepresentation)
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        let symmetricKeySalt = try generateRandomBytes(length: symmetricKeySaltLength)
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
          using: SHA512.self,
          salt: symmetricKeySalt!,
          sharedInfo: Data(),
          outputByteCount: 32
        )
        let encryptedMessage = try ChaChaPoly.seal(messageData, using: symmetricKey)
        
        return (
          encryptedMessage.combined.base64EncodedString(),
          symmetricKeySalt!.withUnsafeBytes {
            return Data(Array($0)).base64EncodedString()
          }
        )
      } catch {
        throw error
      }
    }
    
    static func encryptMessageWithSymmetricKeyFromNodejs(
      message: String,
      privateKeyRepresentation: Data
    ) throws -> (encryptedMessage: String, symmetricKeySalt: String) {
      let messageData = message.data(using: .utf8)!
      
      do {
        let privateKey = try getKeyAgreementPrivateKey(representation: privateKeyRepresentation)
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: nodejsKeyAgreementPublicKey())
        let symmetricKeySalt = try generateRandomBytes(length: symmetricKeySaltLength)
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
          using: SHA512.self,
          salt: symmetricKeySalt!,
          sharedInfo: Data(),
          outputByteCount: 32
        )
        
        print("Symmetric key used by iOS in P256 encryption: \(symmetricKey.withUnsafeBytes { return Data(Array($0)).base64EncodedString() })")
        
        let encryptedMessage = try ChaChaPoly.seal(messageData, using: symmetricKey)
        
        return (
          encryptedMessage.combined.base64EncodedString(),
          symmetricKeySalt!.withUnsafeBytes {
            return Data(Array($0)).base64EncodedString()
          }
        )
      } catch {
        throw error
      }
    }
    
    static func decryptMessageWithSymmetricKey(
      encryptedMessage: String,
      symmetricKeySaltBase64: String,
      privateKeyRepresentation: Data,
      publicKey: P256.KeyAgreement.PublicKey
    ) throws -> String {
      let encryptedMessageData = Data(base64Encoded: encryptedMessage)!
      let symmetricKeySalt = Data(base64Encoded: symmetricKeySaltBase64)!
      
      do {
        let privateKey = try getKeyAgreementPrivateKey(representation: privateKeyRepresentation)
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
          using: SHA512.self,
          salt: symmetricKeySalt,
          sharedInfo: Data(),
          outputByteCount: 32
        )
        
        print("Symmetric key used by iOS in P256 decryption: \(symmetricKey.withUnsafeBytes { return Data(Array($0)).base64EncodedString() })")
        
        let box = try ChaChaPoly.SealedBox.init(combined: encryptedMessageData)
        let decryptedMessage = try ChaChaPoly.open(box, using: symmetricKey)
        let decryptedMessageString = String(data: decryptedMessage, encoding: .utf8)!
        
        return decryptedMessageString
      } catch {
        throw error
      }
    }
    
    static func decryptMessageWithSymmetricKeyFromNodejs(
      encryptedMessage: String,
      symmetricKeySaltBase64: String,
      privateKeyRepresentation: Data
    ) throws -> String {
      let encryptedMessageData = Data(base64Encoded: encryptedMessage)!
      let symmetricKeySalt = Data(base64Encoded: symmetricKeySaltBase64)!
      
      do {
        let privateKey = try getKeyAgreementPrivateKey(representation: privateKeyRepresentation)
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: nodejsKeyAgreementPublicKey())
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
          using: SHA512.self,
          salt: symmetricKeySalt,
          sharedInfo: Data(),
          outputByteCount: 32
        )
        
        let box = try ChaChaPoly.SealedBox.init(combined: encryptedMessageData)
        let decryptedMessage = try ChaChaPoly.open(box, using: symmetricKey)
        let decryptedMessageString = String(data: decryptedMessage, encoding: .utf8)!
        
        return decryptedMessageString
      } catch {
        throw error
      }
    }
  }
  
  struct Ed25519 {
    
    static func nodejsPublicKey() -> Curve25519.Signing.PublicKey {
      let nodejsEd25519PublicKeyData = Data(base64Encoded: nodejsEd25519PublicKeyBase64)!
      
      return try! Curve25519.Signing.PublicKey.init(rawRepresentation: nodejsEd25519PublicKeyData)
    }
    
    static func generate() -> Curve25519.Signing.PrivateKey {
      let ed25519Key = Curve25519.Signing.PrivateKey()
      
      return ed25519Key
    }
    
    static func getSigningPrivateKey(representation: Data) throws -> Curve25519.Signing.PrivateKey {
      do {
        let privateKey = try Curve25519.Signing.PrivateKey.init(rawRepresentation: representation)
        
        return privateKey
      } catch {
        throw error
      }
    }
    
    static func signMessage(message: String, privateKeyRepresentation: Data) throws -> String {
      let messageData = message.data(using: .utf8)!
      
      do {
        let privateKey = try getSigningPrivateKey(representation: privateKeyRepresentation)
        let messageSignature = try privateKey.signature(for: messageData)
        
        return messageSignature.base64EncodedString()
      } catch {
        throw error
      }
    }
    
    static func verifyMessageSignature(
      message: String,
      signature: String,
      publicKey: Curve25519.Signing.PublicKey
    ) -> Bool {
      let messageData = message.data(using: .utf8)!
      let signatureData = Data(base64Encoded: signature)!
      
      let verification = publicKey.isValidSignature(signatureData, for: messageData)
      
      return verification
    }
    
    static func verifyMessageSignatureFromNodejs(message: String, nodejsSignatureBase64: String) -> Bool {
      let messageData = message.data(using: .utf8)!
      let nodejsSignatureData = Data(base64Encoded: nodejsSignatureBase64)!
      
      let verification = nodejsPublicKey().isValidSignature(nodejsSignatureData, for: messageData)
      
      return verification
    }
  }
  
  struct X25519 {
    
    static func nodejsPublicKey() -> Curve25519.KeyAgreement.PublicKey {
      let nodejsX25519PublicKeyData = Data(base64Encoded: nodejsX25519PublicKeyBase64)!
      
      return try! Curve25519.KeyAgreement.PublicKey.init(rawRepresentation: nodejsX25519PublicKeyData)
    }
    
    static func generate() -> Curve25519.KeyAgreement.PrivateKey {
      let X25519Key = Curve25519.KeyAgreement.PrivateKey()
      
      return X25519Key
    }
    
    static func getKeyAgreementPrivateKey(representation: Data) throws -> Curve25519.KeyAgreement.PrivateKey {
      do {
        let privateKey = try Curve25519.KeyAgreement.PrivateKey.init(rawRepresentation: representation)
        
        return privateKey
      } catch {
        throw error
      }
    }
    
    static func encryptMessageWithSymmetricKey(
      message: String,
      privateKeyRepresentation: Data,
      publicKey: Curve25519.KeyAgreement.PublicKey
    ) throws -> (encryptedMessage: String, symmetricKeySalt: String) {
      let messageData = message.data(using: .utf8)!
      
      do {
        let privateKey = try getKeyAgreementPrivateKey(representation: privateKeyRepresentation)
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        let symmetricKeySalt = try generateRandomBytes(length: symmetricKeySaltLength)!
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
          using: SHA512.self,
          salt: symmetricKeySalt,
          sharedInfo: Data(),
          outputByteCount: 32
        )
        let encryptedMessage = try ChaChaPoly.seal(messageData, using: symmetricKey)
        
        return (
          encryptedMessage.combined.base64EncodedString(),
          symmetricKeySalt.withUnsafeBytes {
            return Data(Array($0)).base64EncodedString()
          }
        )
      } catch {
        throw error
      }
    }
    
    static func encryptMessageWithSymmetricKeyFromNodejs(
      message: String,
      privateKeyRepresentation: Data
    ) throws -> (encryptedMessage: String, symmetricKeySalt: String) {
      let messageData = message.data(using: .utf8)!
      
      do {
        let privateKey = try getKeyAgreementPrivateKey(representation: privateKeyRepresentation)
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: nodejsPublicKey())
        let symmetricKeySalt = try generateRandomBytes(length: symmetricKeySaltLength)!
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
          using: SHA512.self,
          salt: symmetricKeySalt,
          sharedInfo: Data(),
          outputByteCount: 32
        )
        let encryptedMessage = try ChaChaPoly.seal(messageData, using: symmetricKey)
        
        return (
          encryptedMessage.combined.base64EncodedString(),
          symmetricKeySalt.withUnsafeBytes {
            return Data(Array($0)).base64EncodedString()
          }
        )
      } catch {
        throw error
      }
    }
    
    static func decryptMessageWithSymmetricKey(
      encryptedMessage: String,
      symmetricKeySaltBase64: String,
      privateKeyRepresentation: Data,
      publicKey: Curve25519.KeyAgreement.PublicKey
    ) throws -> String {
      let encryptedMessageData = Data(base64Encoded: encryptedMessage)!
      let symmetricKeySalt = Data(base64Encoded: symmetricKeySaltBase64)!
      
      do {
        let privateKey = try getKeyAgreementPrivateKey(representation: privateKeyRepresentation)
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
          using: SHA512.self,
          salt: symmetricKeySalt,
          sharedInfo: Data(),
          outputByteCount: 32
        )
        
        let box = try ChaChaPoly.SealedBox.init(combined: encryptedMessageData)
        let decryptedMessage = try ChaChaPoly.open(box, using: symmetricKey)
        let decryptedMessageString = String(data: decryptedMessage, encoding: .utf8)!
        
        return decryptedMessageString
      } catch {
        throw error
      }
    }
    
    static func decryptMessageWithSymmetricKeyFromNodejs(
      encryptedMessage: String,
      symmetricKeySaltBase64: String,
      privateKeyRepresentation: Data
    ) throws -> String {
      let encryptedMessageData = Data(base64Encoded: encryptedMessage)!
      let symmetricKeySalt = Data(base64Encoded: symmetricKeySaltBase64)!
      
      do {
        let privateKey = try getKeyAgreementPrivateKey(representation: privateKeyRepresentation)
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: nodejsPublicKey())
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
          using: SHA512.self,
          salt: symmetricKeySalt,
          sharedInfo: Data(),
          outputByteCount: 32
        )
        
        let box = try ChaChaPoly.SealedBox.init(combined: encryptedMessageData)
        let decryptedMessage = try ChaChaPoly.open(box, using: symmetricKey)
        let decryptedMessageString = String(data: decryptedMessage, encoding: .utf8)!
        
        return decryptedMessageString
      } catch {
        throw error
      }
    }
  }
}
