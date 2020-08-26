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

struct Crypto {
  
  struct NIST_P256 {
    
    // MARK: Example nodejs P256 public key
    static let nodejsPublicKeyData = Data([ // Hex dump 64 character length (remove initial 2 entries 0x00 and 0xST)
      0x91, 0x5a, 0x61, 0x9e, 0xf2, 0x2f, 0x8e, 0x8e, 0x20, 0xeb, 0xd3, 0x3a, 0x80, 0xe7,
      0x7c, 0xcb, 0x43, 0x30, 0xeb, 0xc0, 0x7d, 0x11, 0x6e, 0xfb, 0x60, 0x02, 0x01, 0x02, 0xcb, 0x87,
      0x76, 0x03, 0xeb, 0x71, 0x5a, 0x4c, 0x69, 0xe3, 0x4e, 0x9c, 0xd0, 0xd4, 0xaa, 0x2f, 0xad, 0x15,
      0x4e, 0x8e, 0x9f, 0xff, 0x8c, 0x7f, 0x13, 0x42, 0x2a, 0xd9, 0x1a, 0x8f, 0x82, 0xd5, 0x61, 0x98,
      0xe8, 0xca
    ])
    static let nodejsSigningPublicKey = try! P256.Signing.PublicKey.init(x963Representation: nodejsPublicKeyData)
    static let nodejsKeyAgreementPublicKey = try! P256.KeyAgreement.PublicKey.init(x963Representation: nodejsPublicKeyData)
    
    #if targetEnvironment(simulator)
    
    static func generate() -> P256.KeyAgreement.PrivateKey {
      let P256Key = P256.KeyAgreement.PrivateKey()
      //      print(P256Key.x963Representation.base64EncodedString())
      //      print("\nP256 public key raw representation base64")
      
      return P256Key
    }
    
    static func getSigningPrivateKey(representation: Data) throws -> P256.Signing.PrivateKey {
      // representation == x963representation
      do {
        let privateKey = try P256.Signing.PrivateKey.init(x963Representation: representation)
        
        return privateKey
      } catch {
        throw error
      }
    }
    
    static func getKeyAgreementPrivateKey(representation: Data) throws -> P256.KeyAgreement.PrivateKey {
      // representation == x963representation
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
      //      print(P256Key.dataRepresentation.base64EncodedString())
      //      print(P256Key.publicKey.x963Representation.base64EncodedString())
      
      return P256Key
    }
    
    static func getSigningPrivateKey(representation: Data) throws -> SecureEnclave.P256.Signing.PrivateKey {
      // representation == dataRepresentation
      do {
        let privateKey = try SecureEnclave.P256.Signing.PrivateKey.init(dataRepresentation: representation)
        
        return privateKey
      } catch {
        throw error
      }
    }
    
    static func getKeyAgreementPrivateKey(representation: Data) throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
      // representation == dataRepresentation
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
        let verification = nodejsSigningPublicKey.isValidSignature(nodejsSignatureECDSA, for: messageData)
        
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
        let symmetricKeySalt = try generateRandomBytes(length: 16)
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
          using: SHA256.self,
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
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: nodejsKeyAgreementPublicKey)
        let symmetricKeySalt = try generateRandomBytes(length: 16)
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
          using: SHA256.self,
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
          using: SHA256.self,
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
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: nodejsKeyAgreementPublicKey)
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
          using: SHA256.self,
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
    static let nodejsPublicKeyData = Data([ // Remove only first 0x00
      0x38, 0x3f, 0x32, 0x6a, 0x07, 0x6c, 0xed, 0x9b, 0x62, 0xd2, 0xc5, 0x49, 0xa1, 0x27, 0xcf,
      0x37, 0x0b, 0x91, 0xb6, 0xe9, 0xfa, 0x72, 0x48, 0x79, 0xdf, 0x6c, 0xf9, 0x1e, 0x99, 0x81, 0x5d,
      0xbd
    ])
    static let nodejsPublicKey = try! Curve25519.Signing.PublicKey.init(rawRepresentation: nodejsPublicKeyData)
    
    static func generate() -> Curve25519.Signing.PrivateKey {
      let ed25519Key = Curve25519.Signing.PrivateKey()
      //      print(ed25519Key.rawRepresentation.base64EncodedString())
      //      print(ed25519Key.publicKey.rawRepresentation.base64EncodedString())
      
      return ed25519Key
    }
    
    static func getSigningPrivateKey(representation: Data) throws -> Curve25519.Signing.PrivateKey {
      // representation == rawRepresentation
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
      
      let verification = nodejsPublicKey.isValidSignature(nodejsSignatureData, for: messageData)
      
      return verification
    }
  }
  
  struct X25519 {
    static let nodejsPublicKeyData = Data([ // Remove only first 0x00
      0x00, 0x05, 0x07, 0x5e, 0x4a, 0xf5, 0x94, 0x6d, 0xc1, 0xb5, 0x24, 0x8d, 0xf3, 0x5a, 0xca,
      0x30, 0x44, 0x44, 0xa9, 0xc4, 0xe5, 0x82, 0xf0, 0x62, 0xe6, 0x0b, 0x28, 0xce, 0x8a, 0x49, 0xd1,
      0x4a
    ])
    static let nodejsPublicKey = try! Curve25519.KeyAgreement.PublicKey.init(rawRepresentation: nodejsPublicKeyData)
    
    static func generate() -> Curve25519.KeyAgreement.PrivateKey {
      let X25519Key = Curve25519.KeyAgreement.PrivateKey()
      //      print(X25519Key.rawRepresentation.base64EncodedString())
      //      print(X25519Key.publicKey.rawRepresentation.base64EncodedString())
      
      return X25519Key
    }
    
    static func getKeyAgreementPrivateKey(representation: Data) throws -> Curve25519.KeyAgreement.PrivateKey {
      // representation == rawRepresentation
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
        let symmetricKeySalt = try generateRandomBytes(length: 16)!
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
          using: SHA256.self,
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
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: nodejsPublicKey)
        let symmetricKeySalt = try generateRandomBytes(length: 16)!
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
          using: SHA256.self,
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
          using: SHA256.self,
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
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: nodejsPublicKey)
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
          using: SHA256.self,
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
