//
//  ContentView.swift
//  NodejsCryptoExample
//
//  Created by fuzzcore on 22/8/20.
//  Copyright © 2020 Fuzznets P.C. All rights reserved.
//

import SwiftUI

struct ContentView: View {
  @State private var P256PublicKey = ""
  @State private var Ed25519PublicKey = ""
  @State private var X25519PublicKey = ""
  
  var body: some View {
    VStack {
      Text("Nodejs cryptokit example")
      Text("Base64 private key representations to save in order to restore keys")
        .padding()
      Spacer()
      Text("P256 private key: \n\(self.P256PublicKey)")
        .padding()
      Spacer()
      Text("Ed25519 private key: \n\(self.Ed25519PublicKey)")
      Spacer()
      Text("X25519 private key: \n\(self.X25519PublicKey)")
        .padding()
    }
    .padding()
    .onAppear {
//      let p256key = Crypto.NIST_P256.generate()
//      let ed25519key = Crypto.Ed25519.generate()
//      let x25519key = Crypto.X25519.generate()
//      print("\nIn order to restore some iOS keys copy and paste this in the beginning")
//      print("P256 x963 representation: \(p256key.x963Representation.base64EncodedString())")
//      print("Ed25519 raw representation: \(ed25519key.rawRepresentation.base64EncodedString())")
//      print("X25519 raw representation: \(x25519key.rawRepresentation.base64EncodedString())")

      let p256keyX963RepresentationBase64 = "BDtr3giflhW7iplVoXZ2olz0lpsgyjChKsu22go+Nhm5TDk8dnwmMlm34uczZpjwd3x9NXO/oQWRuhEZF+95p3kY/OH0QWljwx/RwrbnFZFtqtYp1lwBIkF+lTOhDd+bDQ=="
      let ed25519keyRawRepresentationBase64 = "9uTKxyRBn1eAZzmpyP7vZlXL3SDdXaBHcRp146ACK2Q="
      let x25519keyRawRepresentationBase64 = "APDKv1hDdMrOA+wUF25g5XGgAU66FQ4hUAzvTU3lTnI="
      let p256keyX963RepresentationData = Data(base64Encoded: p256keyX963RepresentationBase64)!
      let ed25519keyRawRepresentationData = Data(base64Encoded: ed25519keyRawRepresentationBase64)!
      let x25519keyRawRepresentationData = Data(base64Encoded: x25519keyRawRepresentationBase64)!
      let p256key = try! Crypto.NIST_P256.getKeyAgreementPrivateKey(representation: p256keyX963RepresentationData)
      let ed25519key = try! Crypto.Ed25519.getSigningPrivateKey(representation: ed25519keyRawRepresentationData)
      let x25519key = try! Crypto.X25519.getKeyAgreementPrivateKey(representation: x25519keyRawRepresentationData)
      
      self.P256PublicKey = p256key.x963Representation.base64EncodedString()
      self.Ed25519PublicKey = ed25519key.rawRepresentation.base64EncodedString()
      self.X25519PublicKey = x25519key.rawRepresentation.base64EncodedString()
      
      print("P256 public key = \"\(p256key.publicKey.x963Representation.base64EncodedString())\"")
      print("\nEd25519 public key = \"\(ed25519key.publicKey.rawRepresentation.base64EncodedString())\"")
      print("\nX25519 public key = \"\(x25519key.publicKey.rawRepresentation.base64EncodedString())\"")
      
      let messageToSignWithP256 = "Message to sign with P256 iOS"
      do {
        let messageP256Signature = try Crypto.NIST_P256.signMessage(
          message: messageToSignWithP256,
          privateKeyRepresentation: p256key.x963Representation
        )
        print("\nP256 signature = \"\(messageP256Signature)\"")
      } catch {
        print(error)
        return
      }
      
      let messageToEncryptWithP256 = "Hello! I am an encrypted iOS message with symmetric P256 key <3"
      do {
        let messageP256Encrypted = try Crypto.NIST_P256.encryptMessageWithSymmetricKey(
          message: messageToEncryptWithP256,
          privateKeyRepresentation: p256key.x963Representation,
          publicKey: Crypto.NIST_P256.nodejsKeyAgreementPublicKey()
        )
        print("\nP256 encrypted message = \"\(messageP256Encrypted)\"")
      } catch {
        print(error)
        return
      }
      
      let messageToSignWithEd25519 = "Message to sign with Ed25519 iOS"
      do {
        let messageEd25519Signature = try Crypto.Ed25519.signMessage(
          message: messageToSignWithEd25519,
          privateKeyRepresentation: ed25519key.rawRepresentation
        )
        print("\nEd25519 signature = \"\(messageEd25519Signature)\"")
      } catch {
        print(error)
        return
      }
      
      
      let messageToEncryptWithX25519 = "Hello! I am an encrypted iOS message with symmetric X25519 key <3"
      do {
        let messageX25519Encrypted = try Crypto.X25519.encryptMessageWithSymmetricKey(
          message: messageToEncryptWithX25519,
          privateKeyRepresentation: x25519key.rawRepresentation,
          publicKey: Crypto.X25519.nodejsPublicKey()
        )
        print("\nX25519 encrypted message = \"\(messageX25519Encrypted)\"")
      } catch {
        print(error)
        return
      }
      
      let nodejsP256SignedMessage = "Example message signed with P256 by nodejs"
      let nodejsP256SignatureBase64 = "MEYCIQCygjOwjV08/D/ajOK3k7PXHWIw79FrKuH4upcOW1734gIhAObF4/URg8nKdQAAcuLO7escu321N3Hxk1BlXmSDERCq"
      do {
        let verifyNodejsP256Signature = try Crypto.NIST_P256.verifyMessageSignatureFromNodejs(
          message: nodejsP256SignedMessage,
          nodejsSignatureBase64: nodejsP256SignatureBase64
        )
        print("\nP256 verification from nodejs is: \(verifyNodejsP256Signature)")
      } catch {
        print(error)
      }
      
      let nodejsP256EncryptedMessage = "6DtpOP9VbS71rBSkr0aI1Xue4nUTwcdVssry1/g3/6sgd+Lei6u5tlyBhZ3R/k+2sv2RbS3PZ5GC/ioQzJL5ArIekoFEg6TTWjO0zWETe6r9w/sqZ5odDFHZBQNrvmOhb+z94t6hdwXvjFG+vAUxbw=="
      let nodejsP256EncryptedMessageSalt = "fJEzYpw0Njx2iwxz1pTeq7QxA0qBcpkP+zzDI5GO5/2rPuoF6CoJMd7Q5fLsCCxmjFrOy4I2Id4dVJ/HRr2LFw=="
      do {
        let decryptedNodejsMessage = try Crypto.NIST_P256.decryptMessageWithSymmetricKeyFromNodejs(
          encryptedMessage: nodejsP256EncryptedMessage,
          symmetricKeySaltBase64: nodejsP256EncryptedMessageSalt,
          privateKeyRepresentation: p256keyX963RepresentationData
        )
        print("\nDecrypted nodejs P256 message = \"\(decryptedNodejsMessage)\"")
      } catch {
        print(error)
      }
      
      let nodejsEd25519SignedMessage = "Example message signed with Ed25519 by nodejs";
      let nodejsEd25519SignatureBase64 = "1XsQpNGW7KFqlzZfRWNJgP5Z0tB+Gy4YcNlg40rhX4yfYiczW89p96g0QmlNlR6bdWCvD+0GVoE332WS6bl+Bw==";
      let verifyNodejsEd25519Signature = Crypto.Ed25519.verifyMessageSignatureFromNodejs(
        message: nodejsEd25519SignedMessage,
        nodejsSignatureBase64: nodejsEd25519SignatureBase64
      )
      print("\nEd25519 verification from nodejs is: \(verifyNodejsEd25519Signature)")
      
      let nodejsX25519EncryptedMessage = "/SLFTdIp27q2dbX2MAnJWG2dzHXSkbaUFDQtDNY3/m9EkTZnA++bMymO9/hDNtM6k6xgneFAWbLB78uPjB5HXd61a1Bk4xX6LEtQ4Ok6z34GkCWJXftKbJGIaJ9hjn4Nhcgv7gfZdOQnF9B1CQO7Sw==";
      let nodejsX25519EncryptedMessageSalt = "O/Xqrmu+SdgVkNy0UHZrLK/QM74aKDs89BJYzdipXb2g6667/6v9Vt/lo5SPxoRZm9h6YfrZUarYfV2XL1odzw==";
      do {
        let decryptedNodejsMessage = try Crypto.X25519.decryptMessageWithSymmetricKeyFromNodejs(
          encryptedMessage: nodejsX25519EncryptedMessage,
          symmetricKeySaltBase64: nodejsX25519EncryptedMessageSalt,
          privateKeyRepresentation: x25519keyRawRepresentationData
        )
        print("\nDecrypted nodejs X25519 message = \"\(decryptedNodejsMessage)\"")
      } catch {
        print(error)
      }
    }
  }
}
