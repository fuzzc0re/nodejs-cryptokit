# nodejs-cryptokit

Typescript package for easy interactions with Swift Cryptokit. It works for both symmetric and asymmetric key cryptography.

## Getting started

First you install the package with the following command:

```
npm i cryptokit
```

The user can provide the passwords for the encrypted private keys in a .env file (which can be loaded with the dotenv package) with the following attributes:

```
P256_PASS=this_Must_Be_Changed
ED25519_PASS=this_Must_Be_Changed1
X25519_PASS=this_Must_Be_Changed2
```

There is also the option to provide a password on key generation and on private key loading.

The Ed25519 key pair is used for signatures and the X25519 pair to generate symmetric keys for encryption. The P256 key pair can be used for both.

To generate keys you do

```typescript
import cryptokit from "cryptokit";

async function app() {
  const P256Password = "some long random string";
  const P256Keys = await cryptokit.P256.generateKeys(P256Password);

  console.log("P256 private key (encrypted)= " + P256Keys.privateKey);
  console.log("P256 public key = " + P256Keys.publicKey);
}

app();
```

The P256 private key is encrypted with AES-256-CTR and the output is in 'sec1' format.
The P256 public key is in 'spki' format.

There are also equivalent functions for Ed25519 and X25519 keys. Their private key output is encrypted
with AES-256-GCM. It is a base64-encoded string representing an array buffer comprised of a keySalt,
an iv, the encrypted content buffer and the authTag.

## Loading keys

In order to load private and public keys as nodejs KeyObjects you do

```typescript
import cryptokit from "cryptokit";

async function app() {
  //
  // Previous code
  //

  const P256PrivateKey = await cryptokit.P256.loadPrivateKey(P256Keys.privateKey, P256Password);
  const P256PublicKey = await cryptokit.P256.loadPublicKey(P256Keys.publicKey);
}

app();
```

The P256.loadPrivateKey() function expects the encrypted key in 'sec1' format. The equivalent
Ed25519.loadPrivateKey() and X25519.loadPrivateKey() methods expect the base64-encoded string described above,
they decrypt it and they output the KeyObject.

Swift Cryptokit expects the public keys to be in raw format (without identifying headers).
In order to convert the nodejs KeyObject to raw public key base64 representation you do

```typescript
import cryptokit from "cryptokit";

async function app() {
  //
  // Previous code
  //

  const iOSCompatibleP256PublicKey = await cryptokit.P256.formatPublicKeyToRaw(P256PublicKey);
  console.log("iOS compatible P256 raw public key = " + iOSCompatibleP256PublicKey);
}

app();
```

The loadPublicKey() methods accept PEM-formatted spki public keys, raw public keys
and DER-formatted spki public keys.

```typescript
import cryptokit from "cryptokit";

async function app() {
  //
  // Previous code
  //

  const iOSP256PublicKeyRawRepresentation =
    "BDtr3giflhW7iplVoXZ2olz0lpsgyjChKsu22go+Nhm5TDk8dnwmMlm34uczZpjwd3x9NXO/oQWRuhEZF+95p3k=";

  const iOSP256PublicKey = await cryptokit.P256.loadPublicKey(iOSP256PublicKeyRawRepresentation);
}

app();
```

## Signing and verifying

In order to sign a message and verify the signature you do the following:

```typescript
import cryptokit from "cryptokit";

async function app() {
  //
  // Previous code
  //

  const messageToSign = "Some message to sign";

  const signature = await cryptokit.P256.sign(messageToSign, P256PrivateKey);
  const verification = await cryptokit.P256.verify(messaToSign, signature, P256PublicKey);
}

app();
```

## Encryption and decryption

In order to encrypt and decrypt a message with symmetric key you do the following

```typescript
import cryptokit from "cryptokit";

import cryptokit from "cryptokit";

async function app() {
  //
  // Previous code
  //

  const messageToEncrypt = "Some message to encrypt";
  const encrypted = await cryptokit.P256.encrypt(message, P256PrivateKey, iOSP256PublicKey);
  console.log(encrypted.message);
  console.log(encrypted.symmetricKeySalt);
  const decrypted = await cryptokit.P256.decrypt(
    encrypted,
    P256PrivateKey,
    iOSP256PublicKey,
    encrypted.symmetricKeySalt
  );
  console.log("Decrypted = " + decrypted);
}

app();
```

The result of the encryption function is a dictionary with the encrypted message buffer in base64 string format and the salt used for the symmetric key generation in base64 string format. You need to send the encrypted message as well as the salt to the device that will decrypt it.

The encrypted message is a buffer with an iv of length 12, an authentication tag of length 16 and a chachapoly cipher.

## Examples

You can see a full example, as well as a SwiftUI view to test the implementation in Swift.

## Licence

Copyright (c) 2020 Fuzznets P.C. All rights reserved.
