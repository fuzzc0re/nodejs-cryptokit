# nodejs-cryptokit

Typescript package for easy interactions with Swift Cryptokit. It works for both symmetric and asymmetric key cryptography.

## Getting started

First you install the package with the following command:

```
npm i cryptokit
```

The user is expected to provide the passwords for the encrypted private keys in a .env file (which can be loaded with the dotenv package) with the following attributes:

```
P256_PASS=this_Must_Be_Changed
ED25519_PASS=this_Must_Be_Changed1
X25519_PASS=this_Must_Be_Changed2
```

The Ed25519 key pair is used for signatures and the X25519 pair to generate symmetric keys for encryption. The P256 key pair can be used for both.

To generate keys you do

```typescript
import path from "path";
import cryptokit from "cryptokit";

const P256FolderPath = path.join(__dirname, "keys", "P256");
const P256KeyPaths = cryptokit.P256.generateKeys(P256FolderPath);
console.log("P256 private key path = " + P256KeyPaths.privateKeyPath);
console.log("P256 public key path = " + P256KeyPaths.publicKeyPath);
```

There are equivalent functions for Ed25519 and X25519 keys.

## Loading keys

In order to load private and public keys as nodejs KeyObjects you do

```typescript
import path from "path";
import cryptokit from "cryptokit";

const P256PrivateKeyPath = path.join(__dirname, "keys", "P256", "private.key");
const P256PublicKeyPath = path.join(__dirname, "keys", "P256", "public.key");

const P256PrivateKey = cryptokit.P256.loadPrivateKey(P256PrivateKeyPath);
const P256PublicKey = cryptokit.P256.loadPublicKey(P256PublicKeyPath);
```

In order to convert the nodejs KeyObject to iOS compatible raw public key representation (without identifying headers) you do

```typescript
import cryptokit from "cryptokit";

const iOSCompatibleP256PublicKey = cryptokit.P256.formatPublicKeyToRaw(P256PublicKey);
console.log(iOSCompatibleP256PublicKey);
```

In order to load an iOS public key (raw representation) we have the helper method

```typescript
import cryptokit from "cryptokit";

// exmple iOS P256 key
const iOSP256PublicKeyRaw = "BDtr3giflhW7iplVoXZ2olz0lpsgyjChKsu22go+Nhm5TDk8dnwmMlm34uczZpjwd3x9NXO/oQWRuhEZF+95p3k=";

const iOSP256PublicKey = cryptokit.P256.formatRawToPublicKey(iOSP256PublicKeyRaw); // returns KeyObject
```

## Signing and verifying

In order to sign a message you do the following:

```typescript
import cryptokit from "cryptokit";

const message = "Some message to sign";

// the P256PrivateKeyObject from above
const signature = cryptokit.P256.sign(message, P256PrivateKey);
```

In order to verify a signature we need the message and the public key

```typescript
import cryptokit from "cryptokit";

const verification = cryptokit.P256.verify(message, signature, P256PublicKey);
```

## Encryption and decryption

In order to encrypt a message with symmetric key you do the following

```typescript
import cryptokit from "cryptokit";

const message = "Some message to encrypt";
const encrypted = cryptokit.P256.encrypt(message, P256PrivateKey, iOSP256PublicKey);
console.log(encrypted.message);
console.log(encrypted.symmetricKeySalt);
```

The result of the encryption function is a dictionary with the encrypted message buffer in base64 string format and the salt used for the symmetric key in base64 string format. You need to send the encrypted message as well as the salt to the device that will decrypt it.

The encrypted message is a buffer with an iv of length 12, an authentication tag of length 16 and a chachapoly cipher.

In order to decrypt a message you do

```typescript
import cryptokit from "cryptokit";

const decrypted = cryptokit.P256.decrypt(encrypted, P256PrivateKey, iOSP256PublicKey, encrypted.symmetricKeySalt);
```

You can see a full example, as well as a SwiftUI view to test the implementation in Swift.

## Licence

Copyright (c) 2020 Fuzznets P.C. All rights reserved.
