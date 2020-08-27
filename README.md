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

To generate keys you can use the helper functions provided as follows:

```typescript
import { join } from "path";
import { utils } from "cryptokit";

const P256FolderPath = join(__dirname, "keys", "P256");
const P256KeyPaths = utils.generateP256Keys(P256FolderPath);
console.log("P256 private key path = " + P256KeyPaths.privateKeyPath);
console.log("P256 public key path = " + P256KeyPaths.publicKeyPath);
console.log("P256 public key asn1parse stdout = " + P256KeyPaths.asn1parse);
```

There are equivalent helper functions for Ed25519 and X25519 keys.

The asn1parse stdout contains the hexdump of the public keys. You need to copy the buffer and paste it into a swift Data([]) object with "0x" prefix on every element and commas.
For the P256 keys you need to remove the first two elements of the dump ("0x00" and the second). For the other two keys you just need to remove the first element ("0x00").

## Loading keys

There are also helper functions to load private and public keys as nodejs KeyObjects.

```typescript
import { join } from "path";
import { utils } from "cryptokit/utils";

const P256PrivateKeyPath = join(__dirname, "keys", "P256", "private.key");
const P256PublicKeyPath = join(__dirname, "keys", "P256", "public.key");

const P256PrivateKeyObject = utils.loadP256PrivateKeyObject(P256PrivateKeyPath);
const P256PublicKeyObject = utils.loadP256PublicKeyObject(P256PublicKeyPath);
```

In order to load an iOS public key we have the helper method

```typescript
import { formatiOSPublicKey } from "cryptokit";

// exmple iOS P256 key
const iOSP256PublicKey = "BDtr3giflhW7iplVoXZ2olz0lpsgyjChKsu22go+Nhm5TDk8dnwmMlm34uczZpjwd3x9NXO/oQWRuhEZF+95p3k=";

const iOSP256PublicKeyObject = formatiOSPublicKey(iOSP256PublicKey, "P256");
```

## Signing and verifying

In order to sign a message you do the following:

```typescript
import { signMessage } from "cryptokit";

const message = "Some message to sign";

// the P256PrivateKeyObject from above
const signature = signMessage(message, P256PrivateKeyObject);
```

In order to verify a signature we need the message and the public key

```typescript
import { verifyMessage } from "cryptokit";

const verification = verifyMessage(message, signature, P256PublicKeyObject);
```

## Encryption and decryption

In order to encrypt a message you do the following

```typescript
import { encryptWithSymmetricKey } from "cryptokit";

const message = "Some message to encrypt";
const encrypted = encryptWithSymmetricKey(message, P256PrivateKeyObject, iOSP256PublicKeyObject);
console.log(encrypted.message);
console.log(encrypted.symmetricKeySalt);
```

The result of the encryption function is a dictionary with the encrypted message buffer in base64 string format and the salt used for the symmetric key in base64 string format. You need to send the salt as well to the device that will decrypt this message.

The encrypted message is a buffer with an iv of length 12, an authentication tag of length 16 and a chachapoly cipher.

In order to decrypt a message you do

```typescript
import { decryptWithSymmetricKey } from "cryptokit";

const decrypted = decryptWithSymmetricKey(
  encrypted,
  P256PrivateKeyObject,
  iOSP256PublicKeyObject,
  encrypted.symmetricKeySalt
);
```

You can see a full example, as well as a SwiftUI view to test the implementation in Swift.

## Licence

Copyright (c) 2020 Fuzznets P.C. All rights reserved.
