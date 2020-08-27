const { join } = require("path");
const { config } = require("dotenv");

config({ path: join(__dirname, ".env") });

const cryptokit = require("../lib/index");

const { iOSP256PublicKeyObject, iOSX25519PublicKeyObject } = require("./keys/iOS");

// const P256Filepaths = utils.generateP256Keys(P256FolderPath);
// const X25519Filepaths = utils.generateX25519Keys(X25519FolderPath);

const P256FolderPath = join(__dirname, "keys", "P256");
const P256Filepaths = {
  privateKeyPath: join(P256FolderPath, "private.key"),
  publicKeyPath: join(P256FolderPath, "public.key"),
};
const P256PrivateKeyObject = cryptokit.P256.loadPrivateKey(P256Filepaths.privateKeyPath);

const X25519FolderPath = join(__dirname, "keys", "X25519");
const X25519Filepaths = {
  privateKeyPath: join(X25519FolderPath, "private.key"),
  publicKeyPath: join(X25519FolderPath, "public.key"),
};
const X25519PrivateKeyObject = cryptokit.X25519.loadPrivateKey(X25519Filepaths.privateKeyPath);

// Test P256 iOS
const messageToEncryptWithP256 = "Hi! I am an end-to-end encrypted example message from nodejs with symmetric P256 key";
const encryptedMessageWithP256 = cryptokit.P256.encrypt(
  messageToEncryptWithP256,
  P256PrivateKeyObject,
  iOSP256PublicKeyObject
);
console.log('Nodejs encrypted message with P256 = "' + encryptedMessageWithP256.message + '"\n');
console.log('Nodejs P256 Encrypted message salt = "' + encryptedMessageWithP256.symmetricKeySalt + '"\n');

const iOSP256EncryptedMessage =
  "4LXIVazlAnPGCgheXgQK1N4neJfDChwTWKyV5ElyeMRmPAoWDtYoh1q2seeUNmd3xbavsLqGEPtPOxqPKMEOV5gu20tKOwNMX5sMGsZm1gStBBQkqNaktv52Iw==";
const iOSP256SymmetricKeySalt = "Gfb/vwvj0Dmaxt5UqhZ6Gg==";
const decryptediOSP256Message = cryptokit.P256.decrypt(
  iOSP256EncryptedMessage,
  P256PrivateKeyObject,
  iOSP256PublicKeyObject,
  iOSP256SymmetricKeySalt
);
console.log('Decrypted iOS P256 message = "' + decryptediOSP256Message + '"\n');

// Test X25519 iOS
const messageToEncryptWithX25519 =
  "Hi! I am an end-to-end encrypted example message from nodejs with symmetric P256 key";
const encryptedMessageWithX25519 = cryptokit.X25519.encrypt(
  messageToEncryptWithX25519,
  X25519PrivateKeyObject,
  iOSX25519PublicKeyObject
);
console.log('Nodejs encrypted message with X25519: "' + encryptedMessageWithX25519.message + '"\n');
console.log('Nodejs X25519 encrypted message salt: "' + encryptedMessageWithX25519.symmetricKeySalt + '"\n');

const iOSX25519EncryptedMessage =
  "XfDimHc0LYyoZI/M3ogX81G0ndsFBV1BAONxoX1pX4Il5M6X0dMQvtiuxj4V4K0HQOBBNRK+m+5PhQG1rz7PYW2bNzT2FWHnrPDu4qrzt2gGSK4ShG5jiynCO9qR";
const iOSX25519SymmetricKeySalt = "gfSsGl0yvkNQaJHXw/WLvw==";
const decryptediOSX25519Message = cryptokit.X25519.decrypt(
  iOSX25519EncryptedMessage,
  X25519PrivateKeyObject,
  iOSX25519PublicKeyObject,
  iOSX25519SymmetricKeySalt
);
console.log('Decrypted iOS X25519 message = "' + decryptediOSX25519Message + '"\n');
