const { join } = require("path");
const { config } = require("dotenv");

config({ path: join(__dirname, ".env") });

const cryptokit = require("../lib/index");

const { iOSP256PublicKey, iOSEd25519PublicKey } = require("./keys/iOS");

// const P256Filepaths = cryptokit.P256.generateKeys(P256FolderPath);
// const Ed25519Filepaths = cryptokit.Ed25519.generateKeys(Ed25519FolderPath);

const P256FolderPath = join(__dirname, "keys", "P256");
const P256Filepaths = {
  privateKeyPath: join(P256FolderPath, "private.key"),
  publicKeyPath: join(P256FolderPath, "public.key"),
};
const P256PrivateKey = cryptokit.P256.loadPrivateKey(P256Filepaths.privateKeyPath);
const P256PublicKey = cryptokit.P256.loadPublicKey(P256Filepaths.publicKeyPath);

const iOSCompatibleP256PublicKey = cryptokit.P256.formatPublicKeyToRaw(P256PublicKey);
console.log("P256 iOS compatible public key = " + iOSCompatibleP256PublicKey + "\n");

const Ed25519FolderPath = join(__dirname, "keys", "Ed25519");
const Ed25519Filepaths = {
  privateKeyPath: join(Ed25519FolderPath, "private.key"),
  publicKeyPath: join(Ed25519FolderPath, "public.key"),
};
const Ed25519PrivateKey = cryptokit.Ed25519.loadPrivateKey(Ed25519Filepaths.privateKeyPath);
const Ed25519PublicKey = cryptokit.Ed25519.loadPublicKey(Ed25519Filepaths.publicKeyPath);

const iOSCompatibleEd25519PublicKey = cryptokit.Ed25519.formatPublicKeyToRaw(Ed25519PublicKey);
console.log("Ed25519 iOS compatible public key = " + iOSCompatibleEd25519PublicKey + "\n");

const messageToSignWithP256 = "Example message signed with P256 by nodejs";
const messageP256Signature = cryptokit.P256.sign(messageToSignWithP256, P256PrivateKey);
const messageP256SignatureVerification = cryptokit.P256.verify(
  messageToSignWithP256,
  messageP256Signature,
  P256PublicKey
);
console.log(
  'nodejsP256Signature = "' +
    messageP256Signature +
    '" whose verification was ' +
    messageP256SignatureVerification +
    " in nodejs.\n"
);

const messageToSignWithEd25519 = "Example message signed with Ed25519 by nodejs";
const messageEd25519Signature = cryptokit.Ed25519.sign(messageToSignWithEd25519, Ed25519PrivateKey);
const messageEd25519SignatureVerification = cryptokit.Ed25519.verify(
  messageToSignWithEd25519,
  messageEd25519Signature,
  Ed25519PublicKey
);
console.log(
  'nodejsEd25519Signature = "' +
    messageEd25519Signature +
    '" whose verification was ' +
    messageEd25519SignatureVerification +
    " in nodejs.\n"
);

// Test P256 iOS
const iOSP256SignedMessage = "Message to sign with P256 iOS";
const iOSP256MessageSignature =
  "MEUCIQDly41gOjZVYIMpsRoFUU7CfhXRFpLWjB4qRz86bR766gIgA+SmTXw3gE5lWgvA+LY9p7mqUaMmb6ACx4SWAY5tkuo=";
const verificationiOSP256Signature = cryptokit.P256.verify(
  iOSP256SignedMessage,
  iOSP256MessageSignature,
  iOSP256PublicKey
);
console.log("iOS P256 signature verification was: " + verificationiOSP256Signature + "\n");

// Test Ed25519 iOS
const iOSEd25519SignedMessage = "Message to sign with Ed25519 iOS";
const iOSEd25519MessageSignature =
  "P/vjunKl+bmBYiDKbf1KX6BKKH5k6neRVt2nvtAHet2eUg/k6L7+xZvLf+5Fu7FlfFjCy2BEhLKCW184CLuyAQ==";
const verificationiOSEd25519Signature = cryptokit.Ed25519.verify(
  iOSEd25519SignedMessage,
  iOSEd25519MessageSignature,
  iOSEd25519PublicKey
);
console.log("iOS Ed25519 verification was: " + verificationiOSEd25519Signature + "\n");
