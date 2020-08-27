const { join } = require("path");
const { config } = require("dotenv");

config({ path: join(__dirname, ".env") });

const { utils, signMessage, verifySignature } = require("../lib/index");

const { iOSP256PublicKeyObject, iOSEd25519PublicKeyObject } = require("./keys/iOS");

// const P256Filepaths = utils.generateP256Keys(P256FolderPath);
// const Ed25519Filepaths = utils.generateEd25519Keys(Ed25519FolderPath);

const P256FolderPath = join(__dirname, "keys", "P256");
const P256Filepaths = {
  privateKeyPath: join(P256FolderPath, "private.key"),
  publicKeyPath: join(P256FolderPath, "public.key"),
};
const P256PrivateKeyObject = utils.loadP256PrivateKeyObject(P256Filepaths.privateKeyPath);
const P256PublicKeyObject = utils.loadP256PublicKeyObject(P256Filepaths.publicKeyPath);

const Ed25519FolderPath = join(__dirname, "keys", "Ed25519");
const Ed25519Filepaths = {
  privateKeyPath: join(Ed25519FolderPath, "private.key"),
  publicKeyPath: join(Ed25519FolderPath, "public.key"),
};
const Ed25519PrivateKeyObject = utils.loadEd25519PrivateKeyObject(Ed25519Filepaths.privateKeyPath);
const Ed25519PublicKeyObject = utils.loadEd25519PublicKeyObject(Ed25519Filepaths.publicKeyPath);

const messageToSignWithP256 = "Example message signed with P256 by nodejs";
const messageP256Signature = signMessage(messageToSignWithP256, P256PrivateKeyObject);
const messageP256SignatureVerification = verifySignature(
  messageToSignWithP256,
  messageP256Signature,
  P256PublicKeyObject
);
console.log(
  'nodejsP256Signature = "' +
    messageP256Signature +
    '" whose verification was ' +
    messageP256SignatureVerification +
    " in nodejs.\n"
);

const messageToSignWithEd25519 = "Example message signed with Ed25519 by nodejs";
const messageEd25519Signature = signMessage(messageToSignWithEd25519, Ed25519PrivateKeyObject);
const messageEd25519SignatureVerification = verifySignature(
  messageToSignWithEd25519,
  messageEd25519Signature,
  Ed25519PublicKeyObject
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
const verification_iOS_P256_Signature = verifySignature(
  iOSP256SignedMessage,
  iOSP256MessageSignature,
  iOSP256PublicKeyObject
);
console.log("iOS P256 signature verification was: " + verification_iOS_P256_Signature + "\n");

// Test Ed25519 iOS
const iOSEd25519SignedMessage = "Message to sign with Ed25519 iOS";
const iOSEd25519MessageSignature =
  "P/vjunKl+bmBYiDKbf1KX6BKKH5k6neRVt2nvtAHet2eUg/k6L7+xZvLf+5Fu7FlfFjCy2BEhLKCW184CLuyAQ==";
const verification_iOS_Ed25519_Signature = verifySignature(
  iOSEd25519SignedMessage,
  iOSEd25519MessageSignature,
  iOSEd25519PublicKeyObject
);
console.log("iOS Ed25519 verification was: " + verification_iOS_Ed25519_Signature + "\n");
