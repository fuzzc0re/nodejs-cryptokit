const { join } = require("path");
const { readFileSync } = require("fs");
const { config } = require("dotenv");

config({ path: join(__dirname, ".env") });

const cryptokit = require("../lib/index");

const { iOSP256PublicKeyRaw, iOSEd25519PublicKeyRaw } = require("./keys/iOS");

const P256FolderPath = join(__dirname, "keys", "P256");
const P256Filepaths = {
  privateKeyPath: join(P256FolderPath, "private.key"),
  publicKeyPath: join(P256FolderPath, "public.key"),
};
const P256PrivateKeyContent = readFileSync(P256Filepaths.privateKeyPath, "utf8");
const P256PublicKeyContent = readFileSync(P256Filepaths.publicKeyPath, "utf8");

const Ed25519FolderPath = join(__dirname, "keys", "Ed25519");
const Ed25519Filepaths = {
  privateKeyPath: join(Ed25519FolderPath, "private.key"),
  publicKeyPath: join(Ed25519FolderPath, "public.key"),
};
const Ed25519PrivateKeyContent = readFileSync(Ed25519Filepaths.privateKeyPath, "utf8");
const Ed25519PublicKeyContent = readFileSync(Ed25519Filepaths.publicKeyPath, "utf8");

const messageToSignWithP256 = "Example message signed with P256 by nodejs";

const messageToSignWithEd25519 = "Example message signed with Ed25519 by nodejs";

const iOSP256SignedMessage = "Message to sign with P256 iOS";
const iOSP256MessageSignature =
  "MEUCIGTP8UmIbl32UkvOsqwDrbxhRwdmSFo2zz4HDxWRO9vgAiEAzvO/MAzK/qlZN27yQbhIP9qBBIM8mO8/+rh49R2guB8=";

const iOSEd25519SignedMessage = "Message to sign with Ed25519 iOS";
const iOSEd25519MessageSignature =
  "pTryqXI+WZlcQeT6Nfxlz+FUBaalEs6ZTorfhHndE7GhINyLoikkJKkHh0/0yP/6u8QPlHECLU9zMP8NPW3UAw==";

async function exampleSignatures() {
  try {
    const P256PrivateKey = await cryptokit.P256.loadPrivateKey(P256PrivateKeyContent);
    const P256PublicKey = await cryptokit.P256.loadPublicKey(P256PublicKeyContent);

    const Ed25519PrivateKey = await cryptokit.Ed25519.loadPrivateKey(Ed25519PrivateKeyContent);
    const Ed25519PublicKey = await cryptokit.Ed25519.loadPublicKey(Ed25519PublicKeyContent);

    const iOSCompatibleP256PublicKey = await cryptokit.P256.formatPublicKeyToRaw(P256PublicKey);
    console.log("P256 iOS compatible public key = " + iOSCompatibleP256PublicKey + "\n");

    const iOSCompatibleEd25519PublicKey = await cryptokit.Ed25519.formatPublicKeyToRaw(Ed25519PublicKey);
    console.log("Ed25519 iOS compatible public key = " + iOSCompatibleEd25519PublicKey + "\n");

    const messageP256Signature = await cryptokit.P256.sign(messageToSignWithP256, P256PrivateKey);
    const messageP256SignatureVerification = await cryptokit.P256.verify(
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

    const messageEd25519Signature = await cryptokit.Ed25519.sign(messageToSignWithEd25519, Ed25519PrivateKey);
    const messageEd25519SignatureVerification = await cryptokit.Ed25519.verify(
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

    const iOSP256PublicKey = await cryptokit.P256.loadPublicKey(iOSP256PublicKeyRaw);
    const verificationiOSP256Signature = await cryptokit.P256.verify(
      iOSP256SignedMessage,
      iOSP256MessageSignature,
      iOSP256PublicKey
    );
    console.log("iOS P256 signature verification was: " + verificationiOSP256Signature + "\n");

    const iOSEd25519PublicKey = await cryptokit.Ed25519.loadPublicKey(iOSEd25519PublicKeyRaw);
    const verificationiOSEd25519Signature = await cryptokit.Ed25519.verify(
      iOSEd25519SignedMessage,
      iOSEd25519MessageSignature,
      iOSEd25519PublicKey
    );
    console.log("iOS Ed25519 verification was: " + verificationiOSEd25519Signature + "\n");
  } catch (error) {
    throw error;
  }
}

exampleSignatures();
