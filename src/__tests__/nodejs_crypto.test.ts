import { join } from "path";
import { config } from "dotenv";

import cryptokit from "../index";

import { iOSP256PublicKeyObject, iOSX25519PublicKeyObject } from "./keys/iOS.test";

config({ path: join(__dirname, ".env") });

// const P256Filepaths = cryptokit.P256.generateKeys(P256FolderPath);
// const Ed25519Filepaths = cryptokit.Ed25519.generateKeys(Ed25519FolderPath);
// const X25519Filepaths = cryptokit.X25519.generateKeys(X25519FolderPath);
// Copy the BIT_STRING hex dumps and paste them as described in the swift model file

const P256FolderPath = join(__dirname, "keys", "P256");
const P256Filepaths = {
  privateKeyPath: join(P256FolderPath, "private.key"),
  publicKeyPath: join(P256FolderPath, "public.key"),
};
const P256PrivateKeyObject = cryptokit.P256.loadPrivateKey(P256Filepaths.privateKeyPath);
const P256PublicKey = cryptokit.P256.loadPublicKey(P256Filepaths.publicKeyPath);

const Ed25519FolderPath = join(__dirname, "keys", "Ed25519");
const Ed25519Filepaths = {
  privateKeyPath: join(Ed25519FolderPath, "private.key"),
  publicKeyPath: join(Ed25519FolderPath, "public.key"),
};
const Ed25519PrivateKeyObject = cryptokit.Ed25519.loadPrivateKey(Ed25519Filepaths.privateKeyPath);
const Ed25519PublicKey = cryptokit.Ed25519.loadPublicKey(Ed25519Filepaths.publicKeyPath);

const X25519FolderPath = join(__dirname, "keys", "X25519");
const X25519Filepaths = {
  privateKeyPath: join(X25519FolderPath, "private.key"),
  publicKeyPath: join(X25519FolderPath, "public.key"),
};
const X25519PrivateKeyObject = cryptokit.X25519.loadPrivateKey(X25519Filepaths.privateKeyPath);

describe("Nodejs crypto test suite", () => {
  test("Sign and verify nodejs P256", () => {
    const messageToSignWithP256 = "Example message signed with P256 by nodejs";
    const messageP256Signature = cryptokit.P256.sign(messageToSignWithP256, P256PrivateKeyObject);
    expect(cryptokit.P256.verify(messageToSignWithP256, messageP256Signature, P256PublicKey.object)).toBe(true);
  });

  test("Sign and verify nodejs Ed25519", () => {
    const messageToSignWithEd25519 = "Example message signed with Ed25519 by nodejs";
    const messageEd25519Signature = cryptokit.Ed25519.sign(messageToSignWithEd25519, Ed25519PrivateKeyObject);
    expect(cryptokit.Ed25519.verify(messageToSignWithEd25519, messageEd25519Signature, Ed25519PublicKey.object)).toBe(
      true
    );
  });

  test("Encrypt e2e with iOS P256", () => {
    const messageToEncryptWithP256 =
      "Hi! I am an end-to-end encrypted example message from nodejs with symmetric P256 key";
    expect(
      cryptokit.P256.encrypt(messageToEncryptWithP256, P256PrivateKeyObject, iOSP256PublicKeyObject).message
    ).toEqual(expect.any(String));
  });

  test("Encrypt e2e with iOS X25519", () => {
    const messageToEncryptWithX25519 =
      "Hi! I am an end-to-end encrypted example message from nodejs with symmetric P256 key";
    expect(
      cryptokit.X25519.encrypt(messageToEncryptWithX25519, X25519PrivateKeyObject, iOSX25519PublicKeyObject).message
    ).toEqual(expect.any(String));
  });
});
