import { join } from "path";
import { config } from "dotenv";

import { signMessage, verifySignature, encryptWithSymmetricKey } from "../index";

import {
  // generateP256Keys,
  loadP256PublicKeyObject,
  loadP256PrivateKeyObject,
} from "../utils/P256";
import {
  // generateEd25519Keys,
  loadEd25519PublicKeyObject,
  loadEd25519PrivateKeyObject,
} from "../utils/Ed25519";
import {
  // generateX25519Keys,
  loadX25519PrivateKeyObject,
} from "../utils/X25519";
import { iOSP256PublicKeyObject, iOSX25519PublicKeyObject } from "./keys/iOS.test";

config({ path: join(__dirname, ".env") });

// const P256Filepaths = generateP256Keys(P256FolderPath);
// const Ed25519Filepaths = generateEd25519Keys(Ed25519FolderPath);
// const X25519Filepaths = generateX25519Keys(X25519FolderPath);
// Copy the BIT_STRING hex dumps and paste them as described in the swift model file

const P256FolderPath = join(__dirname, "keys", "P256");
const P256Filepaths = {
  privateKeyPath: join(P256FolderPath, "private.key"),
  publicKeyPath: join(P256FolderPath, "public.key"),
};
const P256PrivateKeyObject = loadP256PrivateKeyObject(P256Filepaths.privateKeyPath);
const P256PublicKeyObject = loadP256PublicKeyObject(P256Filepaths.publicKeyPath);

const Ed25519FolderPath = join(__dirname, "keys", "Ed25519");
const Ed25519Filepaths = {
  privateKeyPath: join(Ed25519FolderPath, "private.key"),
  publicKeyPath: join(Ed25519FolderPath, "public.key"),
};
const Ed25519PrivateKeyObject = loadEd25519PrivateKeyObject(Ed25519Filepaths.privateKeyPath);
const Ed25519PublicKeyObject = loadEd25519PublicKeyObject(Ed25519Filepaths.publicKeyPath);

const X25519FolderPath = join(__dirname, "keys", "X25519");
const X25519Filepaths = {
  privateKeyPath: join(X25519FolderPath, "private.key"),
  publicKeyPath: join(X25519FolderPath, "public.key"),
};
const X25519PrivateKeyObject = loadX25519PrivateKeyObject(X25519Filepaths.privateKeyPath);

describe("Nodejs crypto test suite", () => {
  test("Sign and verify nodejs P256", () => {
    const messageToSignWithP256 = "Example message signed with P256 by nodejs";
    const messageP256Signature = signMessage(messageToSignWithP256, P256PrivateKeyObject);
    expect(verifySignature(messageToSignWithP256, messageP256Signature, P256PublicKeyObject)).toBe(true);
  });

  test("Sign and verify nodejs Ed25519", () => {
    const messageToSignWithEd25519 = "Example message signed with Ed25519 by nodejs";
    const messageEd25519Signature = signMessage(messageToSignWithEd25519, Ed25519PrivateKeyObject);
    expect(verifySignature(messageToSignWithEd25519, messageEd25519Signature, Ed25519PublicKeyObject)).toBe(true);
  });

  test("Encrypt e2e with iOS P256", () => {
    const messageToEncryptWithP256 =
      "Hi! I am an end-to-end encrypted example message from nodejs with symmetric P256 key";
    expect(
      encryptWithSymmetricKey(messageToEncryptWithP256, P256PrivateKeyObject, iOSP256PublicKeyObject).message
    ).toEqual(expect.any(String));
  });

  test("Encrypt e2e with iOS X25519", () => {
    const messageToEncryptWithX25519 =
      "Hi! I am an end-to-end encrypted example message from nodejs with symmetric P256 key";
    expect(
      encryptWithSymmetricKey(messageToEncryptWithX25519, X25519PrivateKeyObject, iOSX25519PublicKeyObject).message
    ).toEqual(expect.any(String));
  });
});
