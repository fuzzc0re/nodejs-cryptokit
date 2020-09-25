import { join } from "path";
import { config } from "dotenv";

import cryptokit from "../index";

import { iOSP256PublicKey, iOSX25519PublicKey } from "./keys/iOS.test";

config({ path: join(__dirname, ".env") });

const P256PrivateKeyContent = process.env.P256_PRIVATE_KEY as string;
const P256PublicKeyContent = process.env.P256_PUBLIC_KEY as string;

const Ed25519PrivateKeyContent = process.env.ED25519_PRIVATE_KEY as string;
const Ed25519PublicKeyContent = process.env.ED25519_PUBLIC_KEY as string;

const X25519PrivateKeyContent = process.env.X25519_PRIVATE_KEY as string;
const X25519PublicKeyContent = process.env.X25519_PUBLIC_KEY as string;

describe("Nodejs crypto test suite", () => {
  test("Sign with P256PrivateKey and verify with P256PublicKey", async () => {
    const P256PrivateKey = await cryptokit.P256.loadPrivateKey(P256PrivateKeyContent);
    const P256PublicKey = await cryptokit.P256.loadPublicKey(P256PublicKeyContent);

    const rawP256PublicKey = await cryptokit.P256.formatPublicKeyToRaw(P256PublicKey);
    console.log("Raw P256 public key to copy to iOS = " + rawP256PublicKey);

    const messageToSignWithP256 = "Example message signed with P256 by nodejs";
    const messageP256Signature = await cryptokit.P256.sign(messageToSignWithP256, P256PrivateKey);
    expect(await cryptokit.P256.verify(messageToSignWithP256, messageP256Signature, P256PublicKey)).toBe(true);
  });

  test("Sign with Ed25519PrivateKey and verify with Ed25519PublicKey", async () => {
    const Ed25519PrivateKey = await cryptokit.Ed25519.loadPrivateKey(Ed25519PrivateKeyContent);
    const Ed25519PublicKey = await cryptokit.Ed25519.loadPublicKey(Ed25519PublicKeyContent);

    const rawEd25519PublicKey = await cryptokit.Ed25519.formatPublicKeyToRaw(Ed25519PublicKey);
    console.log("Raw Ed25519 public key to copy to iOS = " + rawEd25519PublicKey);

    const messageToSignWithEd25519 = "Example message signed with Ed25519 by nodejs";
    const messageEd25519Signature = await cryptokit.Ed25519.sign(messageToSignWithEd25519, Ed25519PrivateKey);
    expect(await cryptokit.Ed25519.verify(messageToSignWithEd25519, messageEd25519Signature, Ed25519PublicKey)).toBe(
      true
    );
  });

  test("Encrypt with P256PrivateKey and iOSP256PublicKey symmetric key", async () => {
    const P256PrivateKey = await cryptokit.P256.loadPrivateKey(P256PrivateKeyContent);
    const iOSP256PublicKeyObject = await cryptokit.P256.loadPublicKey(iOSP256PublicKey);

    const messageToEncryptWithP256 =
      "Hi! I am an end-to-end encrypted example message from nodejs with symmetric P256 key";
    const encrypted = await cryptokit.P256.encrypt(messageToEncryptWithP256, P256PrivateKey, iOSP256PublicKeyObject);
    expect(encrypted.message).toEqual(expect.any(String));
  });

  test("Encrypt with X25519PrivateKey and iOSX25519PublicKey symmetric key", async () => {
    const X25519PrivateKey = await cryptokit.X25519.loadPrivateKey(X25519PrivateKeyContent);
    const iOSX25519PublicKeyObject = await cryptokit.X25519.loadPublicKey(iOSX25519PublicKey);

    const X25519PublicKey = await cryptokit.X25519.loadPublicKey(X25519PublicKeyContent);
    const rawX25519PublicKey = await cryptokit.X25519.formatPublicKeyToRaw(X25519PublicKey);
    console.log("Raw X25519 public key to copy to iOS = " + rawX25519PublicKey);

    const messageToEncryptWithX25519 =
      "Hi! I am an end-to-end encrypted example message from nodejs with symmetric P256 key";
    const encrypted = await cryptokit.X25519.encrypt(
      messageToEncryptWithX25519,
      X25519PrivateKey,
      iOSX25519PublicKeyObject
    );
    expect(encrypted.message).toEqual(expect.any(String));
  });
});
