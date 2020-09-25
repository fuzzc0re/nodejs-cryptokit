import { join } from "path";
import { config } from "dotenv";

import cryptokit from "../index";

import { iOSP256PublicKey, iOSEd25519PublicKey, iOSX25519PublicKey } from "./keys/iOS.test";

config({ path: join(__dirname, ".env") });

const P256PrivateKeyContent = process.env.P256_PRIVATE_KEY as string;
const X25519PrivateKeyContent = process.env.X25519_PRIVATE_KEY as string;

describe("Swift Cryptokit test suite", () => {
  test("Verify iOS P256 signature", async () => {
    const iOSP256SignedMessage = "Message to sign with P256 iOS";
    const iOSP256MessageSignature =
      "MEUCIGTP8UmIbl32UkvOsqwDrbxhRwdmSFo2zz4HDxWRO9vgAiEAzvO/MAzK/qlZN27yQbhIP9qBBIM8mO8/+rh49R2guB8=";
    const iOSP256PublicKeyObject = await cryptokit.P256.loadPublicKey(iOSP256PublicKey);
    expect(
      await cryptokit.P256.verify(iOSP256SignedMessage, iOSP256MessageSignature, iOSP256PublicKeyObject)
    ).toStrictEqual(true);
  });

  test("Verify iOS Ed25519 signature", async () => {
    const iOSEd25519SignedMessage = "Message to sign with Ed25519 iOS";
    const iOSEd25519MessageSignature =
      "pTryqXI+WZlcQeT6Nfxlz+FUBaalEs6ZTorfhHndE7GhINyLoikkJKkHh0/0yP/6u8QPlHECLU9zMP8NPW3UAw==";
    const iOSEd25519PublicKeyObject = await cryptokit.Ed25519.loadPublicKey(iOSEd25519PublicKey);
    expect(
      await cryptokit.Ed25519.verify(iOSEd25519SignedMessage, iOSEd25519MessageSignature, iOSEd25519PublicKeyObject)
    ).toStrictEqual(true);
  });

  test("Decrypt iOS message with P256 symmetric key", async () => {
    const P256PrivateKeyObject = await cryptokit.P256.loadPrivateKey(P256PrivateKeyContent);
    const iOSP256PublicKeyObject = await cryptokit.P256.loadPublicKey(iOSP256PublicKey);

    const iOSP256Message = "Hello! I am an encrypted iOS message with symmetric P256 key <3";
    const iOSP256EncryptedMessage =
      "ro4XWUC43Dwpinhy9K5mgD8tSNt73XMWlh4U7NDbzV0AxdUr8akmUis7cDCrxEFeJaD3YGq93GsBBQy7APT9QsZK72yw7mz+1/FZUkRmbsGy6KsbdkOVd0iX6g==";
    const iOSP256SymmetricKeySalt =
      "p3SxObu+ABqFOzf2k3hEoG9K192Qm0YSozUxPp3NY/WPq8qN8Y7nvEdL8dgH7KQ7Q1zqASVkJypD4wyb2p4eVw==";
    expect(
      await cryptokit.P256.decrypt(
        iOSP256EncryptedMessage,
        P256PrivateKeyObject,
        iOSP256PublicKeyObject,
        iOSP256SymmetricKeySalt
      )
    ).toStrictEqual(iOSP256Message);
  });

  test("Decrypt iOS message with X25519 symmetric key", async () => {
    const X25519PrivateKeyObject = await cryptokit.X25519.loadPrivateKey(X25519PrivateKeyContent);
    const iOSX25519PublicKeyObject = await cryptokit.X25519.loadPublicKey(iOSX25519PublicKey);

    const iOSX25519Message = "Hello! I am an encrypted iOS message with symmetric X25519 key <3";
    const iOSX25519EncryptedMessage =
      "58G4eZwNAOKJTikTuadmSSKsE0RrhGIsRMMfALo4ZhqzA4UOfy/Xs+V3R/mwU6ruXkfkOWS1fnt1pAkL9x2ZAPgmGJ3DcgGb7wwFK6T0kNyfKK4JXFt0eVVCa3MQ";
    const iOSX25519SymmetricKeySalt =
      "qq1LDIfBOEAJk50/tRaE+3UIsaBwO2AYD+ADGUBVnO3vQOATmlp5uzvg6TUN4Kw0HCEO10EPbf34iLVIgTzItw==";

    expect(
      await cryptokit.X25519.decrypt(
        iOSX25519EncryptedMessage,
        X25519PrivateKeyObject,
        iOSX25519PublicKeyObject,
        iOSX25519SymmetricKeySalt
      )
    ).toStrictEqual(iOSX25519Message);
  });
});
