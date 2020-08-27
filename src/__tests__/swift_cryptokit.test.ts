import { join } from "path";
import { config } from "dotenv";

import cryptokit from "../index";

import { iOSP256PublicKeyObject, iOSEd25519PublicKeyObject, iOSX25519PublicKeyObject } from "./keys/iOS.test";

config({ path: join(__dirname, ".env") });

// const P256Filepaths = generateP256Keys(P256FolderPath);
// const X25519Filepaths = generateX25519Keys(X25519FolderPath);
// Copy the BIT_STRING hex dumps and paste them as described in the swift model file

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

describe("Swift Cryptokit test suite", () => {
  const iOSP256SignedMessage = "Message to sign with P256 iOS";
  const iOSP256MessageSignature =
    "MEUCIQDly41gOjZVYIMpsRoFUU7CfhXRFpLWjB4qRz86bR766gIgA+SmTXw3gE5lWgvA+LY9p7mqUaMmb6ACx4SWAY5tkuo=";
  test("Verify iOS P256 signature", () => {
    expect(cryptokit.P256.verify(iOSP256SignedMessage, iOSP256MessageSignature, iOSP256PublicKeyObject)).toStrictEqual(
      true
    );
  });

  test("Verify iOS Ed25519 signature", () => {
    const iOSEd25519SignedMessage = "Message to sign with Ed25519 iOS";
    const iOSEd25519MessageSignature =
      "P/vjunKl+bmBYiDKbf1KX6BKKH5k6neRVt2nvtAHet2eUg/k6L7+xZvLf+5Fu7FlfFjCy2BEhLKCW184CLuyAQ==";
    expect(
      cryptokit.Ed25519.verify(iOSEd25519SignedMessage, iOSEd25519MessageSignature, iOSEd25519PublicKeyObject)
    ).toStrictEqual(true);
  });

  test("Decrypt iOS message with P256 symmetric key", () => {
    const iOSP256Message = "Hello! I am an encrypted iOS message with symmetric P256 key <3";
    const iOSP256EncryptedMessage =
      "4LXIVazlAnPGCgheXgQK1N4neJfDChwTWKyV5ElyeMRmPAoWDtYoh1q2seeUNmd3xbavsLqGEPtPOxqPKMEOV5gu20tKOwNMX5sMGsZm1gStBBQkqNaktv52Iw==";
    const iOSP256SymmetricKeySalt = "Gfb/vwvj0Dmaxt5UqhZ6Gg==";
    expect(
      cryptokit.P256.decrypt(
        iOSP256EncryptedMessage,
        P256PrivateKeyObject,
        iOSP256PublicKeyObject,
        iOSP256SymmetricKeySalt
      )
    ).toStrictEqual(iOSP256Message);
  });

  test("Decrypt iOS message with X25519 symmetric key", () => {
    const iOSX25519Message = "Hello! I am an encrypted iOS message with symmetric X25519 key <3";
    const iOSX25519EncryptedMessage =
      "XfDimHc0LYyoZI/M3ogX81G0ndsFBV1BAONxoX1pX4Il5M6X0dMQvtiuxj4V4K0HQOBBNRK+m+5PhQG1rz7PYW2bNzT2FWHnrPDu4qrzt2gGSK4ShG5jiynCO9qR";
    const iOSX25519SymmetricKeySalt = "gfSsGl0yvkNQaJHXw/WLvw==";
    expect(
      cryptokit.X25519.decrypt(
        iOSX25519EncryptedMessage,
        X25519PrivateKeyObject,
        iOSX25519PublicKeyObject,
        iOSX25519SymmetricKeySalt
      )
    ).toStrictEqual(iOSX25519Message);
  });
});
