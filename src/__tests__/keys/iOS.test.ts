import { KeyObject } from "crypto";

import cryptokit from "../../index";

export const iOSP256PublicKey =
  "BDtr3giflhW7iplVoXZ2olz0lpsgyjChKsu22go+Nhm5TDk8dnwmMlm34uczZpjwd3x9NXO/oQWRuhEZF+95p3k=";
// export const iOSP256PublicKeyObject = await cryptokit.P256.loadPublicKey(iOSP256PublicKey);

export const iOSEd25519PublicKey = "+QNqahcKDGZFr3IErZjOwew+A5UyvZaX5BJX2OxOIsg=";
// export const iOSEd25519PublicKeyObject = await cryptokit.Ed25519.loadPublicKey(iOSEd25519PublicKey);

export const iOSX25519PublicKey = "Ms3HkYAK+eLgXBdTSDbWs6PWa6uE2Y+4b9fspmge7GM=";
// export const iOSX25519PublicKeyObject = await cryptokit.X25519.loadPublicKey(iOSX25519PublicKey);

describe("iOS Public key format", () => {
  test("P256 public key formatter", async () => {
    expect(await cryptokit.P256.loadPublicKey(iOSP256PublicKey)).toEqual(expect.any(KeyObject));
  });

  test("Ed25519 public key formatter", async () => {
    expect(await cryptokit.Ed25519.loadPublicKey(iOSEd25519PublicKey)).toEqual(expect.any(KeyObject));
  });

  test("P256 public key formatter", async () => {
    expect(await cryptokit.X25519.loadPublicKey(iOSX25519PublicKey)).toEqual(expect.any(KeyObject));
  });
});
