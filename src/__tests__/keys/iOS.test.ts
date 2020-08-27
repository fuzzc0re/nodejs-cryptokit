import { KeyObject } from "crypto";

import cryptokit from "../../index";

const iOSP256PublicKey = "BDtr3giflhW7iplVoXZ2olz0lpsgyjChKsu22go+Nhm5TDk8dnwmMlm34uczZpjwd3x9NXO/oQWRuhEZF+95p3k=";
export const iOSP256PublicKeyObject = cryptokit.P256.formatiOSPublicKey(iOSP256PublicKey);

const iOSEd25519PublicKey = "+QNqahcKDGZFr3IErZjOwew+A5UyvZaX5BJX2OxOIsg=";
export const iOSEd25519PublicKeyObject = cryptokit.Ed25519.formatiOSPublicKey(iOSEd25519PublicKey);

const iOSX25519PublicKey = "Ms3HkYAK+eLgXBdTSDbWs6PWa6uE2Y+4b9fspmge7GM=";
export const iOSX25519PublicKeyObject = cryptokit.X25519.formatiOSPublicKey(iOSX25519PublicKey);

describe("iOS Public key format", () => {
  test("P256 public key formatter", () => {
    expect(cryptokit.P256.formatiOSPublicKey(iOSP256PublicKey)).toEqual(expect.any(KeyObject));
  });

  test("Ed25519 public key formatter", () => {
    expect(cryptokit.Ed25519.formatiOSPublicKey(iOSEd25519PublicKey)).toEqual(expect.any(KeyObject));
  });

  test("P256 public key formatter", () => {
    expect(cryptokit.X25519.formatiOSPublicKey(iOSX25519PublicKey)).toEqual(expect.any(KeyObject));
  });
});
