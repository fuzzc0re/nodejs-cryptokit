import { KeyObject } from "crypto";

import { formatiOSPublicKey } from "../../index";

const iOSP256PublicKey = "BDtr3giflhW7iplVoXZ2olz0lpsgyjChKsu22go+Nhm5TDk8dnwmMlm34uczZpjwd3x9NXO/oQWRuhEZF+95p3k=";
export const iOSP256PublicKeyObject = formatiOSPublicKey(iOSP256PublicKey, "P256");

const iOSEd25519PublicKey = "+QNqahcKDGZFr3IErZjOwew+A5UyvZaX5BJX2OxOIsg=";
export const iOSEd25519PublicKeyObject = formatiOSPublicKey(iOSEd25519PublicKey, "Ed25519");

const iOSX25519PublicKey = "Ms3HkYAK+eLgXBdTSDbWs6PWa6uE2Y+4b9fspmge7GM=";
export const iOSX25519PublicKeyObject = formatiOSPublicKey(iOSX25519PublicKey, "X25519");

describe("iOS Public key format", () => {
  test("P256 public key formatter", () => {
    expect(formatiOSPublicKey(iOSP256PublicKey, "P256")).toEqual(expect.any(KeyObject));
  });

  test("Ed25519 public key formatter", () => {
    expect(formatiOSPublicKey(iOSEd25519PublicKey, "Ed25519")).toEqual(expect.any(KeyObject));
  });

  test("P256 public key formatter", () => {
    expect(formatiOSPublicKey(iOSX25519PublicKey, "X25519")).toEqual(expect.any(KeyObject));
  });
});
