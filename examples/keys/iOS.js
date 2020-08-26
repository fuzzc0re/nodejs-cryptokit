const { formatiOSPublicKey } = require("../../lib/index");

const iOSP256PublicKey = "BDtr3giflhW7iplVoXZ2olz0lpsgyjChKsu22go+Nhm5TDk8dnwmMlm34uczZpjwd3x9NXO/oQWRuhEZF+95p3k=";
const iOSP256PublicKeyObject = formatiOSPublicKey(iOSP256PublicKey, "P256");

const iOSEd25519PublicKey = "+QNqahcKDGZFr3IErZjOwew+A5UyvZaX5BJX2OxOIsg=";
const iOSEd25519PublicKeyObject = formatiOSPublicKey(iOSEd25519PublicKey, "Ed25519");

const iOSX25519PublicKey = "Ms3HkYAK+eLgXBdTSDbWs6PWa6uE2Y+4b9fspmge7GM=";
const iOSX25519PublicKeyObject = formatiOSPublicKey(iOSX25519PublicKey, "X25519");

module.exports = {
  iOSP256PublicKeyObject,
  iOSEd25519PublicKeyObject,
  iOSX25519PublicKeyObject,
};
