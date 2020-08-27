const cryptokit = require("../../lib/index");

const iOSP256PublicKey = "BDtr3giflhW7iplVoXZ2olz0lpsgyjChKsu22go+Nhm5TDk8dnwmMlm34uczZpjwd3x9NXO/oQWRuhEZF+95p3k=";
const iOSP256PublicKeyObject = cryptokit.P256.formatiOSPublicKey(iOSP256PublicKey);

const iOSEd25519PublicKey = "+QNqahcKDGZFr3IErZjOwew+A5UyvZaX5BJX2OxOIsg=";
const iOSEd25519PublicKeyObject = cryptokit.Ed25519.formatiOSPublicKey(iOSEd25519PublicKey);

const iOSX25519PublicKey = "Ms3HkYAK+eLgXBdTSDbWs6PWa6uE2Y+4b9fspmge7GM=";
const iOSX25519PublicKeyObject = cryptokit.X25519.formatiOSPublicKey(iOSX25519PublicKey);

module.exports = {
  iOSP256PublicKeyObject,
  iOSEd25519PublicKeyObject,
  iOSX25519PublicKeyObject,
};
