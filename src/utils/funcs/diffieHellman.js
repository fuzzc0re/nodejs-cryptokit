const { diffieHellman } = require("crypto");

export function dh(publicKey, privateKey) {
  return diffieHellman({
    publicKey: publicKey,
    privateKey: privateKey,
  });
}
