const { join } = require("path");
const { config } = require("dotenv");

config({ path: join(__dirname, ".env") });

const cryptokit = require("../lib/index");

const { iOSP256PublicKeyRaw, iOSX25519PublicKeyRaw } = require("./keys/iOS");

const messageToEncryptWithP256 = "Hi! I am an end-to-end encrypted example message from nodejs with symmetric P256 key";

const messageToEncryptWithX25519 =
  "Hi! I am an end-to-end encrypted example message from nodejs with symmetric P256 key";

const iOSP256EncryptedMessage =
  "ro4XWUC43Dwpinhy9K5mgD8tSNt73XMWlh4U7NDbzV0AxdUr8akmUis7cDCrxEFeJaD3YGq93GsBBQy7APT9QsZK72yw7mz+1/FZUkRmbsGy6KsbdkOVd0iX6g==";
const iOSP256SymmetricKeySalt =
  "p3SxObu+ABqFOzf2k3hEoG9K192Qm0YSozUxPp3NY/WPq8qN8Y7nvEdL8dgH7KQ7Q1zqASVkJypD4wyb2p4eVw==";

const iOSX25519EncryptedMessage =
  "58G4eZwNAOKJTikTuadmSSKsE0RrhGIsRMMfALo4ZhqzA4UOfy/Xs+V3R/mwU6ruXkfkOWS1fnt1pAkL9x2ZAPgmGJ3DcgGb7wwFK6T0kNyfKK4JXFt0eVVCa3MQ";
const iOSX25519SymmetricKeySalt =
  "qq1LDIfBOEAJk50/tRaE+3UIsaBwO2AYD+ADGUBVnO3vQOATmlp5uzvg6TUN4Kw0HCEO10EPbf34iLVIgTzItw==";

async function e2eEncryption() {
  try {
    const P256PrivateKey = await cryptokit.P256.loadPrivateKey(process.env.P256_PRIVATE_KEY);
    const iOSP256PublicKey = await cryptokit.P256.loadPublicKey(iOSP256PublicKeyRaw);
    const encryptedMessageWithP256 = await cryptokit.P256.encrypt(
      messageToEncryptWithP256,
      P256PrivateKey,
      iOSP256PublicKey
    );
    console.log('Nodejs encrypted message with P256 = "' + encryptedMessageWithP256.message + '"\n');
    console.log('Nodejs P256 Encrypted message salt = "' + encryptedMessageWithP256.symmetricKeySalt + '"\n');

    const X25519PublicKey = await cryptokit.X25519.loadPublicKey(process.env.X25519_PUBLIC_KEY);
    const iOSCompatibleX25519PublicKey = await cryptokit.X25519.formatPublicKeyToRaw(X25519PublicKey);
    console.log("iOS Compatible X25519 public key = " + iOSCompatibleX25519PublicKey);

    const X25519PrivateKey = await cryptokit.X25519.loadPrivateKey(process.env.X25519_PRIVATE_KEY);
    const iOSX25519PublicKey = await cryptokit.X25519.loadPublicKey(iOSX25519PublicKeyRaw);
    const encryptedMessageWithX25519 = await cryptokit.X25519.encrypt(
      messageToEncryptWithX25519,
      X25519PrivateKey,
      iOSX25519PublicKey
    );
    console.log('Nodejs encrypted message with X25519: "' + encryptedMessageWithX25519.message + '"\n');
    console.log('Nodejs X25519 encrypted message salt: "' + encryptedMessageWithX25519.symmetricKeySalt + '"\n');

    const decryptediOSP256Message = await cryptokit.P256.decrypt(
      iOSP256EncryptedMessage,
      P256PrivateKey,
      iOSP256PublicKey,
      iOSP256SymmetricKeySalt
    );
    console.log('Decrypted iOS P256 message = "' + decryptediOSP256Message + '"\n');

    const decryptediOSX25519Message = await cryptokit.X25519.decrypt(
      iOSX25519EncryptedMessage,
      X25519PrivateKey,
      iOSX25519PublicKey,
      iOSX25519SymmetricKeySalt
    );
    console.log('Decrypted iOS X25519 message = "' + decryptediOSX25519Message + '"\n');
  } catch (error) {
    throw error;
  }
}

e2eEncryption();
