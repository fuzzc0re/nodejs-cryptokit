const { join } = require("path");
const { readFileSync } = require("fs");
const { config } = require("dotenv");

config({ path: join(__dirname, ".env") });

const cryptokit = require("../lib/index");

const { iOSP256PublicKeyRaw, iOSX25519PublicKeyRaw } = require("./keys/iOS");

const P256FolderPath = join(__dirname, "keys", "P256");
const P256Filepaths = {
  privateKeyPath: join(P256FolderPath, "private.key"),
  publicKeyPath: join(P256FolderPath, "public.key"),
};
const P256PrivateKeyContent = readFileSync(P256Filepaths.privateKeyPath, "utf8");

const X25519FolderPath = join(__dirname, "keys", "X25519");
const X25519Filepaths = {
  privateKeyPath: join(X25519FolderPath, "private.key"),
  publicKeyPath: join(X25519FolderPath, "public.key"),
};
const X25519PrivateKeyContent = readFileSync(X25519Filepaths.privateKeyPath, "utf8");
const X25519PublicKeyContent = readFileSync(X25519Filepaths.publicKeyPath, "utf8");

const messageToEncryptWithP256 = "Hi! I am an end-to-end encrypted example message from nodejs with symmetric P256 key";

const messageToEncryptWithX25519 =
  "Hi! I am an end-to-end encrypted example message from nodejs with symmetric P256 key";

const iOSP256EncryptedMessage =
  "jEn5nutFeXcFyNf522GAqYY52ueRRe2jdjQKK21AizC8gH1gYbdwD2R1+q3F4JfdcPohehStuGfj16zaIHna3lIgPAhsAkvQ34rqnuSe4xWaDcHCbWTC2jyEUQ==";
const iOSP256SymmetricKeySalt =
  "VEC0tdnHcOSiPr6ebmYCX6w7m8SmLhqa25+PntP86eHLD1rlBqS97aHI5EjDKGwn6Uq6wyQIn5CZxM/j9wmD3g==";

const iOSX25519EncryptedMessage =
  "58G4eZwNAOKJTikTuadmSSKsE0RrhGIsRMMfALo4ZhqzA4UOfy/Xs+V3R/mwU6ruXkfkOWS1fnt1pAkL9x2ZAPgmGJ3DcgGb7wwFK6T0kNyfKK4JXFt0eVVCa3MQ";
const iOSX25519SymmetricKeySalt =
  "qq1LDIfBOEAJk50/tRaE+3UIsaBwO2AYD+ADGUBVnO3vQOATmlp5uzvg6TUN4Kw0HCEO10EPbf34iLVIgTzItw==";

async function e2eEncryption() {
  try {
    const P256PrivateKey = await cryptokit.P256.loadPrivateKey(P256PrivateKeyContent);
    const iOSP256PublicKey = await cryptokit.P256.loadPublicKey(iOSP256PublicKeyRaw);
    const encryptedMessageWithP256 = await cryptokit.P256.encrypt(
      messageToEncryptWithP256,
      P256PrivateKey,
      iOSP256PublicKey
    );
    console.log('Nodejs encrypted message with P256 = "' + encryptedMessageWithP256.message + '"\n');
    console.log('Nodejs P256 Encrypted message salt = "' + encryptedMessageWithP256.symmetricKeySalt + '"\n');

    const X25519PublicKey = await cryptokit.X25519.loadPublicKey(X25519PublicKeyContent);
    const iOSCompatibleX25519PublicKey = await cryptokit.X25519.formatPublicKeyToRaw(X25519PublicKey);
    console.log("iOS Compatible X25519 public key = " + iOSCompatibleX25519PublicKey);

    const X25519PrivateKey = await cryptokit.X25519.loadPrivateKey(X25519PrivateKeyContent);
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
