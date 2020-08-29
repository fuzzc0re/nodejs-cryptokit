import { randomBytes, createCipheriv, createDecipheriv, sign, verify, createPublicKey, KeyObject } from "crypto";

import { generateP256Keys, loadP256PrivateKeyObject, loadP256PublicKey, P256ASNBuffer } from "./utils/P256";
import {
  generateEd25519Keys,
  loadEd25519PrivateKeyObject,
  loadEd25519PublicKey,
  Ed25519ASNBuffer,
} from "./utils/Ed25519";
import { generateX25519Keys, loadX25519PrivateKeyObject, loadX25519PublicKey, X25519ASNBuffer } from "./utils/X25519";

import { hkdf } from "./utils/funcs/hkdf";
import { dh } from "./utils/funcs/diffieHellman";

// if (!process.env.P256_PASS && !process.env.ED25519_PASS && !process.env.X25519_PASS) {
//   throw new Error("No passwords provided in .env file");
// }

function signMessage(message: string | Buffer, privateKey: KeyObject) {
  let messageData: Buffer;
  if (typeof message === "string") {
    messageData = Buffer.from(message, "utf8");
  } else {
    messageData = message;
  }

  try {
    const messageSignature = sign(null, messageData, privateKey);

    return messageSignature.toString("base64");
  } catch (error) {
    throw error;
  }
}

function verifySignature(message: string | Buffer, signature: string | Buffer, publicKey: KeyObject) {
  let messageData: Buffer;
  if (typeof message === "string") {
    messageData = Buffer.from(message, "utf8");
  } else {
    messageData = message;
  }

  let signatureData: Buffer;
  if (typeof signature === "string") {
    signatureData = Buffer.from(signature, "base64");
  } else {
    signatureData = signature;
  }

  const verification = verify(null, messageData, publicKey, signatureData);

  return verification;
}

function formatiOSPublicKey(publicKey: string | Buffer, publicKeyType: "P256" | "Ed25519" | "X25519") {
  let publicKeyBuffer: Buffer;
  if (typeof publicKey === "string") {
    publicKeyBuffer = Buffer.from(publicKey, "base64");
  } else {
    publicKeyBuffer = publicKey;
  }

  let publicKeyData: Buffer;
  if (publicKeyType === "P256") {
    publicKeyData = Buffer.concat([P256ASNBuffer, publicKeyBuffer]);
  } else if (publicKeyType === "Ed25519") {
    publicKeyData = Buffer.concat([Ed25519ASNBuffer, publicKeyBuffer]);
  } else {
    publicKeyData = Buffer.concat([X25519ASNBuffer, publicKeyBuffer]);
  }

  const publicKeyWithASN = publicKeyData.toString("base64");

  let resultString = "-----BEGIN PUBLIC KEY-----\n";
  let charCount = 0;
  let currentLine = "";
  for (const i of publicKeyWithASN) {
    charCount += 1;
    currentLine += i;
    if (charCount === 64) {
      resultString += currentLine + "\n";
      charCount = 0;
      currentLine = "";
    }
  }
  if (currentLine.length > 0) {
    resultString += currentLine + "\n";
  }
  resultString += "-----END PUBLIC KEY-----";

  try {
    const keyObject = createPublicKey({ key: resultString });

    return keyObject;
  } catch (error) {
    throw error;
  }
}

function generateSymmetricKey(
  privateKey: KeyObject,
  publicKey: KeyObject,
  salt?: string | Buffer
): { key: Buffer; salt: Buffer } {
  const sharedSecret = dh(publicKey, privateKey);

  let symmetricKeySalt: Buffer;
  if (salt) {
    if (Buffer.isBuffer(salt)) {
      symmetricKeySalt = salt;
    } else if (typeof salt === "string") {
      symmetricKeySalt = Buffer.from(salt, "base64");
    } else {
      throw new Error("Invalid symmetric key salt");
    }
  } else {
    symmetricKeySalt = randomBytes(16);
  }

  const symmetricKey = hkdf(sharedSecret, sharedSecret.length, {
    salt: symmetricKeySalt,
    info: "",
    hash: "sha256",
  });

  return { key: symmetricKey, salt: symmetricKeySalt };
}

const ivLength = 12;
const authTagLength = 16;

function encryptWithSymmetricKey(
  message: string,
  privateKey: KeyObject,
  publicKey: KeyObject
): { message: string; symmetricKeySalt: string } {
  const symmetricKey = generateSymmetricKey(privateKey, publicKey);

  const iv = randomBytes(ivLength);
  const cipher = createCipheriv("chacha20-poly1305", symmetricKey.key, iv, {
    authTagLength,
  });
  const encryptedBuffer = Buffer.concat([cipher.update(message, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  const encryptedMessage = Buffer.concat([iv, encryptedBuffer, tag]);

  return { message: encryptedMessage.toString("base64"), symmetricKeySalt: symmetricKey.salt.toString("base64") };
}

function decryptWithSymmetricKey(
  encryptedMessage: string | Buffer,
  privateKey: KeyObject,
  publicKey: KeyObject,
  symmetricKeySalt: string | Buffer
) {
  let encryptedMessageData: Buffer;
  if (typeof encryptedMessage === "string") {
    encryptedMessageData = Buffer.from(encryptedMessage, "base64");
  } else {
    encryptedMessageData = encryptedMessage;
  }

  const symmetricKey = generateSymmetricKey(privateKey, publicKey, symmetricKeySalt);

  const encryptedMessageDataLength = encryptedMessageData.length;
  const iv = encryptedMessageData.slice(0, ivLength);
  const encryptedText = encryptedMessageData.slice(ivLength, encryptedMessageDataLength - authTagLength);
  const tag = encryptedMessageData.slice(encryptedMessageDataLength - authTagLength, encryptedMessageDataLength);
  const decipher = createDecipheriv("chacha20-poly1305", symmetricKey.key, iv, {
    authTagLength,
  });
  decipher.setAuthTag(tag);
  const decrypted = decipher.update(encryptedText, "binary", "utf8") + decipher.final("utf8");

  return decrypted;
}

export const P256 = {
  generateKeys: generateP256Keys,
  loadPrivateKey: loadP256PrivateKeyObject,
  loadPublicKey: loadP256PublicKey,
  formatiOSPublicKey: (publicKey: string | Buffer) => formatiOSPublicKey(publicKey, "P256"),
  sign: signMessage,
  verify: verifySignature,
  encrypt: encryptWithSymmetricKey,
  decrypt: decryptWithSymmetricKey,
};

export const Ed25519 = {
  generateKeys: generateEd25519Keys,
  loadPrivateKey: loadEd25519PrivateKeyObject,
  loadPublicKey: loadEd25519PublicKey,
  formatiOSPublicKey: (publicKey: string | Buffer) => formatiOSPublicKey(publicKey, "Ed25519"),
  sign: signMessage,
  verify: verifySignature,
};

export const X25519 = {
  generateKeys: generateX25519Keys,
  loadPrivateKey: loadX25519PrivateKeyObject,
  loadPublicKey: loadX25519PublicKey,
  formatiOSPublicKey: (publicKey: string | Buffer) => formatiOSPublicKey(publicKey, "X25519"),
  encrypt: encryptWithSymmetricKey,
  decrypt: decryptWithSymmetricKey,
};

const cryptokit = {
  P256,
  Ed25519,
  X25519,
};

export default cryptokit;
