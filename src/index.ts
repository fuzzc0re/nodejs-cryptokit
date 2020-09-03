import { randomBytes, createCipheriv, createDecipheriv, sign, verify, KeyObject, diffieHellman } from "crypto";

import { generateP256Keys, loadP256PrivateKey, loadP256PublicKey, convertP256PublicKeyToRaw } from "./utils/P256";
import {
  generateEd25519Keys,
  loadEd25519PrivateKey,
  loadEd25519PublicKey,
  convertEd25519PublicKeyToRaw,
} from "./utils/Ed25519";
import {
  generateX25519Keys,
  loadX25519PrivateKey,
  loadX25519PublicKey,
  convertX25519PublicKeyToRaw,
} from "./utils/X25519";

import { hkdf } from "./utils/funcs/hkdf";

const symmetricKeyHash = "sha512";
const symmetricKeySaltLength = 64;
const symmetricKeyLength = 32;
const ivLength = 12;
const authTagLength = 16;

function signMessage(message: string | Buffer, privateKey: KeyObject): Promise<string> {
  return new Promise((resolve, reject) => {
    try {
      let messageData: Buffer;
      if (typeof message === "string") {
        messageData = Buffer.from(message, "utf8");
      } else {
        messageData = message;
      }

      const messageSignature = sign(null, messageData, privateKey);
      const messageSignatureBase64 = messageSignature.toString("base64");

      resolve(messageSignatureBase64);
    } catch (error) {
      reject(error);
    }
  });
}

function verifySignature(message: string | Buffer, signature: string | Buffer, publicKey: KeyObject): Promise<boolean> {
  return new Promise((resolve, reject) => {
    try {
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

      resolve(verification);
    } catch (error) {
      reject(error);
    }
  });
}

function generateSymmetricKey(
  privateKey: KeyObject,
  publicKey: KeyObject,
  salt?: string | Buffer
): Promise<{ key: Buffer; salt: Buffer }> {
  return new Promise((resolve, reject) => {
    try {
      const sharedSecret = diffieHellman({ privateKey, publicKey });

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
        symmetricKeySalt = randomBytes(symmetricKeySaltLength);
      }

      const symmetricKey = hkdf(sharedSecret, symmetricKeyLength, symmetricKeySalt, "", symmetricKeyHash);

      resolve({ key: symmetricKey, salt: symmetricKeySalt });
    } catch (error) {
      reject(error);
    }
  });
}

function encryptWithSymmetricKey(
  message: string,
  privateKey: KeyObject,
  publicKey: KeyObject
): Promise<{ message: string; symmetricKeySalt: string }> {
  return new Promise(async (resolve, reject) => {
    try {
      const symmetricKey = await generateSymmetricKey(privateKey, publicKey);
      const symmetricKeySaltBase64 = symmetricKey.salt.toString("base64");

      const iv = randomBytes(ivLength);
      const cipher = createCipheriv("chacha20-poly1305", symmetricKey.key, iv, {
        authTagLength,
      });
      const encryptedBuffer = Buffer.concat([cipher.update(message, "utf8"), cipher.final()]);
      const tag = cipher.getAuthTag();
      const encryptedMessage = Buffer.concat([iv, encryptedBuffer, tag]);
      const encryptedMessageBase64 = encryptedMessage.toString("base64");

      resolve({ message: encryptedMessageBase64, symmetricKeySalt: symmetricKeySaltBase64 });
    } catch (error) {
      reject(error);
    }
  });
}

function decryptWithSymmetricKey(
  encryptedMessage: string | Buffer,
  privateKey: KeyObject,
  publicKey: KeyObject,
  symmetricKeySalt: string | Buffer
): Promise<string> {
  return new Promise(async (resolve, reject) => {
    try {
      let encryptedMessageData: Buffer;
      if (typeof encryptedMessage === "string") {
        encryptedMessageData = Buffer.from(encryptedMessage, "base64");
      } else {
        encryptedMessageData = encryptedMessage;
      }

      const symmetricKey = await generateSymmetricKey(privateKey, publicKey, symmetricKeySalt);

      const encryptedMessageDataLength = encryptedMessageData.length;
      const iv = encryptedMessageData.slice(0, ivLength);
      const encryptedText = encryptedMessageData.slice(ivLength, encryptedMessageDataLength - authTagLength);
      const tag = encryptedMessageData.slice(encryptedMessageDataLength - authTagLength, encryptedMessageDataLength);
      const decipher = createDecipheriv("chacha20-poly1305", symmetricKey.key, iv, {
        authTagLength,
      });
      decipher.setAuthTag(tag);
      const decrypted = decipher.update(encryptedText, "binary", "utf8") + decipher.final("utf8");

      resolve(decrypted);
    } catch (error) {
      reject(error);
    }
  });
}

export const P256 = {
  generateKeys: generateP256Keys,
  loadPrivateKey: loadP256PrivateKey,
  loadPublicKey: loadP256PublicKey,
  formatPublicKeyToRaw: convertP256PublicKeyToRaw,
  sign: signMessage,
  verify: verifySignature,
  encrypt: encryptWithSymmetricKey,
  decrypt: decryptWithSymmetricKey,
};

export const Ed25519 = {
  generateKeys: generateEd25519Keys,
  loadPrivateKey: loadEd25519PrivateKey,
  loadPublicKey: loadEd25519PublicKey,
  formatPublicKeyToRaw: convertEd25519PublicKeyToRaw,
  sign: signMessage,
  verify: verifySignature,
};

export const X25519 = {
  generateKeys: generateX25519Keys,
  loadPrivateKey: loadX25519PrivateKey,
  loadPublicKey: loadX25519PublicKey,
  formatPublicKeyToRaw: convertX25519PublicKeyToRaw,
  encrypt: encryptWithSymmetricKey,
  decrypt: decryptWithSymmetricKey,
};

const cryptokit = {
  P256,
  Ed25519,
  X25519,
};

export default cryptokit;
