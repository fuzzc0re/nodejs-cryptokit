import {
  generateKeyPair,
  randomBytes,
  createCipheriv,
  createDecipheriv,
  createPublicKey,
  createPrivateKey,
  KeyObject,
} from "crypto";

import { hkdf } from "./funcs/hkdf";
import { convertToPEM } from "./funcs/convertToPEM";

const algorithm = "aes-256-gcm";
const hash = "sha512";
const saltLength = 64;
const symmetricKeyLength = 32;
const ivLength = 16;
const authTagLength = 16;

const Ed25519OIDHeaderLength = 12;
const Ed25519OIDHeader = new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
const Ed25519ASNBuffer = Buffer.from(Ed25519OIDHeader, Ed25519OIDHeaderLength);

export function generateEd25519Keys(password?: string): Promise<{ publicKey: string; privateKey: string }> {
  return new Promise((resolve, reject) => {
    try {
      generateKeyPair(
        "ed25519",
        {
          publicKeyEncoding: {
            type: "spki",
            format: "pem",
          },
          privateKeyEncoding: {
            type: "pkcs8",
            format: "pem",
          },
        },
        (err, publicKey, privateKey) => {
          if (err) reject(err);

          const salt = randomBytes(saltLength);
          const keyBuffer = Buffer.from(password ? password : (process.env.ED25519_PASS as string), "utf8");
          const key = hkdf(keyBuffer, symmetricKeyLength, salt, "", hash);

          const iv = randomBytes(ivLength);
          const cipher = createCipheriv(algorithm, key, iv);
          const privateKeyCipherBuffer = cipher.update(privateKey);
          const privateKeyBufferFinal = Buffer.concat([privateKeyCipherBuffer, cipher.final()]);
          const authTag = cipher.getAuthTag();
          const privateKeyEncrypted = Buffer.concat([salt, iv, privateKeyBufferFinal, authTag]);
          const privateKeyEncryptedBase64 = privateKeyEncrypted.toString("base64");

          resolve({ publicKey, privateKey: privateKeyEncryptedBase64 });
        }
      );
    } catch (error) {
      reject(error);
    }
  });
}

export function loadEd25519PrivateKey(content: string | Buffer, password?: string): Promise<KeyObject> {
  return new Promise((resolve, reject) => {
    try {
      let contentBuffer: Buffer;
      if (Buffer.isBuffer(content)) {
        contentBuffer = content;
      } else {
        contentBuffer = Buffer.from(content, "base64");
      }
      const contentBufferLength = contentBuffer.length;
      const salt = contentBuffer.slice(0, saltLength);
      const iv = contentBuffer.slice(saltLength, saltLength + ivLength);
      const encryptedContent = contentBuffer.slice(saltLength + ivLength, contentBufferLength - authTagLength);
      const authTag = contentBuffer.slice(contentBufferLength - authTagLength, contentBufferLength);

      const keyBuffer = Buffer.from(password ? password : (process.env.ED25519_PASS as string), "utf8");
      const key = hkdf(keyBuffer, symmetricKeyLength, salt, "", hash);

      const decipher = createDecipheriv(algorithm, key, iv);
      decipher.setAuthTag(authTag);
      const decrypted = decipher.update(encryptedContent);
      const privateKey = Buffer.concat([decrypted, decipher.final()]);
      const privateKeyObject = createPrivateKey({ key: privateKey });

      resolve(privateKeyObject);
    } catch (error) {
      reject(error);
    }
  });
}

export function loadEd25519PublicKey(content: string): Promise<KeyObject> {
  return new Promise((resolve, reject) => {
    try {
      const isPEM = content.includes("-----BEGIN PUBLIC KEY-----") && content.includes("-----END PUBLIC KEY-----");
      let publicKey = content;
      if (!isPEM) {
        const publicKeyBuffer = Buffer.from(content, "base64");
        if (publicKeyBuffer.length === 44) {
          publicKey = convertToPEM(content);
        } else if (publicKeyBuffer.length === 32) {
          const publicKeyWithHeader = Buffer.concat([Ed25519ASNBuffer, publicKeyBuffer]);
          const publicKeyWithHeaderBase64 = publicKeyWithHeader.toString("base64");
          publicKey = convertToPEM(publicKeyWithHeaderBase64);
        } else {
          reject(new Error("Invalid Ed25519 public key length"));
        }
      }

      const publicKeyObject = createPublicKey({ key: publicKey });

      resolve(publicKeyObject);
    } catch (error) {
      reject(error);
    }
  });
}

export function convertEd25519PublicKeyToRaw(publicKey: KeyObject): Promise<string> {
  return new Promise((resolve, reject) => {
    try {
      const rawWithHeader = publicKey.export({ type: "spki", format: "der" });
      const rawWithoutHeader = rawWithHeader.slice(Ed25519OIDHeaderLength);
      const rawPublicKey = rawWithoutHeader.toString("base64");

      resolve(rawPublicKey);
    } catch (error) {
      reject(error);
    }
  });
}
