import { generateKeyPair, createPublicKey, createPrivateKey, KeyObject } from "crypto";

import { convertToPEM } from "./funcs/convertToPEM";

const algorithm = "aes-256-ctr";

const P256OIDHeaderLength = 26;
const P256OIDHeader = new Uint8Array([
  0x30,
  0x59,
  0x30,
  0x13,
  0x06,
  0x07,
  0x2a,
  0x86,
  0x48,
  0xce,
  0x3d,
  0x02,
  0x01,
  0x06,
  0x08,
  0x2a,
  0x86,
  0x48,
  0xce,
  0x3d,
  0x03,
  0x01,
  0x07,
  0x03,
  0x42,
  0x00,
]);
const P256ASNBuffer = Buffer.from(P256OIDHeader, P256OIDHeaderLength);

export async function generateP256Keys(password?: string): Promise<{ publicKey: string; privateKey: string }> {
  return new Promise((resolve, reject) => {
    try {
      generateKeyPair(
        "ec",
        {
          namedCurve: "prime256v1",
          publicKeyEncoding: {
            type: "spki",
            format: "pem",
          },
          privateKeyEncoding: {
            type: "sec1",
            format: "pem",
            cipher: algorithm,
            passphrase: password ? password : process.env.P256_PASS,
          },
        },
        (err, publicKey, privateKey) => {
          if (err) reject(err);

          resolve({ publicKey, privateKey });
        }
      );
    } catch (error) {
      reject(error);
    }
  });
}

export function loadP256PrivateKey(content: string, password?: string): Promise<KeyObject> {
  return new Promise((resolve, reject) => {
    try {
      const privateKeyObject = createPrivateKey({
        key: content,
        type: "sec1",
        format: "pem",
        passphrase: password ? password : process.env.P256_PASS,
      });

      resolve(privateKeyObject);
    } catch (error) {
      reject(error);
    }
  });
}

export function loadP256PublicKey(content: string): Promise<KeyObject> {
  return new Promise((resolve, reject) => {
    try {
      const isPEM = content.includes("-----BEGIN PUBLIC KEY-----") && content.includes("-----END PUBLIC KEY-----");
      let publicKey = content;
      if (!isPEM) {
        const publicKeyBuffer = Buffer.from(content, "base64");
        if (publicKeyBuffer.length === 91) {
          publicKey = convertToPEM(content);
        } else if (publicKeyBuffer.length === 65) {
          const publicKeyWithHeader = Buffer.concat([P256ASNBuffer, publicKeyBuffer]);
          const publicKeyWithHeaderBase64 = publicKeyWithHeader.toString("base64");
          publicKey = convertToPEM(publicKeyWithHeaderBase64);
        } else if (publicKeyBuffer.length === 64) {
          const publicKeyWithHeader = Buffer.concat([P256ASNBuffer, new Uint8Array([0x04]), publicKeyBuffer]);
          const publicKeyWithHeaderBase64 = publicKeyWithHeader.toString("base64");
          publicKey = convertToPEM(publicKeyWithHeaderBase64);
        } else {
          reject(new Error("Invalid P256 public key length"));
        }
      }

      const publicKeyObject = createPublicKey({ key: publicKey });

      resolve(publicKeyObject);
    } catch (error) {
      reject(error);
    }
  });
}

export function convertP256PublicKeyToRaw(publicKey: KeyObject): Promise<string> {
  return new Promise((resolve, reject) => {
    try {
      const rawWithHeader = publicKey.export({ type: "spki", format: "der" });
      const rawWithoutHeader = rawWithHeader.slice(P256OIDHeaderLength + 1);
      const rawPublicKey = rawWithoutHeader.toString("base64");

      resolve(rawPublicKey);
    } catch (error) {
      reject(error);
    }
  });
}
